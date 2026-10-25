//! Encrypted local store for saved hosts and their credentials.
//!
//! The whole vault (host list included) is one XChaCha20-Poly1305 encrypted file.
//! Its key is derived with Argon2id from the user's PIN *and* a device secret
//! (kept in the OS keyring by the app), so a copied vault file can't be
//! brute-forced offline without also stealing the keyring secret.

mod file;
mod throttle;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub use file::KdfParams;
pub use throttle::Throttle;

/// A fresh random device secret, for the app to keep in the OS keyring.
pub fn new_device_secret() -> Zeroizing<[u8; 32]> {
    let mut secret = Zeroizing::new([0u8; 32]);
    getrandom::fill(secret.as_mut()).expect("OS random number generator");
    secret
}

/// Shortest accepted PIN. Digits only is fine; the device secret carries the entropy.
pub const MIN_PIN_LEN: usize = 6;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wrong PIN")]
    WrongPin,
    #[error("PIN must be at least {MIN_PIN_LEN} characters")]
    PinTooShort,
    #[error("a vault already exists")]
    AlreadyExists,
    #[error("vault file is corrupt or from an unsupported version")]
    Corrupt,
    #[error("unknown host id")]
    UnknownHost,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Default, Serialize, Deserialize)]
struct VaultData {
    hosts: Vec<SavedHost>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedHost {
    pub id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<Zeroizing<String>>,
}

/// What the UI is allowed to see: everything except the secret itself.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSummary {
    pub id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub has_password: bool,
}

impl From<&SavedHost> for HostSummary {
    fn from(h: &SavedHost) -> Self {
        Self {
            id: h.id.clone(),
            label: h.label.clone(),
            host: h.host.clone(),
            port: h.port,
            username: h.username.clone(),
            has_password: h.password.is_some(),
        }
    }
}

/// Create or update request from the UI. `id: None` creates a new host.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInput {
    pub id: Option<String>,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: PasswordChange,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum PasswordChange {
    Keep,
    Set { value: Zeroizing<String> },
    Clear,
}

/// An unlocked vault. Dropping it wipes the key and secrets from memory.
pub struct Vault {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    kdf: KdfParams,
    data: VaultData,
}

impl Vault {
    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    pub fn create(
        path: impl Into<PathBuf>,
        pin: &str,
        device_secret: &[u8],
        params: KdfParams,
    ) -> Result<Self> {
        let path = path.into();
        if path.exists() {
            return Err(Error::AlreadyExists);
        }
        if pin.chars().count() < MIN_PIN_LEN {
            return Err(Error::PinTooShort);
        }
        let kdf = params.with_fresh_salt();
        let vault = Self {
            key: file::derive_key(pin, device_secret, &kdf),
            path,
            kdf,
            data: VaultData::default(),
        };
        vault.save()?;
        Ok(vault)
    }

    pub fn unlock(path: impl Into<PathBuf>, pin: &str, device_secret: &[u8]) -> Result<Self> {
        let path = path.into();
        let opened = file::read(&path, pin, device_secret)?;
        let data = serde_json::from_slice(&opened.plaintext).map_err(|_| Error::Corrupt)?;
        Ok(Self {
            path,
            key: opened.key,
            kdf: opened.kdf,
            data,
        })
    }

    pub fn change_pin(&mut self, new_pin: &str, device_secret: &[u8]) -> Result<()> {
        if new_pin.chars().count() < MIN_PIN_LEN {
            return Err(Error::PinTooShort);
        }
        self.kdf = self.kdf.with_fresh_salt();
        self.key = file::derive_key(new_pin, device_secret, &self.kdf);
        self.save()
    }

    pub fn hosts(&self) -> Vec<HostSummary> {
        self.data.hosts.iter().map(HostSummary::from).collect()
    }

    pub fn host(&self, id: &str) -> Option<&SavedHost> {
        self.data.hosts.iter().find(|h| h.id == id)
    }

    pub fn upsert_host(&mut self, input: HostInput) -> Result<HostSummary> {
        let existing = match &input.id {
            Some(id) => Some(
                self.data
                    .hosts
                    .iter()
                    .position(|h| &h.id == id)
                    .ok_or(Error::UnknownHost)?,
            ),
            None => None,
        };
        let old_password = existing.and_then(|i| self.data.hosts[i].password.clone());
        let host = SavedHost {
            id: input.id.unwrap_or_else(file::random_id),
            label: input.label,
            host: input.host,
            port: input.port,
            username: input.username,
            password: match input.password {
                PasswordChange::Keep => old_password,
                PasswordChange::Set { value } => Some(value),
                PasswordChange::Clear => None,
            },
        };
        let summary = HostSummary::from(&host);
        match existing {
            Some(i) => self.data.hosts[i] = host,
            None => self.data.hosts.push(host),
        }
        self.save()?;
        Ok(summary)
    }

    pub fn delete_host(&mut self, id: &str) -> Result<()> {
        let before = self.data.hosts.len();
        self.data.hosts.retain(|h| h.id != id);
        if self.data.hosts.len() == before {
            return Err(Error::UnknownHost);
        }
        self.save()
    }

    fn save(&self) -> Result<()> {
        let plaintext = Zeroizing::new(serde_json::to_vec(&self.data).map_err(|_| Error::Corrupt)?);
        file::write(&self.path, &self.key, &self.kdf, &plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"device-secret-for-tests-32-bytes";

    fn input(password: PasswordChange) -> HostInput {
        HostInput {
            id: None,
            label: "box".into(),
            host: "10.0.0.1".into(),
            port: 22,
            username: "root".into(),
            password,
        }
    }

    fn set(p: &str) -> PasswordChange {
        PasswordChange::Set {
            value: Zeroizing::new(p.into()),
        }
    }

    #[test]
    fn round_trip_and_wrong_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        let mut v =
            Vault::create(&path, "123456", SECRET, KdfParams::insecure_for_tests()).unwrap();
        let saved = v.upsert_host(input(set("hunter2"))).unwrap();
        assert!(saved.has_password);
        drop(v);

        let v = Vault::unlock(&path, "123456", SECRET).unwrap();
        let host = v.host(&saved.id).unwrap();
        assert_eq!(
            host.password.as_deref().map(String::as_str),
            Some("hunter2")
        );

        assert!(matches!(
            Vault::unlock(&path, "654321", SECRET),
            Err(Error::WrongPin)
        ));
        assert!(matches!(
            Vault::unlock(&path, "123456", b"some-other-device-secret-32-byte"),
            Err(Error::WrongPin)
        ));
    }

    #[test]
    fn file_contains_no_plaintext() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut v =
            Vault::create(&path, "123456", SECRET, KdfParams::insecure_for_tests()).unwrap();
        v.upsert_host(input(set("hunter2"))).unwrap();

        let raw = std::fs::read_to_string(&path).unwrap();
        assert!(!raw.contains("hunter2"));
        assert!(!raw.contains("10.0.0.1"));
    }

    #[test]
    fn password_keep_set_clear() {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::create(
            dir.path().join("v.json"),
            "123456",
            SECRET,
            KdfParams::insecure_for_tests(),
        )
        .unwrap();
        let id = v.upsert_host(input(set("a"))).unwrap().id;

        let mut edit = input(PasswordChange::Keep);
        edit.id = Some(id.clone());
        edit.label = "renamed".into();
        assert!(v.upsert_host(edit).unwrap().has_password);

        let mut edit = input(PasswordChange::Clear);
        edit.id = Some(id.clone());
        assert!(!v.upsert_host(edit).unwrap().has_password);

        v.delete_host(&id).unwrap();
        assert!(v.hosts().is_empty());
    }

    #[test]
    fn change_pin() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v.json");
        let mut v =
            Vault::create(&path, "123456", SECRET, KdfParams::insecure_for_tests()).unwrap();
        v.change_pin("abcdef", SECRET).unwrap();
        assert!(Vault::unlock(&path, "abcdef", SECRET).is_ok());
        assert!(matches!(
            Vault::unlock(&path, "123456", SECRET),
            Err(Error::WrongPin)
        ));
    }

    #[test]
    fn short_pin_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let r = Vault::create(
            dir.path().join("v.json"),
            "123",
            SECRET,
            KdfParams::insecure_for_tests(),
        );
        assert!(matches!(r, Err(Error::PinTooShort)));
    }
}
