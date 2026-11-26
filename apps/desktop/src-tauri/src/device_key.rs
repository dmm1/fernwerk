//! The device secret mixed into the vault key. It lives in the OS keyring
//! (Windows Credential Manager, macOS Keychain, Secret Service on Linux) so the
//! vault file alone is useless. If no keyring is available we fall back to an
//! owner-only file next to the vault, which still requires the PIN but loses that
//! protection; the UI warns about it, and the secret moves into the keyring at the
//! next unlock once one is available.

use std::path::{Path, PathBuf};

use keyring::{Entry, Error as KeyringError};
use zeroize::Zeroizing;

const SERVICE: &str = "app.fernwerk.desktop";
const ACCOUNT: &str = "vault-device-secret";
const FALLBACK_FILE: &str = "device.key";

pub struct DeviceKey {
    service: &'static str,
    fallback: PathBuf,
}

impl DeviceKey {
    pub fn new(data_dir: &Path) -> Self {
        Self::with_service(SERVICE, data_dir)
    }

    fn with_service(service: &'static str, data_dir: &Path) -> Self {
        Self {
            service,
            fallback: data_dir.join(FALLBACK_FILE),
        }
    }

    /// Loads the existing secret. Never creates one: a missing secret for an
    /// existing vault must surface as an error, not as a "wrong PIN".
    pub fn load(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        match self.entry().and_then(|e| e.get_secret()) {
            Ok(secret) => Ok(Zeroizing::new(secret)),
            Err(e) => match std::fs::read(&self.fallback) {
                Ok(secret) => Ok(Zeroizing::new(secret)),
                Err(_) if matches!(e, KeyringError::NoEntry) => Err(
                    "the device key for this vault is missing from the OS keyring; \
                     the vault can't be opened on this device and must be reset"
                        .into(),
                ),
                Err(_) => Err(format!("OS keyring unavailable: {e}")),
            },
        }
    }

    /// Generates and stores a new secret, replacing any previous one.
    pub fn create(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let secret = vault::new_device_secret();
        match self.entry().and_then(|e| e.set_secret(secret.as_ref())) {
            Ok(()) => {
                let _ = std::fs::remove_file(&self.fallback);
            }
            Err(e) => {
                tracing::warn!(error = %e, "OS keyring unavailable, storing device key in a file");
                vault::write_private_file(&self.fallback, secret.as_ref())
                    .map_err(|e| e.to_string())?;
            }
        }
        Ok(Zeroizing::new(secret.to_vec()))
    }

    /// True when the secret is kept in the fallback file instead of the OS keyring.
    pub fn in_file(&self) -> bool {
        self.fallback.exists()
    }

    /// Moves a secret kept in the fallback file into the OS keyring, if one has become
    /// available. The file is deleted only after the keyring copy reads back intact.
    pub fn move_to_keyring(&self, secret: &[u8]) {
        if !self.in_file() {
            return;
        }
        let stored = self.entry().and_then(|e| {
            e.set_secret(secret)?;
            e.get_secret()
        });
        match stored {
            Ok(read_back) if read_back == secret => {
                if let Err(e) = std::fs::remove_file(&self.fallback) {
                    tracing::warn!(error = %e, "device key moved to the OS keyring, but its file remains");
                }
            }
            Ok(_) => tracing::warn!("OS keyring returned a different device key; keeping the file"),
            Err(e) => tracing::debug!(error = %e, "OS keyring still unavailable"),
        }
    }

    pub fn delete(&self) {
        if let Ok(e) = self.entry() {
            let _ = e.delete_credential();
        }
        let _ = std::fs::remove_file(&self.fallback);
    }

    fn entry(&self) -> keyring::Result<Entry> {
        Entry::new(self.service, ACCOUNT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touches the real OS keyring, so it only runs on request:
    /// `cargo test -p fernwerk-desktop -- --ignored`
    #[test]
    #[ignore]
    fn os_keyring_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        // Separate service name so this never touches a real vault's key.
        let key = DeviceKey::with_service("app.fernwerk.desktop.test", dir.path());
        let created = key.create().unwrap();
        assert_eq!(created.len(), 32);
        assert!(
            !dir.path().join(FALLBACK_FILE).exists(),
            "fell back to file"
        );
        assert_eq!(*key.load().unwrap(), *created);
        key.delete();
        assert!(key.load().is_err());
    }
}
