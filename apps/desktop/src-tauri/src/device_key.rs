//! The device secret mixed into the vault key. It lives in the OS keyring
//! (Windows Credential Manager, macOS Keychain, Secret Service on Linux) so the
//! vault file alone is useless. If no keyring is available we fall back to a
//! file next to the vault, which still requires the PIN but loses that protection.

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
                if let Some(dir) = self.fallback.parent() {
                    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
                }
                std::fs::write(&self.fallback, secret.as_ref()).map_err(|e| e.to_string())?;
            }
        }
        Ok(Zeroizing::new(secret.to_vec()))
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
