//! PIN attempt throttling. After `FREE_ATTEMPTS` failures every further failure
//! locks unlocking for an exponentially growing delay (30s, 60s, 120s ... max 1h).
//!
//! This guards the UI against someone guessing at an unattended machine. It is
//! not what protects the file offline; the Argon2id + device secret key does that.

use std::path::Path;

use serde::{Deserialize, Serialize};

const FREE_ATTEMPTS: u32 = 5;
const BASE_DELAY_SECS: u64 = 30;
const MAX_DELAY_SECS: u64 = 3600;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Throttle {
    failures: u32,
    locked_until: Option<u64>,
}

impl Throttle {
    /// Loads persisted state. A missing file is a clean slate. A file that exists but
    /// can't be read or parsed is treated as a used-up allowance, so damaging it
    /// doesn't hand out free guesses: the next wrong PIN locks out.
    pub fn load(path: &Path) -> Self {
        match std::fs::read(path) {
            Ok(raw) => serde_json::from_slice(&raw).unwrap_or_else(|_| Self::exhausted()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(_) => Self::exhausted(),
        }
    }

    fn exhausted() -> Self {
        Self {
            failures: FREE_ATTEMPTS - 1,
            locked_until: None,
        }
    }

    /// Writes beside the file and renames, so a crash never leaves a torn file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let mut tmp = path.to_path_buf().into_os_string();
        tmp.push(".tmp");
        let tmp = std::path::PathBuf::from(tmp);
        std::fs::write(&tmp, serde_json::to_vec(self).expect("serializes"))?;
        std::fs::rename(&tmp, path)
    }

    /// Seconds until another attempt is allowed, if currently locked out.
    pub fn retry_after(&self, now: u64) -> Option<u64> {
        self.locked_until
            .filter(|&until| until > now)
            .map(|until| until - now)
    }

    /// Wrong PINs left before the next lockout kicks in.
    pub fn attempts_left(&self) -> u32 {
        FREE_ATTEMPTS.saturating_sub(self.failures)
    }

    pub fn record_failure(&mut self, now: u64) {
        self.failures += 1;
        if self.failures >= FREE_ATTEMPTS {
            let doublings = (self.failures - FREE_ATTEMPTS).min(16);
            let delay = (BASE_DELAY_SECS << doublings).min(MAX_DELAY_SECS);
            self.locked_until = Some(now + delay);
        }
    }

    pub fn record_success(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_out_with_backoff() {
        let mut t = Throttle::default();
        for _ in 0..4 {
            t.record_failure(100);
            assert_eq!(t.retry_after(100), None);
        }
        assert_eq!(t.attempts_left(), 1);

        t.record_failure(100);
        assert_eq!(t.retry_after(100), Some(30));
        assert_eq!(t.retry_after(130), None);

        t.record_failure(130);
        assert_eq!(t.retry_after(130), Some(60));

        for _ in 0..20 {
            t.record_failure(1000);
        }
        assert_eq!(t.retry_after(1000), Some(MAX_DELAY_SECS));

        t.record_success();
        assert_eq!(t.retry_after(1000), None);
        assert_eq!(t.attempts_left(), FREE_ATTEMPTS);
    }

    #[test]
    fn corrupt_file_is_not_a_clean_slate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("attempts.json");
        assert_eq!(Throttle::load(&path).attempts_left(), FREE_ATTEMPTS);

        std::fs::write(&path, b"not json").unwrap();
        let mut t = Throttle::load(&path);
        assert_eq!(t.attempts_left(), 1);
        t.record_failure(100);
        assert_eq!(t.retry_after(100), Some(BASE_DELAY_SECS));
    }
}
