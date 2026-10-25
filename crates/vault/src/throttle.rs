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
    /// Loads persisted state; a missing or unreadable file counts as a clean slate.
    pub fn load(path: &Path) -> Self {
        std::fs::read(path)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        std::fs::write(path, serde_json::to_vec(self).expect("serializes"))
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
}
