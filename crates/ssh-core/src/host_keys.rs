use std::future::Future;
use std::path::PathBuf;

use russh::keys::{self, HashAlg, PublicKey};

/// A server host key presented during the handshake.
#[derive(Debug, Clone)]
pub struct HostKey {
    pub host: String,
    pub port: u16,
    pub algorithm: String,
    /// OpenSSH-style `SHA256:...` fingerprint.
    pub fingerprint: String,
    pub key: PublicKey,
}

impl HostKey {
    pub(crate) fn new(host: &str, port: u16, key: &PublicKey) -> Self {
        Self {
            host: host.to_owned(),
            port,
            algorithm: key.algorithm().to_string(),
            fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
            key: key.clone(),
        }
    }
}

/// Decides whether to trust a server's host key.
///
/// The long-term plan is an interactive verifier that asks the user on first
/// contact (TOFU) and hard-fails on a changed key.
pub trait HostKeyVerifier: Send + Sync + 'static {
    fn verify(&self, key: &HostKey) -> impl Future<Output = bool> + Send;
}

/// Trust-on-first-use backed by an OpenSSH-format `known_hosts` file owned by
/// this app. Unknown hosts are learned automatically; changed keys are rejected.
pub struct KnownHostsFile {
    path: PathBuf,
}

impl KnownHostsFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl HostKeyVerifier for KnownHostsFile {
    async fn verify(&self, hk: &HostKey) -> bool {
        if self.path.exists() {
            match keys::check_known_hosts_path(&hk.host, hk.port, &hk.key, &self.path) {
                Ok(true) => return true,
                Ok(false) => {}
                Err(keys::Error::KeyChanged { line }) => {
                    tracing::error!(
                        host = %hk.host,
                        fingerprint = %hk.fingerprint,
                        line,
                        "HOST KEY CHANGED: possible man-in-the-middle attack, refusing to connect"
                    );
                    return false;
                }
                Err(e) => {
                    tracing::error!(error = %e, "could not read known_hosts");
                    return false;
                }
            }
        }

        tracing::warn!(
            host = %hk.host,
            algorithm = %hk.algorithm,
            fingerprint = %hk.fingerprint,
            "learning new host key (TOFU)"
        );
        if let Err(e) =
            keys::known_hosts::learn_known_hosts_path(&hk.host, hk.port, &hk.key, &self.path)
        {
            tracing::error!(error = %e, "could not write known_hosts");
        }
        true
    }
}

/// Accepts every host key. Only for tests against throwaway servers.
pub struct AcceptAnyHostKey;

impl HostKeyVerifier for AcceptAnyHostKey {
    async fn verify(&self, hk: &HostKey) -> bool {
        tracing::warn!(host = %hk.host, fingerprint = %hk.fingerprint, "accepting host key without verification");
        true
    }
}
