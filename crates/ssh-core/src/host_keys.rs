use std::collections::HashSet;
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

/// Failure to read or write the `known_hosts` file. The connection is refused.
#[derive(Debug, thiserror::Error)]
pub enum KnownHostsError {
    #[error("could not access known_hosts: {0}")]
    Io(#[from] std::io::Error),
    #[error("could not read known_hosts: {0}")]
    Keys(#[from] keys::Error),
}

/// Decides whether to trust a server's host key.
pub trait HostKeyVerifier: Send + Sync + 'static {
    fn verify(&self, key: &HostKey) -> impl Future<Output = Result<bool, KnownHostsError>> + Send;
}

/// Asks the user whether to trust a host key. `previous` is the fingerprint
/// recorded for this host when its key has changed.
pub trait HostKeyPrompt: Send + Sync + 'static {
    fn confirm(&self, key: &HostKey, previous: Option<&str>) -> impl Future<Output = bool> + Send;
}

/// Where a host key stands relative to the `known_hosts` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trust {
    Known,
    Unknown,
    /// The host is recorded with a different key: possible man-in-the-middle.
    Changed {
        line: usize,
    },
}

/// An OpenSSH-format `known_hosts` file owned by this app.
pub struct KnownHostsFile {
    path: PathBuf,
}

impl KnownHostsFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn lookup(&self, hk: &HostKey) -> Result<Trust, KnownHostsError> {
        // russh treats a file it cannot open as empty, so check readability here.
        match std::fs::read_to_string(&self.path) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Trust::Unknown),
            Err(e) => return Err(e.into()),
        }
        match keys::check_known_hosts_path(&hk.host, hk.port, &hk.key, &self.path) {
            Ok(true) => Ok(Trust::Known),
            Ok(false) => Ok(Trust::Unknown),
            Err(keys::Error::KeyChanged { line }) => Ok(Trust::Changed { line }),
            Err(e) => Err(e.into()),
        }
    }

    pub fn learn(&self, hk: &HostKey) -> Result<(), KnownHostsError> {
        keys::known_hosts::learn_known_hosts_path(&hk.host, hk.port, &hk.key, &self.path)?;
        Ok(())
    }

    /// Fingerprint recorded for `host:port`, if any. Matches hashed (`|1|`) entries too.
    pub fn recorded_fingerprint(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Option<String>, KnownHostsError> {
        let matches = keys::known_hosts::known_host_keys_path(host, port, &self.path)?;
        Ok(matches
            .first()
            .map(|(_, key)| key.fingerprint(HashAlg::Sha256).to_string()))
    }

    /// Deletes the whole file, forgetting every host.
    pub fn clear(&self) -> Result<(), KnownHostsError> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes every entry for `host:port`, hashed or not. Succeeds when there is
    /// nothing to remove.
    pub fn forget(&self, host: &str, port: u16) -> Result<(), KnownHostsError> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        // russh reports 1-based line numbers of the matching entries.
        let stale: HashSet<usize> =
            keys::known_hosts::known_host_keys_path(host, port, &self.path)?
                .into_iter()
                .map(|(line, _)| line)
                .collect();
        if stale.is_empty() {
            return Ok(());
        }
        let kept: String = text
            .split_inclusive('\n')
            .enumerate()
            .filter(|(index, _)| !stale.contains(&(index + 1)))
            .map(|(_, line)| line)
            .collect();
        // Write beside the file and rename, so a failed write leaves the old file intact.
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        std::fs::write(&tmp, kept)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Trust on first use, but only after the user confirms the fingerprint.
/// Known keys pass silently. A changed key needs the user to confirm the
/// replacement, and the old entry is dropped only once they do.
pub struct TrustOnFirstUse<P> {
    known_hosts: KnownHostsFile,
    prompt: P,
}

impl<P: HostKeyPrompt> TrustOnFirstUse<P> {
    pub fn new(known_hosts: KnownHostsFile, prompt: P) -> Self {
        Self {
            known_hosts,
            prompt,
        }
    }

    pub fn prompt(&self) -> &P {
        &self.prompt
    }

    pub fn known_hosts(&self) -> &KnownHostsFile {
        &self.known_hosts
    }
}

impl<P: HostKeyPrompt> HostKeyVerifier for TrustOnFirstUse<P> {
    async fn verify(&self, hk: &HostKey) -> Result<bool, KnownHostsError> {
        match self.known_hosts.lookup(hk)? {
            Trust::Known => Ok(true),
            Trust::Unknown => {
                if !self.prompt.confirm(hk, None).await {
                    tracing::info!(host = %hk.host, "host key rejected by user");
                    return Ok(false);
                }
                self.known_hosts.learn(hk)?;
                Ok(true)
            }
            Trust::Changed { line } => {
                tracing::error!(
                    host = %hk.host,
                    fingerprint = %hk.fingerprint,
                    line,
                    "HOST KEY CHANGED: possible man-in-the-middle attack"
                );
                let previous = self.known_hosts.recorded_fingerprint(&hk.host, hk.port)?;
                if !self.prompt.confirm(hk, previous.as_deref()).await {
                    tracing::info!(host = %hk.host, "changed host key rejected by user");
                    return Ok(false);
                }
                self.known_hosts.forget(&hk.host, hk.port)?;
                self.known_hosts.learn(hk)?;
                Ok(true)
            }
        }
    }
}

/// Accepts every host key. Only for tests against throwaway servers.
pub struct AcceptAnyHostKey;

impl HostKeyVerifier for AcceptAnyHostKey {
    async fn verify(&self, hk: &HostKey) -> Result<bool, KnownHostsError> {
        tracing::warn!(host = %hk.host, fingerprint = %hk.fingerprint, "accepting host key without verification");
        Ok(true)
    }
}
