use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use hmac::{Hmac, KeyInit, Mac};
use russh::keys::{self, HashAlg, PublicKey};
use sha1::Sha1;

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
///
/// Entries are written with hashed host names (like OpenSSH's `HashKnownHosts yes`),
/// so the file doesn't reveal which servers the user connects to, and the file is
/// readable by its owner only.
pub struct KnownHostsFile {
    path: PathBuf,
    /// Serializes read-modify-write updates, so concurrent connects can't drop entries.
    write_lock: Mutex<()>,
}

impl KnownHostsFile {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            write_lock: Mutex::new(()),
        }
    }

    pub fn lookup(&self, hk: &HostKey) -> Result<Trust, KnownHostsError> {
        // russh treats a file it cannot open as empty, so check readability here.
        if self.read()?.is_none() {
            return Ok(Trust::Unknown);
        }
        match keys::check_known_hosts_path(&hk.host, hk.port, &hk.key, &self.path) {
            Ok(true) => Ok(Trust::Known),
            Ok(false) => Ok(Trust::Unknown),
            Err(keys::Error::KeyChanged { line }) => Ok(Trust::Changed { line }),
            Err(e) => Err(e.into()),
        }
    }

    /// Records `hk` under a salted hash of its host name.
    pub fn learn(&self, hk: &HostKey) -> Result<(), KnownHostsError> {
        let key = hk.key.to_openssh().map_err(keys::Error::from)?;
        let _guard = self.lock();
        let mut text = self.read()?.unwrap_or_default();
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&hash_host(&host_pattern(&hk.host, hk.port)));
        text.push(' ');
        text.push_str(&key);
        text.push('\n');
        replace_private(&self.path, text.as_bytes())?;
        Ok(())
    }

    /// Hashes any host names still stored in plain text (from older versions) and
    /// restricts the file to its owner. Meant to run once at startup.
    pub fn harden(&self) -> Result<(), KnownHostsError> {
        let _guard = self.lock();
        let Some(text) = self.read()? else {
            return Ok(());
        };
        let mut out = String::with_capacity(text.len());
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let entry = match line.split_once(' ') {
                Some(parts) if !line.starts_with(['#', '@']) => Some(parts),
                _ => None,
            };
            let Some((hosts, rest)) = entry else {
                out.push_str(line);
                out.push('\n');
                continue;
            };
            // One line per host, so forgetting one host never drops another.
            for host in hosts.split(',').filter(|h| !h.is_empty()) {
                let hashable = !host.starts_with("|1|") && !host.contains(['*', '?', '!']);
                if hashable {
                    out.push_str(&hash_host(host));
                } else {
                    out.push_str(host);
                }
                out.push(' ');
                out.push_str(rest);
                out.push('\n');
            }
        }
        replace_private(&self.path, out.as_bytes())?;
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
        let _guard = self.lock();
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Removes every entry for `host:port`, hashed or not. Succeeds when there is
    /// nothing to remove.
    pub fn forget(&self, host: &str, port: u16) -> Result<(), KnownHostsError> {
        let _guard = self.lock();
        let Some(text) = self.read()? else {
            return Ok(());
        };
        // Matched here rather than by russh's line numbers, which skip comment lines.
        let pattern = host_pattern(host, port);
        let kept: String = text
            .split_inclusive('\n')
            .filter(|line| !line_matches(line.trim_end(), &pattern))
            .collect();
        if kept.len() == text.len() {
            return Ok(());
        }
        replace_private(&self.path, kept.as_bytes())?;
        Ok(())
    }

    /// The file's contents, or `None` if it doesn't exist yet.
    fn read(&self) -> Result<Option<String>, KnownHostsError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => Ok(Some(text)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.write_lock.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// How OpenSSH names a host in `known_hosts`: bare for port 22, `[host]:port` otherwise.
fn host_pattern(host: &str, port: u16) -> String {
    if port == 22 {
        host.to_owned()
    } else {
        format!("[{host}]:{port}")
    }
}

/// `|1|<salt>|<HMAC-SHA1(salt, host)>`, the format of OpenSSH's `HashKnownHosts`.
fn hash_host(pattern: &str) -> String {
    let mut salt = [0u8; 20];
    getrandom::fill(&mut salt).expect("OS random number generator");
    let mut mac = Hmac::<Sha1>::new_from_slice(&salt).expect("HMAC takes any key length");
    mac.update(pattern.as_bytes());
    format!(
        "|1|{}|{}",
        B64.encode(salt),
        B64.encode(mac.finalize().into_bytes())
    )
}

/// True when the host field of a `known_hosts` line names `pattern`, hashed or not.
fn line_matches(line: &str, pattern: &str) -> bool {
    if line.starts_with('#') {
        return false;
    }
    let hosts = line.split(' ').next().unwrap_or_default();
    hosts
        .split(',')
        .any(|entry| match entry.strip_prefix("|1|") {
            Some(hashed) => {
                let mut parts = hashed.split('|');
                let (Some(Ok(salt)), Some(Ok(hash))) = (
                    parts.next().map(|p| B64.decode(p)),
                    parts.next().map(|p| B64.decode(p)),
                ) else {
                    return false;
                };
                Hmac::<Sha1>::new_from_slice(&salt).is_ok_and(|mut mac| {
                    mac.update(pattern.as_bytes());
                    mac.verify_slice(&hash).is_ok()
                })
            }
            None => entry == pattern,
        })
}

/// Atomically replaces `path` with `bytes`, readable by the owner only. Writes beside
/// the file and renames, so a failed write leaves the old file intact.
fn replace_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    // `mode` only applies when the file is created, so fix up a leftover temp file too.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
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
