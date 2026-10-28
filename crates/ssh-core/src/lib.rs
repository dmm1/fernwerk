//! SSH engine behind the desktop app's Tauri commands. Callers only see
//! [`Session`]: they push [`Command`]s in and receive [`Event`]s out.

mod host_keys;

use std::sync::Arc;
use std::time::Duration;

use russh::client::{self, Handle};
use russh::keys::PublicKeyOrCertificate;
use russh::{ChannelMsg, Disconnect};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

pub use host_keys::{
    AcceptAnyHostKey, HostKey, HostKeyPrompt, HostKeyVerifier, KnownHostsError, KnownHostsFile,
    Trust, TrustOnFirstUse,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectOptions {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub auth: Auth,
    #[serde(default = "default_term")]
    pub term: String,
    pub cols: u32,
    pub rows: u32,
}

fn default_port() -> u16 {
    22
}

fn default_term() -> String {
    "xterm-256color".into()
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Auth {
    Password { password: Zeroizing<String> },
    // TODO: PublicKey { key_id }, Agent, KeyboardInteractive
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Auth::Password { .. } => f.write_str("Password(<redacted>)"),
        }
    }
}

/// Input to a running session.
#[derive(Debug)]
pub enum Command {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
    Close,
}

/// Output from a running session.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Event {
    Data { data: Vec<u8> },
    Exit { code: Option<u32> },
    Closed { reason: Option<String> },
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("host key for {host} was rejected")]
    HostKeyRejected { host: String },
    #[error("authentication failed")]
    AuthFailed,
    #[error("{0}")]
    KnownHosts(String),
    #[error("timed out connecting to {0}")]
    Timeout(String),
    #[error("server did not present a host key")]
    NoHostKey,
    #[error(transparent)]
    Ssh(#[from] russh::Error),
}

/// How a presented host key compares with the one recorded for that host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyStatus {
    /// Matches the recorded key.
    Known,
    /// No key is recorded for this host yet.
    Unknown,
    /// A different key is recorded for this host.
    Changed,
}

/// Result of [`check_host_key`]: the key a server presents and how it compares.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyCheck {
    pub algorithm: String,
    /// OpenSSH-style `SHA256:...` fingerprint of the presented key.
    pub fingerprint: String,
    /// Fingerprint recorded for this host, if any.
    pub recorded_fingerprint: Option<String>,
    pub status: KeyStatus,
}

/// A live interactive shell. Dropping `commands` closes the session.
pub struct Session {
    pub commands: mpsc::Sender<Command>,
    pub events: mpsc::Receiver<Event>,
}

struct ClientHandler<V> {
    host: String,
    port: u16,
    verifier: Arc<V>,
    /// Set when the verifier fails, so `connect` can say why instead of "rejected".
    failure: Arc<std::sync::Mutex<Option<String>>>,
}

impl<V: HostKeyVerifier> client::Handler for ClientHandler<V> {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let host_key = HostKey::new(&self.host, self.port, &key.public_key());
        match self.verifier.verify(&host_key).await {
            Ok(accepted) => Ok(accepted),
            Err(e) => {
                *self.failure.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.to_string());
                Ok(false)
            }
        }
    }
}

/// Bounds the TCP connect, so an unreachable host fails promptly.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// A server that accepts the connection but never answers the login.
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);

async fn tcp_connect(host: &str, port: u16) -> Result<tokio::net::TcpStream, Error> {
    match tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    {
        Err(_) => Err(Error::Timeout(host.to_owned())),
        Ok(stream) => stream.map_err(|e| Error::Ssh(russh::Error::IO(e))),
    }
}

/// Connects, authenticates, opens a PTY shell and spawns the I/O pump.
pub async fn connect<V: HostKeyVerifier>(
    opts: ConnectOptions,
    verifier: Arc<V>,
) -> Result<Session, Error> {
    let config = Arc::new(client::Config {
        keepalive_interval: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let failure = Arc::new(std::sync::Mutex::new(None));
    let handler = ClientHandler {
        host: opts.host.clone(),
        port: opts.port,
        verifier,
        failure: failure.clone(),
    };

    // Only the TCP connect is bounded here: the handshake may wait on the user to
    // confirm a host key, which has its own timeout.
    let stream = tcp_connect(&opts.host, opts.port).await?;
    let mut handle: Handle<ClientHandler<V>> = client::connect_stream(config, stream, handler)
        .await
        .map_err(|e| match e {
            russh::Error::UnknownKey => {
                let failure = failure.lock().unwrap_or_else(|p| p.into_inner()).take();
                match failure {
                    Some(message) => Error::KnownHosts(message),
                    None => Error::HostKeyRejected {
                        host: opts.host.clone(),
                    },
                }
            }
            other => Error::Ssh(other),
        })?;

    let authed = match &opts.auth {
        Auth::Password { password } => tokio::time::timeout(
            AUTH_TIMEOUT,
            handle.authenticate_password(&opts.username, password.as_str()),
        )
        .await
        .map_err(|_| Error::Timeout(opts.host.clone()))??,
    };
    if !authed.success() {
        return Err(Error::AuthFailed);
    }

    let channel = handle.channel_open_session().await?;
    channel
        .request_pty(false, &opts.term, opts.cols, opts.rows, 0, 0, &[])
        .await?;
    channel.request_shell(false).await?;

    let (cmd_tx, cmd_rx) = mpsc::channel(256);
    let (evt_tx, evt_rx) = mpsc::channel(256);
    tokio::spawn(pump(handle, channel, cmd_rx, evt_tx));

    Ok(Session {
        commands: cmd_tx,
        events: evt_rx,
    })
}

struct ProbeHandler {
    host: String,
    port: u16,
    seen: Arc<std::sync::Mutex<Option<HostKey>>>,
}

impl client::Handler for ProbeHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let host_key = HostKey::new(&self.host, self.port, &key.public_key());
        *self.seen.lock().unwrap_or_else(|p| p.into_inner()) = Some(host_key);
        // Accept so the handshake completes. Nothing is authenticated or recorded.
        Ok(true)
    }
}

/// Reads the key a server presents and compares it with the recorded one. Stops after
/// the handshake: no login, no shell, and nothing is written to `known_hosts`.
pub async fn check_host_key(
    host: &str,
    port: u16,
    known_hosts: &KnownHostsFile,
) -> Result<KeyCheck, Error> {
    let seen = Arc::new(std::sync::Mutex::new(None));
    let handler = ProbeHandler {
        host: host.to_owned(),
        port,
        seen: seen.clone(),
    };
    let config = Arc::new(client::Config::default());
    let stream = tcp_connect(host, port).await?;
    let handle = match tokio::time::timeout(
        CONNECT_TIMEOUT,
        client::connect_stream(config, stream, handler),
    )
    .await
    {
        Err(_) => return Err(Error::Timeout(host.to_owned())),
        Ok(result) => result?,
    };
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;

    let key = seen
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
        .ok_or(Error::NoHostKey)?;
    let trust = known_hosts
        .lookup(&key)
        .map_err(|e| Error::KnownHosts(e.to_string()))?;
    let recorded_fingerprint = known_hosts
        .recorded_fingerprint(host, port)
        .map_err(|e| Error::KnownHosts(e.to_string()))?;
    let status = match trust {
        Trust::Known => KeyStatus::Known,
        Trust::Unknown => KeyStatus::Unknown,
        Trust::Changed { .. } => KeyStatus::Changed,
    };
    Ok(KeyCheck {
        algorithm: key.algorithm,
        fingerprint: key.fingerprint,
        recorded_fingerprint,
        status,
    })
}

async fn pump<H: client::Handler>(
    handle: Handle<H>,
    mut channel: russh::Channel<client::Msg>,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
) {
    let reason = loop {
        tokio::select! {
            cmd = commands.recv() => match cmd {
                Some(Command::Data(bytes)) => {
                    if let Err(e) = channel.data(&bytes[..]).await {
                        break Some(e.to_string());
                    }
                }
                Some(Command::Resize { cols, rows }) => {
                    let _ = channel.window_change(cols, rows, 0, 0).await;
                }
                Some(Command::Close) | None => break None,
            },
            msg = channel.wait() => match msg {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if events.send(Event::Data { data: data.to_vec() }).await.is_err() {
                        break None;
                    }
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    let _ = events.send(Event::Exit { code: Some(exit_status) }).await;
                }
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => break None,
                Some(_) => {}
            },
        }
    };

    let _ = channel.close().await;
    let _ = handle.disconnect(Disconnect::ByApplication, "", "en").await;
    let _ = events.send(Event::Closed { reason }).await;
}
