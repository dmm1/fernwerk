//! End-to-end tests against an in-process russh server, so no Docker or sshd is needed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg, Session as ServerSession};
use russh::{Channel, ChannelId};
use ssh_core::{
    Command, ConnectOptions, Error, Event, HostKey, HostKeyPrompt, KeyStatus, KnownHostsFile,
    TrustOnFirstUse,
};
use tokio::net::TcpListener;
use tokio::time::timeout;

const USER: &str = "dev";
const PASSWORD: &str = "secret";

/// Accepts `dev`/`secret`, opens a shell, and echoes input back as `echo:<input>`.
#[derive(Clone)]
struct EchoServer;

impl server::Handler for EchoServer {
    type Error = russh::Error;

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        Ok(if user == USER && password == PASSWORD {
            Auth::Accept
        } else {
            Auth::reject()
        })
    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut ServerSession,
    ) -> Result<(), Self::Error> {
        session.data(channel, [b"echo:", data].concat())?;
        Ok(())
    }
}

async fn start_server(key: PrivateKey) -> SocketAddr {
    let config = Arc::new(server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::ZERO),
        ..Default::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let config = config.clone();
            tokio::spawn(async move {
                if let Ok(session) = server::run_stream(config, stream, EchoServer).await {
                    let _ = session.await;
                }
            });
        }
    });
    addr
}

fn random_key() -> PrivateKey {
    PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519).unwrap()
}

fn options(addr: SocketAddr, password: &str) -> ConnectOptions {
    ConnectOptions {
        host: addr.ip().to_string(),
        port: addr.port(),
        username: USER.into(),
        auth: ssh_core::Auth::Password {
            password: zeroize::Zeroizing::new(password.to_owned()),
        },
        term: "xterm-256color".into(),
        cols: 80,
        rows: 24,
    }
}

/// Answers every host key prompt the same way and records the `previous` fingerprint
/// each prompt was shown, so tests can count prompts and see whether they were changes.
#[derive(Clone)]
struct Answer {
    accept: bool,
    asked: Arc<Mutex<Vec<Option<String>>>>,
}

impl HostKeyPrompt for Answer {
    async fn confirm(&self, _key: &HostKey, previous: Option<&str>) -> bool {
        self.asked.lock().unwrap().push(previous.map(str::to_owned));
        self.accept
    }
}

type Asked = Arc<Mutex<Vec<Option<String>>>>;

fn prompts(asked: &Asked) -> usize {
    asked.lock().unwrap().len()
}

fn trust_with(path: &std::path::Path, accept: bool) -> (Arc<TrustOnFirstUse<Answer>>, Asked) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let answer = Answer {
        accept,
        asked: asked.clone(),
    };
    let verifier = TrustOnFirstUse::new(KnownHostsFile::new(path), answer);
    (Arc::new(verifier), asked)
}

#[tokio::test]
async fn shell_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let (verifier, _) = trust_with(&dir.path().join("known_hosts"), true);
    let addr = start_server(random_key()).await;

    let mut session = ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("connect");
    session
        .commands
        .send(Command::Data(b"hello".to_vec()))
        .await
        .unwrap();

    let event = timeout(Duration::from_secs(5), session.events.recv())
        .await
        .expect("timed out waiting for echo")
        .expect("session ended early");
    match event {
        Event::Data { data } => assert_eq!(data, b"echo:hello"),
        other => panic!("unexpected event: {other:?}"),
    }

    session.commands.send(Command::Close).await.unwrap();
}

#[tokio::test]
async fn wrong_password_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (verifier, _) = trust_with(&dir.path().join("known_hosts"), true);
    let addr = start_server(random_key()).await;

    let result = ssh_core::connect(options(addr, "nope"), verifier).await;
    assert!(matches!(result, Err(Error::AuthFailed)));
}

#[tokio::test]
async fn unknown_host_is_rejected_when_user_declines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let (verifier, asked) = trust_with(&path, false);
    let addr = start_server(random_key()).await;

    let result = ssh_core::connect(options(addr, PASSWORD), verifier).await;
    assert!(matches!(result, Err(Error::HostKeyRejected { .. })));
    assert_eq!(prompts(&asked), 1);
    assert!(!path.exists(), "declined key must not be saved");
}

#[tokio::test]
async fn accepted_host_key_is_remembered_without_prompting_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let addr = start_server(random_key()).await;

    let (first, asked) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), first)
        .await
        .expect("first connect");
    assert_eq!(prompts(&asked), 1);

    // A later connection to the same key passes even if the user would now decline.
    let (second, asked) = trust_with(&path, false);
    ssh_core::connect(options(addr, PASSWORD), second)
        .await
        .expect("reconnect with known key");
    assert_eq!(prompts(&asked), 0);
}

/// Learns `addr`'s key into `path`, then points the recorded entry at `impostor`'s
/// port, so `impostor` looks like a server whose key has changed.
async fn record_then_swap_key(path: &std::path::Path) -> (SocketAddr, SocketAddr) {
    let addr = start_server(random_key()).await;
    let (verifier, _) = trust_with(path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("first connect");

    let impostor = start_server(random_key()).await;
    // Host names are hashed, so re-record the saved key in plain form for the impostor.
    let key = recorded_key(path);
    std::fs::write(path, format!("[127.0.0.1]:{} {key}\n", impostor.port())).unwrap();
    (addr, impostor)
}

/// The `<algorithm> <base64>` part of the only entry in `path`.
fn recorded_key(path: &std::path::Path) -> String {
    let contents = std::fs::read_to_string(path).unwrap();
    let mut entries = contents.lines().filter(|l| !l.trim().is_empty());
    let entry = entries.next().expect("one entry");
    assert!(entries.next().is_none(), "known_hosts:\n{contents}");
    entry.split_once(' ').unwrap().1.to_owned()
}

#[tokio::test]
async fn changed_host_key_is_rejected_when_user_declines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let (_, impostor) = record_then_swap_key(&path).await;
    let before = std::fs::read_to_string(&path).unwrap();

    let (verifier, asked) = trust_with(&path, false);
    let result = ssh_core::connect(options(impostor, PASSWORD), verifier).await;
    assert!(matches!(result, Err(Error::HostKeyRejected { .. })));
    // The prompt must show the saved fingerprint, and a decline keeps the old entry.
    let asked = asked.lock().unwrap().clone();
    assert_eq!(asked.len(), 1);
    assert!(
        asked[0]
            .as_deref()
            .is_some_and(|f| f.starts_with("SHA256:"))
    );
    assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
}

#[tokio::test]
async fn changed_host_key_is_replaced_when_user_accepts() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let (_, impostor) = record_then_swap_key(&path).await;

    let (verifier, asked) = trust_with(&path, true);
    ssh_core::connect(options(impostor, PASSWORD), verifier)
        .await
        .expect("connect after replacing the key");
    assert_eq!(prompts(&asked), 1);

    // The new key is now the recorded one, so a reconnect doesn't prompt.
    let (verifier, asked) = trust_with(&path, false);
    ssh_core::connect(options(impostor, PASSWORD), verifier)
        .await
        .expect("reconnect with replaced key");
    assert_eq!(prompts(&asked), 0);
    recorded_key(&path);
}

#[tokio::test]
async fn forgotten_host_prompts_again_when_readded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let addr = start_server(random_key()).await;

    let (verifier, _) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("first connect");

    KnownHostsFile::new(&path)
        .forget(&addr.ip().to_string(), addr.port())
        .unwrap();

    let (verifier, asked) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("connect after forgetting");
    assert_eq!(prompts(&asked), 1);
}

#[tokio::test]
async fn unreadable_known_hosts_is_reported_not_as_rejection() {
    let dir = tempfile::tempdir().unwrap();
    // A directory where the file should be: the file can't be read.
    let path = dir.path().join("known_hosts");
    std::fs::create_dir(&path).unwrap();
    let addr = start_server(random_key()).await;

    let (verifier, asked) = trust_with(&path, true);
    let result = ssh_core::connect(options(addr, PASSWORD), verifier).await;
    assert!(
        matches!(result, Err(Error::KnownHosts(_))),
        "got {:?}",
        result.as_ref().err()
    );
    assert_eq!(prompts(&asked), 0);
}

#[tokio::test]
async fn host_names_are_hashed_and_forgettable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let addr = start_server(random_key()).await;

    let (verifier, _) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("first connect");

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(contents.starts_with("|1|"), "known_hosts:\n{contents}");
    assert!(
        !contents.contains("127.0.0.1"),
        "host name stored in plain text"
    );

    // The hashed entry is recognized, so no prompt.
    let (verifier, asked) = trust_with(&path, false);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("connect with hashed entry");
    assert_eq!(prompts(&asked), 0);

    KnownHostsFile::new(&path)
        .forget("127.0.0.1", addr.port())
        .unwrap();
    assert!(!std::fs::read_to_string(&path).unwrap().contains("|1|"));

    let (verifier, asked) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("connect after forgetting hashed entry");
    assert_eq!(prompts(&asked), 1);
}

#[tokio::test]
async fn harden_hashes_plain_entries_and_keeps_them_trusted() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let addr = start_server(random_key()).await;
    let other = start_server(random_key()).await;

    let (verifier, _) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("first connect");
    // The plain, multi-host form older versions (and OpenSSH) write.
    let key = recorded_key(&path);
    let plain = format!(
        "# comment\n\n[127.0.0.1]:{},[127.0.0.1]:{} {key}\n",
        addr.port(),
        other.port()
    );
    std::fs::write(&path, plain).unwrap();

    KnownHostsFile::new(&path).harden().unwrap();

    let contents = std::fs::read_to_string(&path).unwrap();
    assert!(!contents.contains("127.0.0.1"), "known_hosts:\n{contents}");
    assert_eq!(contents.matches("|1|").count(), 2, "one line per host");
    assert!(contents.starts_with("# comment\n"));

    let (verifier, asked) = trust_with(&path, false);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("still trusted after hashing");
    assert_eq!(prompts(&asked), 0);

    // Forgetting one host leaves the other's entry in place.
    KnownHostsFile::new(&path)
        .forget("127.0.0.1", addr.port())
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&path)
            .unwrap()
            .matches("|1|")
            .count(),
        1
    );
}

#[tokio::test]
async fn forget_removes_the_right_entry_after_comment_lines() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let addr = start_server(random_key()).await;

    let (verifier, _) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("first connect");
    let key = recorded_key(&path);
    std::fs::write(
        &path,
        format!(
            "# one\n# two\n[127.0.0.1]:{} {key}\n[127.0.0.1]:1 {key}\n",
            addr.port()
        ),
    )
    .unwrap();

    KnownHostsFile::new(&path)
        .forget("127.0.0.1", addr.port())
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("# one\n# two\n[127.0.0.1]:1 {key}\n")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn known_hosts_is_private_to_its_owner() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let addr = start_server(random_key()).await;
    let (verifier, _) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("first connect");

    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[tokio::test]
async fn clearing_known_hosts_prompts_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let addr = start_server(random_key()).await;

    let (verifier, _) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("first connect");

    KnownHostsFile::new(&path).clear().unwrap();
    KnownHostsFile::new(&path).clear().unwrap(); // already gone: still fine

    let (verifier, asked) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("connect after clearing");
    assert_eq!(prompts(&asked), 1);
}

#[tokio::test]
async fn host_key_check_reports_unknown_then_known_without_recording() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let addr = start_server(random_key()).await;
    let known = KnownHostsFile::new(&path);

    // Unknown: nothing is recorded by just looking.
    let check = ssh_core::check_host_key("127.0.0.1", addr.port(), &known)
        .await
        .expect("check");
    assert_eq!(check.status, KeyStatus::Unknown);
    assert!(check.recorded_fingerprint.is_none());
    assert!(!path.exists(), "a check must not record the key");

    // Known: after trusting it once, the same key compares equal.
    let (verifier, _) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("connect");
    let check = ssh_core::check_host_key("127.0.0.1", addr.port(), &known)
        .await
        .expect("check");
    assert_eq!(check.status, KeyStatus::Known);
    assert_eq!(
        check.recorded_fingerprint.as_deref(),
        Some(check.fingerprint.as_str())
    );
}

#[tokio::test]
async fn host_key_check_reports_changed_key() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let (_, impostor) = record_then_swap_key(&path).await;

    let check = ssh_core::check_host_key("127.0.0.1", impostor.port(), &KnownHostsFile::new(&path))
        .await
        .expect("check");
    assert_eq!(check.status, KeyStatus::Changed);
    assert_ne!(
        check.recorded_fingerprint.as_deref(),
        Some(check.fingerprint.as_str())
    );
}
