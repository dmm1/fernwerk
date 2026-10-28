//! End-to-end tests against an in-process russh server, so no Docker or sshd is needed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::STANDARD};
use hmac::{Hmac, KeyInit, Mac};
use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg, Session as ServerSession};
use russh::{Channel, ChannelId};
use sha1::Sha1;
use ssh_core::{
    Command, ConnectOptions, Error, Event, HostKey, HostKeyPrompt, KnownHostsFile, TrustOnFirstUse,
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
            password: password.into(),
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
    let contents = std::fs::read_to_string(path).unwrap();
    std::fs::write(
        path,
        contents.replace(
            &format!("]:{}", addr.port()),
            &format!("]:{}", impostor.port()),
        ),
    )
    .unwrap();
    (addr, impostor)
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
    let content = std::fs::read_to_string(&path).unwrap();
    // russh starts a new file with a blank line, so count only the entries.
    assert_eq!(
        content.lines().filter(|l| !l.is_empty()).count(),
        1,
        "known_hosts:\n{content}"
    );
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
async fn forgetting_removes_hashed_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");
    let addr = start_server(random_key()).await;

    let (verifier, _) = trust_with(&path, true);
    ssh_core::connect(options(addr, PASSWORD), verifier)
        .await
        .expect("first connect");

    // Rewrite the entry the way `HashKnownHosts yes` does: HMAC-SHA1 of the host name.
    let salt = [7u8; 20];
    let mut mac = Hmac::<Sha1>::new_from_slice(&salt).unwrap();
    mac.update(format!("[127.0.0.1]:{}", addr.port()).as_bytes());
    let hashed = format!(
        "|1|{}|{}",
        STANDARD.encode(salt),
        STANDARD.encode(mac.finalize().into_bytes())
    );
    let contents = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        contents.replace(&format!("[127.0.0.1]:{}", addr.port()), &hashed),
    )
    .unwrap();

    // The hashed entry is still recognized, so no prompt.
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
