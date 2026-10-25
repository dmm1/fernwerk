//! End-to-end tests against an in-process russh server, so no Docker or sshd is needed.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey};
use russh::server::{self, Auth, Msg, Session as ServerSession};
use russh::{Channel, ChannelId};
use ssh_core::{Command, ConnectOptions, Error, Event, KnownHostsFile};
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

#[tokio::test]
async fn shell_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let known_hosts = Arc::new(KnownHostsFile::new(dir.path().join("known_hosts")));
    let addr = start_server(random_key()).await;

    let mut session = ssh_core::connect(options(addr, PASSWORD), known_hosts)
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
    let known_hosts = Arc::new(KnownHostsFile::new(dir.path().join("known_hosts")));
    let addr = start_server(random_key()).await;

    let result = ssh_core::connect(options(addr, "nope"), known_hosts).await;
    assert!(matches!(result, Err(Error::AuthFailed)));
}

#[tokio::test]
async fn changed_host_key_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("known_hosts");

    // First contact learns the key (TOFU) and a reconnect with it succeeds.
    let addr = start_server(random_key()).await;
    let known_hosts = Arc::new(KnownHostsFile::new(&path));
    ssh_core::connect(options(addr, PASSWORD), known_hosts.clone())
        .await
        .expect("first connect");
    ssh_core::connect(options(addr, PASSWORD), known_hosts)
        .await
        .expect("reconnect with known key");

    // A server on a host:port we already trust, presenting a different key, must be
    // refused. Simulate it by pointing the recorded entry at a fresh server.
    let impostor = start_server(random_key()).await;
    let contents = std::fs::read_to_string(&path).unwrap();
    std::fs::write(
        &path,
        contents.replace(
            &format!("]:{}", addr.port()),
            &format!("]:{}", impostor.port()),
        ),
    )
    .unwrap();

    let result = ssh_core::connect(
        options(impostor, PASSWORD),
        Arc::new(KnownHostsFile::new(&path)),
    )
    .await;
    assert!(matches!(result, Err(Error::HostKeyRejected { .. })));
}
