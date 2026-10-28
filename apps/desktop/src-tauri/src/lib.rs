mod device_key;
mod host_key_prompt;
mod vault_cmds;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use device_key::DeviceKey;
use host_key_prompt::HostKeyPrompter;
use ssh_core::{Auth, Command, ConnectOptions, Event, KnownHostsFile, TrustOnFirstUse};
use tauri::ipc::Channel;
use tauri::{Manager, State};
use tokio::sync::{Mutex, mpsc};
use vault::Vault;

pub(crate) struct AppState {
    data_dir: PathBuf,
    next_id: AtomicU32,
    sessions: Mutex<HashMap<u32, mpsc::Sender<Command>>>,
    host_keys: Arc<TrustOnFirstUse<HostKeyPrompter>>,
    /// `Some` while unlocked. Dropping it wipes keys and passwords from memory.
    vault: Mutex<Option<Vault>>,
    device_key: DeviceKey,
}

impl AppState {
    fn vault_path(&self) -> PathBuf {
        self.data_dir.join("vault.json")
    }

    fn throttle_path(&self) -> PathBuf {
        self.data_dir.join("unlock-attempts.json")
    }

    async fn send(&self, id: u32, cmd: Command) -> Result<(), String> {
        let tx = self.sessions.lock().await.get(&id).cloned();
        match tx {
            Some(tx) => tx.send(cmd).await.map_err(|_| "session closed".into()),
            None => Err(format!("no session {id}")),
        }
    }

    async fn start_session(
        self: &Arc<Self>,
        opts: ConnectOptions,
        on_event: Channel<Event>,
    ) -> Result<u32, String> {
        let session = ssh_core::connect(opts, self.host_keys.clone())
            .await
            .map_err(|e| e.to_string())?;

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.sessions.lock().await.insert(id, session.commands);

        let state = Arc::clone(self);
        let mut events = session.events;
        tauri::async_runtime::spawn(async move {
            while let Some(event) = events.recv().await {
                let closed = matches!(event, Event::Closed { .. });
                if on_event.send(event).is_err() || closed {
                    break;
                }
            }
            state.sessions.lock().await.remove(&id);
        });
        Ok(id)
    }
}

#[tauri::command]
async fn ssh_connect(
    state: State<'_, Arc<AppState>>,
    opts: ConnectOptions,
    on_event: Channel<Event>,
) -> Result<u32, String> {
    state.start_session(opts, on_event).await
}

/// Connects to a saved host using its stored password, which never leaves Rust.
#[tauri::command]
async fn ssh_connect_saved(
    state: State<'_, Arc<AppState>>,
    host_id: String,
    cols: u32,
    rows: u32,
    on_event: Channel<Event>,
) -> Result<u32, String> {
    let opts = {
        let guard = state.vault.lock().await;
        let host = guard
            .as_ref()
            .ok_or("vault is locked")?
            .host(&host_id)
            .ok_or("unknown host")?;
        let password = host
            .password
            .as_ref()
            .ok_or("no saved password for this host")?;
        ConnectOptions {
            host: host.host.clone(),
            port: host.port,
            username: host.username.clone(),
            auth: Auth::Password {
                password: password.to_string(),
            },
            term: "xterm-256color".into(),
            cols,
            rows,
        }
    };
    state.start_session(opts, on_event).await
}

/// Answers a `host-key-prompt` event. `accept: false` refuses the connection.
#[tauri::command]
async fn host_key_respond(
    state: State<'_, Arc<AppState>>,
    id: u32,
    accept: bool,
) -> Result<(), String> {
    state.host_keys.prompt().answer(id, accept).await
}

#[tauri::command]
async fn ssh_write(state: State<'_, Arc<AppState>>, id: u32, data: Vec<u8>) -> Result<(), String> {
    state.send(id, Command::Data(data)).await
}

#[tauri::command]
async fn ssh_resize(
    state: State<'_, Arc<AppState>>,
    id: u32,
    cols: u32,
    rows: u32,
) -> Result<(), String> {
    state.send(id, Command::Resize { cols, rows }).await
}

#[tauri::command]
async fn ssh_close(state: State<'_, Arc<AppState>>, id: u32) -> Result<(), String> {
    state.send(id, Command::Close).await
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let data_dir = app.path().app_data_dir()?;
            let prompter = HostKeyPrompter::new(app.handle().clone());
            app.manage(Arc::new(AppState {
                host_keys: Arc::new(TrustOnFirstUse::new(
                    KnownHostsFile::new(data_dir.join("known_hosts")),
                    prompter,
                )),
                device_key: DeviceKey::new(&data_dir),
                data_dir,
                next_id: AtomicU32::new(1),
                sessions: Mutex::default(),
                vault: Mutex::default(),
            }));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ssh_connect,
            ssh_connect_saved,
            host_key_respond,
            ssh_write,
            ssh_resize,
            ssh_close,
            vault_cmds::vault_status,
            vault_cmds::vault_setup,
            vault_cmds::vault_unlock,
            vault_cmds::vault_lock,
            vault_cmds::vault_reset,
            vault_cmds::hosts_list,
            vault_cmds::host_save,
            vault_cmds::host_delete,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
