//! Asks the user to confirm an unknown host key. The verifier runs inside the
//! SSH handshake, so `confirm` parks on a oneshot until the UI answers.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use serde::Serialize;
use ssh_core::{HostKey, HostKeyPrompt};
use tauri::{AppHandle, Emitter};
use tokio::sync::{Mutex, oneshot};

const EVENT: &str = "host-key-prompt";
/// A connect that nobody answers is refused rather than left hanging.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct HostKeyRequest {
    id: u32,
    host: String,
    port: u16,
    algorithm: String,
    fingerprint: String,
    /// Set when the host is already known with a different key.
    previous_fingerprint: Option<String>,
}

pub struct HostKeyPrompter {
    app: AppHandle,
    next_id: AtomicU32,
    pending: Mutex<HashMap<u32, oneshot::Sender<bool>>>,
}

impl HostKeyPrompter {
    pub fn new(app: AppHandle) -> Self {
        Self {
            app,
            next_id: AtomicU32::new(1),
            pending: Mutex::default(),
        }
    }

    /// Resolves the prompt with `id`. Fails if it already timed out or was answered.
    pub async fn answer(&self, id: u32, accept: bool) -> Result<(), String> {
        let tx = self
            .pending
            .lock()
            .await
            .remove(&id)
            .ok_or("no pending host key prompt")?;
        let _ = tx.send(accept);
        Ok(())
    }
}

impl HostKeyPrompt for HostKeyPrompter {
    async fn confirm(&self, key: &HostKey, previous: Option<&str>) -> bool {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);

        let request = HostKeyRequest {
            id,
            host: key.host.clone(),
            port: key.port,
            algorithm: key.algorithm.clone(),
            fingerprint: key.fingerprint.clone(),
            previous_fingerprint: previous.map(str::to_owned),
        };
        if self.app.emit(EVENT, request).is_err() {
            self.pending.lock().await.remove(&id);
            return false;
        }

        match tokio::time::timeout(ANSWER_TIMEOUT, rx).await {
            Ok(Ok(accept)) => accept,
            _ => {
                self.pending.lock().await.remove(&id);
                false
            }
        }
    }
}
