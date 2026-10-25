//! Tauri commands for the PIN-locked vault. Secrets stay on the Rust side: the
//! UI only ever receives `HostSummary` (with `hasPassword`), never a password.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::State;
use vault::{HostInput, HostSummary, KdfParams, Throttle, Vault};
use zeroize::Zeroizing;

use crate::AppState;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    state: &'static str,
    retry_after_secs: Option<u64>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
pub enum UnlockResult {
    Ok,
    #[serde(rename_all = "camelCase")]
    WrongPin {
        attempts_left: u32,
    },
    #[serde(rename_all = "camelCase")]
    LockedOut {
        retry_after_secs: u64,
    },
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[tauri::command]
pub async fn vault_status(state: State<'_, Arc<AppState>>) -> Result<VaultStatus, String> {
    let status = |state, retry_after_secs| VaultStatus {
        state,
        retry_after_secs,
    };
    if state.vault.lock().await.is_some() {
        return Ok(status("unlocked", None));
    }
    if !Vault::exists(&state.vault_path()) {
        return Ok(status("uninitialized", None));
    }
    let retry = Throttle::load(&state.throttle_path()).retry_after(now());
    Ok(status("locked", retry))
}

#[tauri::command]
pub async fn vault_setup(
    state: State<'_, Arc<AppState>>,
    pin: Zeroizing<String>,
) -> Result<(), String> {
    let mut guard = state.vault.lock().await;
    let path = state.vault_path();
    if Vault::exists(&path) {
        return Err("a vault already exists".into());
    }
    let secret = state.device_key.create()?;
    let vault = tauri::async_runtime::spawn_blocking(move || {
        Vault::create(path, &pin, &secret, KdfParams::default())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;
    *guard = Some(vault);
    Ok(())
}

#[tauri::command]
pub async fn vault_unlock(
    state: State<'_, Arc<AppState>>,
    pin: Zeroizing<String>,
) -> Result<UnlockResult, String> {
    // Holding the lock across the attempt serializes guesses, so the throttle can't be raced.
    let mut guard = state.vault.lock().await;
    if guard.is_some() {
        return Ok(UnlockResult::Ok);
    }
    let throttle_path = state.throttle_path();
    let mut throttle = Throttle::load(&throttle_path);
    if let Some(secs) = throttle.retry_after(now()) {
        return Ok(UnlockResult::LockedOut {
            retry_after_secs: secs,
        });
    }

    let secret = state.device_key.load()?;
    let path = state.vault_path();
    let result = tauri::async_runtime::spawn_blocking(move || Vault::unlock(path, &pin, &secret))
        .await
        .map_err(|e| e.to_string())?;

    match result {
        Ok(vault) => {
            throttle.record_success();
            let _ = throttle.save(&throttle_path);
            *guard = Some(vault);
            Ok(UnlockResult::Ok)
        }
        Err(vault::Error::WrongPin) => {
            throttle.record_failure(now());
            throttle.save(&throttle_path).map_err(|e| e.to_string())?;
            Ok(match throttle.retry_after(now()) {
                Some(secs) => UnlockResult::LockedOut {
                    retry_after_secs: secs,
                },
                None => UnlockResult::WrongPin {
                    attempts_left: throttle.attempts_left(),
                },
            })
        }
        Err(e) => Err(e.to_string()),
    }
}

#[tauri::command]
pub async fn vault_lock(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    // Dropping the vault zeroizes the key and all saved passwords.
    state.vault.lock().await.take();
    Ok(())
}

/// Forgot-PIN escape hatch: permanently deletes all saved hosts and credentials.
#[tauri::command]
pub async fn vault_reset(state: State<'_, Arc<AppState>>) -> Result<(), String> {
    let mut guard = state.vault.lock().await;
    guard.take();
    for path in [state.vault_path(), state.throttle_path()] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    state.device_key.delete();
    Ok(())
}

#[tauri::command]
pub async fn hosts_list(state: State<'_, Arc<AppState>>) -> Result<Vec<HostSummary>, String> {
    let guard = state.vault.lock().await;
    Ok(guard.as_ref().ok_or("vault is locked")?.hosts())
}

#[tauri::command]
pub async fn host_save(
    state: State<'_, Arc<AppState>>,
    input: HostInput,
) -> Result<HostSummary, String> {
    let mut guard = state.vault.lock().await;
    let vault = guard.as_mut().ok_or("vault is locked")?;
    vault.upsert_host(input).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn host_delete(state: State<'_, Arc<AppState>>, id: String) -> Result<(), String> {
    let mut guard = state.vault.lock().await;
    let vault = guard.as_mut().ok_or("vault is locked")?;
    vault.delete_host(&id).map_err(|e| e.to_string())
}
