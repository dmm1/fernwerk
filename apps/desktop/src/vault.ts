// PIN-locked store for saved hosts, backed by the Rust commands in
// src-tauri/src/vault_cmds.rs. Passwords go in, never come out.
import { invoke } from "@tauri-apps/api/core";

export const MIN_PIN_LENGTH = 6;

/** Shape of `ssh_core::KeyCheck` after serde. */
export interface KeyCheck {
  algorithm: string;
  fingerprint: string;
  recordedFingerprint: string | null;
  status: "known" | "unknown" | "changed";
}

export type VaultState = "uninitialized" | "locked" | "unlocked";

export interface VaultStatus {
  state: VaultState;
  retryAfterSecs: number | null;
}

export type UnlockResult =
  | { status: "ok" }
  | { status: "wrongPin"; attemptsLeft: number }
  | { status: "lockedOut"; retryAfterSecs: number };

export interface HostSummary {
  id: string;
  label: string;
  host: string;
  port: number;
  username: string;
  hasPassword: boolean;
}

export type PasswordChange =
  | { type: "keep" }
  | { type: "set"; value: string }
  | { type: "clear" };

export interface HostInput {
  id: string | null;
  label: string;
  host: string;
  port: number;
  username: string;
  password: PasswordChange;
}

export const vault = {
  status: () => invoke<VaultStatus>("vault_status"),
  setup: (pin: string) => invoke<void>("vault_setup", { pin }),
  unlock: (pin: string) => invoke<UnlockResult>("vault_unlock", { pin }),
  lock: () => invoke<void>("vault_lock"),
  /** Permanently deletes the vault (forgot-PIN escape hatch). */
  reset: () => invoke<void>("vault_reset"),
  listHosts: () => invoke<HostSummary[]>("hosts_list"),
  saveHost: (input: HostInput) => invoke<HostSummary>("host_save", { input }),
  deleteHost: (id: string) => invoke<void>("host_delete", { id }),
  /** Reads the server's key without logging in; never records it. */
  checkHostKey: (id: string) => invoke<KeyCheck>("host_key_check", { id }),
};
