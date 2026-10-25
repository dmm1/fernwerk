// SSH sessions over the Rust commands in src-tauri/src/lib.rs.
// Field names mirror `ssh_core::ConnectOptions` / `ssh_core::Event`.
import { Channel, invoke } from "@tauri-apps/api/core";

export type Auth = { type: "password"; password: string };

export interface ConnectOptions {
  host: string;
  port: number;
  username: string;
  auth: Auth;
}

/**
 * `direct` carries credentials from the UI. `saved` refers to a vault entry so
 * the stored password never has to pass through the UI.
 */
export type ConnectTarget =
  | ({ type: "direct" } & ConnectOptions)
  | { type: "saved"; hostId: string };

export interface TerminalSize {
  cols: number;
  rows: number;
}

export type SessionEvent =
  | { type: "data"; data: Uint8Array<ArrayBuffer> }
  | { type: "exit"; code: number | null }
  | { type: "closed"; reason: string | null };

export interface Session {
  write(data: Uint8Array<ArrayBuffer>): void;
  resize(cols: number, rows: number): void;
  close(): void;
}

// Shape of `ssh_core::Event` after serde: bytes arrive as a number array.
type RustEvent =
  | { type: "data"; data: number[] }
  | { type: "exit"; code: number | null }
  | { type: "closed"; reason: string | null };

/** Resolves once authenticated and the shell is open; rejects with a readable message. */
export async function connect(
  target: ConnectTarget,
  size: TerminalSize,
  onEvent: (event: SessionEvent) => void,
): Promise<Session> {
  const onEventChannel = new Channel<RustEvent>();
  onEventChannel.onmessage = (e) =>
    onEvent(e.type === "data" ? { type: "data", data: Uint8Array.from(e.data) } : e);

  let id: number;
  if (target.type === "saved") {
    id = await invoke<number>("ssh_connect_saved", {
      hostId: target.hostId,
      ...size,
      onEvent: onEventChannel,
    });
  } else {
    const { type: _, ...opts } = target;
    id = await invoke<number>("ssh_connect", { opts: { ...opts, ...size }, onEvent: onEventChannel });
  }

  // TODO: send raw bytes (tauri::ipc::Request body) instead of JSON arrays.
  return {
    write: (data) => void invoke("ssh_write", { id, data: Array.from(data) }).catch(() => {}),
    resize: (cols, rows) => void invoke("ssh_resize", { id, cols, rows }).catch(() => {}),
    close: () => void invoke("ssh_close", { id }).catch(() => {}),
  };
}
