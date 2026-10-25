import { useCallback, useEffect, useState } from "react";
import { HostManager } from "./HostManager";
import { LockScreen } from "./LockScreen";
import { SessionView, type ActiveSession } from "./SessionView";
import { useIdleLock } from "./useIdleLock";
import { vault, type VaultStatus } from "./vault";
import "./styles.css";

const IDLE_LOCK_MS = 15 * 60 * 1000;

export function App() {
  const [status, setStatus] = useState<VaultStatus | null>(null);
  const [session, setSession] = useState<ActiveSession | null>(null);

  const refresh = useCallback(() => {
    vault.status().then(setStatus);
  }, []);
  useEffect(refresh, [refresh]);

  const lock = useCallback(async () => {
    await vault.lock();
    refresh();
  }, [refresh]);

  const unlocked = status?.state === "unlocked";
  useIdleLock(unlocked, IDLE_LOCK_MS, lock);

  if (!status) return null;

  return (
    <div className="app">
      {/* Locking hides a running session without disconnecting it. */}
      {session && (
        <div className="layer" hidden={!unlocked}>
          <SessionView session={session} onExit={() => setSession(null)} onLock={lock} />
        </div>
      )}
      {!unlocked && <LockScreen status={status} onChange={refresh} />}
      {unlocked && !session && <HostManager onConnect={setSession} onLock={lock} />}
    </div>
  );
}
