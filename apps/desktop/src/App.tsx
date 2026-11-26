import { useCallback, useEffect, useState } from "react";
import { HostKeyPrompt } from "./HostKeyPrompt";
import { HostManager } from "./HostManager";
import { LockScreen } from "./LockScreen";
import { SessionView, type ActiveSession } from "./SessionView";
import { TitleBar } from "./TitleBar";
import { UpdateBanner } from "./UpdateBanner";
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
      <TitleBar />
      <UpdateBanner hasSession={session !== null} />
      <HostKeyPrompt />
      <main className="app-main">
        {/* Locking disconnects the session; it stays visible as "Closed" after unlocking. */}
        {session && (
          <div className="layer" hidden={!unlocked}>
            <SessionView session={session} onExit={() => setSession(null)} onLock={lock} />
          </div>
        )}
        {!unlocked && <LockScreen status={status} onChange={refresh} />}
        {unlocked && !session && (
          <HostManager
            onConnect={setSession}
            onLock={lock}
            deviceKeyInFile={status.deviceKeyInFile}
          />
        )}
      </main>
    </div>
  );
}
