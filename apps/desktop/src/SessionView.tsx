import { useEffect, useRef, useState } from "react";
import { Terminal, type TerminalHandle } from "@fernwerk/terminal";
import { connect, type ConnectTarget, type Session } from "./ssh";

export interface ActiveSession {
  title: string;
  target: ConnectTarget;
}

type Status = "connecting" | "connected" | "closed";

interface Props {
  session: ActiveSession;
  onExit: () => void;
  onLock: () => void;
}

export function SessionView({ session: active, onExit, onLock }: Props) {
  const termRef = useRef<TerminalHandle>(null);
  const sessionRef = useRef<Session | null>(null);
  const [status, setStatus] = useState<Status>("connecting");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const term = termRef.current;
    if (!term) return;

    connect(active.target, term.size(), (event) => {
      if (event.type === "data") term.write(event.data);
      else if (event.type === "closed") {
        setStatus("closed");
        if (event.reason) setError(event.reason);
      }
    })
      .then((session) => {
        if (cancelled) return session.close();
        sessionRef.current = session;
        setStatus("connected");
        // Sync in case the terminal was resized while connecting.
        const now = term.size();
        session.resize(now.cols, now.rows);
        term.focus();
      })
      .catch((e: unknown) => {
        if (cancelled) return;
        setStatus("closed");
        setError(e instanceof Error ? e.message : String(e));
      });

    return () => {
      cancelled = true;
      sessionRef.current?.close();
      sessionRef.current = null;
    };
  }, [active]);

  return (
    <div className="session">
      <header className="session-bar">
        <span className={`dot ${status}`} />
        <span className="title">{active.title}</span>
        {error && <span className="error">{error}</span>}
        <span className="spacer" />
        <button className="secondary" onClick={onLock}>
          Lock
        </button>
        <button onClick={onExit}>{status === "closed" ? "Back" : "Disconnect"}</button>
      </header>
      <div className="session-term">
        <Terminal
          ref={termRef}
          onInput={(d) => sessionRef.current?.write(d)}
          onResize={({ cols, rows }) => sessionRef.current?.resize(cols, rows)}
        />
      </div>
    </div>
  );
}
