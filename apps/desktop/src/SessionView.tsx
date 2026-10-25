import { useEffect, useRef, useState } from "react";
import { Badge, Button } from "@dmm1/daemon-ui";
import { Terminal, type TerminalHandle } from "@fernwerk/terminal";
import { connect, type ConnectTarget, type Session } from "./ssh";

export interface ActiveSession {
  title: string;
  target: ConnectTarget;
}

type Status = "connecting" | "connected" | "closed";

const STATUS: Record<Status, { label: string; variant: "warning" | "success" | "error" }> = {
  connecting: { label: "Connecting", variant: "warning" },
  connected: { label: "Online", variant: "success" },
  closed: { label: "Closed", variant: "error" },
};

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
      // A superseded connection (e.g. StrictMode's double effect) still reports
      // its own "closed" when we shut it down; don't let it mark this view closed.
      if (cancelled) return;
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

  const state = STATUS[status];

  return (
    <div className="session">
      <header className="flex flex-none items-center gap-3 border-b border-border bg-background-panel px-3 py-2">
        <Badge variant={state.variant} className="gap-1.5">
          <span className="h-1.5 w-1.5 rounded-full bg-current motion-safe:animate-pulse" />
          {state.label}
        </Badge>
        <span className="truncate font-mono text-xs text-foreground-bright">{active.title}</span>
        {error && <span className="truncate text-xs text-error">{error}</span>}
        <span className="flex-1" />
        <Button size="sm" variant="outline" onClick={onLock}>
          Lock
        </Button>
        <Button size="sm" onClick={onExit}>
          {status === "closed" ? "Back" : "Disconnect"}
        </Button>
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
