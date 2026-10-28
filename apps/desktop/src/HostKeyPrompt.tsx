// Asks before trusting a host key we have never seen, or one that differs from the
// key recorded for that host. The Rust verifier waits on `host_key_respond`, so an
// unanswered prompt times out and refuses the connection.
import { Fragment, useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@dmm1/daemon-ui";

// Shape of `HostKeyRequest` in src-tauri/src/host_key_prompt.rs.
export interface HostKeyRequest {
  id: number;
  host: string;
  port: number;
  algorithm: string;
  fingerprint: string;
  previousFingerprint: string | null;
}

export function HostKeyPrompt() {
  const [queue, setQueue] = useState<HostKeyRequest[]>([]);

  useEffect(() => {
    const unlisten = listen<HostKeyRequest>("host-key-prompt", (e) =>
      setQueue((q) => [...q, e.payload]),
    );
    return () => void unlisten.then((stop) => stop());
  }, []);

  const current = queue[0];

  // Closing the dialog another way (Escape) counts as rejecting. The backend
  // ignores the second answer after an Action click, since the prompt is gone.
  const answer = (accept: boolean) => {
    if (!current) return;
    setQueue((q) => q.slice(1));
    void invoke("host_key_respond", { id: current.id, accept }).catch(() => {});
  };

  const changed = current?.previousFingerprint != null;
  const rows: [string, string | null][] = !current
    ? []
    : changed
      ? [
          ["Saved", current.previousFingerprint],
          ["New", current.fingerprint],
          ["Type", current.algorithm],
        ]
      : [
          ["Type", current.algorithm],
          ["Fingerprint", current.fingerprint],
        ];

  return (
    <AlertDialog open={current !== undefined} onOpenChange={(open) => !open && answer(false)}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{changed ? "Host key has changed" : "Trust this server?"}</AlertDialogTitle>
          <AlertDialogDescription>
            {current &&
              (changed
                ? `${current.host}:${current.port} presented a different key than the one saved for it. This can mean the server was reinstalled, or that someone is intercepting the connection. Only replace the key if you can confirm the new fingerprint with the server's administrator.`
                : `${current.host}:${current.port} is new to this app. Only continue if you can confirm this fingerprint with the server's administrator.`)}
          </AlertDialogDescription>
        </AlertDialogHeader>
        {current && (
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 font-mono text-xs break-all">
            {rows.map(([label, value]) => (
              <Fragment key={label}>
                <dt className="text-foreground-dim">{label}</dt>
                <dd>{value}</dd>
              </Fragment>
            ))}
          </dl>
        )}
        <AlertDialogFooter>
          <AlertDialogCancel>Reject</AlertDialogCancel>
          <AlertDialogAction onClick={() => answer(true)}>
            {changed ? "Replace key and connect" : "Trust and connect"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
