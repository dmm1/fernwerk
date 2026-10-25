// Checks GitHub Releases for a newer signed build (`plugins.updater` in
// src-tauri/tauri.conf.json) and installs it on request.
import { useCallback, useEffect, useRef, useState } from "react";
import { check, type Update } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

export type UpdateState =
  | { kind: "idle" }
  | { kind: "available"; update: Update }
  | { kind: "installing"; update: Update; progress: number | null }
  | { kind: "failed"; update: Update; error: string };

export function useUpdater() {
  const [state, setState] = useState<UpdateState>({ kind: "idle" });
  const checkedOnce = useRef(false);
  const idle = state.kind === "idle";

  // Check at startup, then periodically while nothing is pending. "Later"
  // returns to idle, so a dismissed update reappears at the next interval.
  useEffect(() => {
    if (!idle) return;
    const run = () =>
      check().then(
        (update) => update && setState({ kind: "available", update }),
        // Offline, or no release published yet: try again next interval.
        (e: unknown) => console.warn("Update check failed:", e),
      );
    if (!checkedOnce.current) {
      checkedOnce.current = true;
      void run();
    }
    const timer = window.setInterval(run, CHECK_INTERVAL_MS);
    return () => window.clearInterval(timer);
  }, [idle]);

  const install = useCallback(async (update: Update) => {
    let total = 0;
    let done = 0;
    setState({ kind: "installing", update, progress: null });
    try {
      await update.downloadAndInstall((e) => {
        if (e.event === "Started") total = e.data.contentLength ?? 0;
        else if (e.event === "Progress" && total > 0) {
          done += e.data.chunkLength;
          setState({ kind: "installing", update, progress: done / total });
        }
      });
      // Windows exits during install; macOS and Linux need the restart.
      await relaunch();
    } catch (e) {
      setState({ kind: "failed", update, error: String(e) });
    }
  }, []);

  const dismiss = useCallback((update: Update) => {
    void update.close();
    setState({ kind: "idle" });
  }, []);

  return { state, install, dismiss };
}
