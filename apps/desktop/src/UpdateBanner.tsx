import { useUpdater } from "./useUpdater";

export function UpdateBanner({ hasSession }: { hasSession: boolean }) {
  const { state, install, dismiss } = useUpdater();
  if (state.kind === "idle") return null;
  const { update } = state;

  if (state.kind === "installing") {
    const percent = state.progress === null ? "" : ` (${Math.round(state.progress * 100)}%)`;
    return (
      <div className="update-banner" role="status">
        Installing Fernwerk {update.version}
        {percent}…
      </div>
    );
  }

  return (
    <div className="update-banner" role="status">
      <span className={state.kind === "failed" ? "error" : undefined}>
        {state.kind === "failed"
          ? `Updating to ${update.version} failed: ${state.error}`
          : `Fernwerk ${update.version} is available.`}
        {hasSession && <span className="muted"> Restarting closes open sessions.</span>}
      </span>
      <span className="spacer" />
      <button onClick={() => install(update)}>
        {state.kind === "failed" ? "Retry" : "Restart & update"}
      </button>
      <button className="secondary" onClick={() => dismiss(update)}>
        Later
      </button>
    </div>
  );
}
