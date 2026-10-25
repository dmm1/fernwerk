import { Badge, Button, Spinner } from "@dmm1/daemon-ui";
import { useUpdater } from "./useUpdater";

export function UpdateBanner({ hasSession }: { hasSession: boolean }) {
  const { state, install, dismiss } = useUpdater();
  if (state.kind === "idle") return null;
  const { update } = state;

  if (state.kind === "installing") {
    const percent = state.progress === null ? "" : ` (${Math.round(state.progress * 100)}%)`;
    return (
      <div
        className="flex flex-none items-center gap-3 border-b border-primary/30 bg-background-panel px-4 py-2 font-mono text-xs text-foreground"
        role="status"
      >
        <Spinner size="sm" />
        <span>
          Installing Fernwerk {update.version}
          {percent}…
        </span>
      </div>
    );
  }

  const failed = state.kind === "failed";

  return (
    <div
      className="flex flex-none items-center gap-3 border-b border-primary/30 bg-background-panel px-4 py-2 font-mono text-xs"
      role="status"
    >
      <Badge variant={failed ? "error" : "default"}>{failed ? "Failed" : "Update"}</Badge>
      <span className={failed ? "text-error" : "text-foreground"}>
        {failed
          ? `Updating to ${update.version} failed: ${state.error}`
          : `Fernwerk ${update.version} is available.`}
        {hasSession && <span className="text-foreground-dim"> Restarting closes open sessions.</span>}
      </span>
      <span className="flex-1" />
      <Button size="sm" onClick={() => install(update)}>
        {failed ? "Retry" : "Restart & update"}
      </Button>
      <Button size="sm" variant="ghost" onClick={() => dismiss(update)}>
        Later
      </Button>
    </div>
  );
}
