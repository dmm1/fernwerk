// Shows the key a server presents, compared with the one saved for it. Read-only:
// the check never logs in or records anything.
import {
  Badge,
  AlertDialog,
  AlertDialogAction,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Alert,
  AlertDescription,
} from "@dmm1/daemon-ui";
import { FingerprintRows } from "./FingerprintRows";
import type { KeyCheck } from "./vault";

export interface FingerprintState {
  title: string;
  address: string;
  result?: KeyCheck;
  error?: string;
}

const STATUS = {
  known: {
    variant: "success",
    label: "Matches the saved key",
    detail: "The server presents the key saved for this host.",
  },
  unknown: {
    variant: "warning",
    label: "No key saved yet",
    detail: "Connecting will ask you to confirm this key before saving it.",
  },
  changed: {
    variant: "error",
    label: "Key has changed",
    detail:
      "The server presents a different key than the one saved. Only connect if you expect this, for example after a reinstall.",
  },
} as const;

interface Props {
  state: FingerprintState | null;
  onClose: () => void;
}

export function FingerprintDialog({ state, onClose }: Props) {
  const result = state?.result;
  const rows: [string, string][] = !result
    ? []
    : [
        ...(result.recordedFingerprint ? [["Saved", result.recordedFingerprint] as [string, string]] : []),
        ["Presented", result.fingerprint],
        ["Type", result.algorithm],
      ];
  const status = result && STATUS[result.status];

  return (
    <AlertDialog open={state !== null} onOpenChange={(open) => !open && onClose()}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Server fingerprint</AlertDialogTitle>
          <AlertDialogDescription>
            {state && `${state.title} (${state.address})`}
          </AlertDialogDescription>
        </AlertDialogHeader>

        {state?.error && (
          <Alert variant="error">
            <AlertDescription className="text-error">{state.error}</AlertDescription>
          </Alert>
        )}
        {state && !result && !state.error && (
          <p className="text-sm text-foreground-dim">Reading the server's key…</p>
        )}
        {status && (
          <div className="flex flex-col gap-3">
            <Badge variant={status.variant}>{status.label}</Badge>
            <p className="text-sm text-foreground">{status.detail}</p>
            <FingerprintRows rows={rows} />
          </div>
        )}

        <AlertDialogFooter>
          <AlertDialogAction onClick={onClose}>Close</AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
