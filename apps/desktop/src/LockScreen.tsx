import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import {
  Alert,
  AlertDescription,
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Input,
  Label,
  Spinner,
} from "@dmm1/daemon-ui";
import { MIN_PIN_LENGTH, vault, type VaultStatus } from "./vault";

interface Props {
  status: VaultStatus;
  onChange: () => void;
}

export function LockScreen({ status, onChange }: Props) {
  return status.state === "uninitialized" ? (
    <SetupPin onDone={onChange} />
  ) : (
    <UnlockPin initialRetryAfter={status.retryAfterSecs} onDone={onChange} />
  );
}

interface PinCardProps {
  title: string;
  description: string;
  children: ReactNode;
}

function PinCard({ title, description, children }: PinCardProps) {
  return (
    <div className="mx-auto mt-[12vh] w-[calc(100%-2rem)] max-w-sm">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm text-foreground-bright">{title}</CardTitle>
          <CardDescription>{description}</CardDescription>
        </CardHeader>
        <CardContent>{children}</CardContent>
      </Card>
    </div>
  );
}

function SetupPin({ onDone }: { onDone: () => void }) {
  const [pin, setPin] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (pin.length < MIN_PIN_LENGTH) return setError(`Use at least ${MIN_PIN_LENGTH} characters.`);
    if (pin !== confirm) return setError("The PINs don't match.");
    setBusy(true);
    try {
      await vault.setup(pin);
      onDone();
    } catch (err) {
      setError(String(err));
      setBusy(false);
    }
  }

  return (
    <PinCard
      title="Protect your connections"
      description="Choose a PIN to encrypt your saved hosts and passwords on this device. It can't be recovered: if you forget it, saved connections have to be deleted."
    >
      <form className="flex flex-col gap-4" onSubmit={submit}>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="setup-pin">PIN</Label>
          <Input
            id="setup-pin"
            type="password"
            value={pin}
            onChange={(e) => setPin(e.target.value)}
            autoComplete="new-password"
            autoFocus
          />
        </div>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="setup-confirm">Confirm PIN</Label>
          <Input
            id="setup-confirm"
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
          />
        </div>
        {error && (
          <Alert variant="error">
            <AlertDescription className="text-error">{error}</AlertDescription>
          </Alert>
        )}
        <Button type="submit" disabled={busy}>
          {busy ? (
            <>
              <Spinner size="sm" className="mr-2" /> Creating…
            </>
          ) : (
            "Create vault"
          )}
        </Button>
      </form>
    </PinCard>
  );
}

interface UnlockProps {
  initialRetryAfter: number | null;
  onDone: () => void;
}

function UnlockPin({ initialRetryAfter, onDone }: UnlockProps) {
  const [pin, setPin] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [retryAfter, setRetryAfter] = useState(initialRetryAfter ?? 0);
  const [confirmReset, setConfirmReset] = useState(false);

  useEffect(() => {
    if (retryAfter <= 0) return;
    const t = window.setTimeout(() => setRetryAfter((s) => s - 1), 1000);
    return () => window.clearTimeout(t);
  }, [retryAfter]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const result = await vault.unlock(pin);
      if (result.status === "ok") return onDone();
      setPin("");
      if (result.status === "lockedOut") {
        setRetryAfter(result.retryAfterSecs);
      } else {
        setError(
          result.attemptsLeft > 0
            ? `Wrong PIN. ${result.attemptsLeft} attempt${result.attemptsLeft === 1 ? "" : "s"} left before a lockout.`
            : "Wrong PIN.",
        );
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function reset() {
    await vault.reset();
    onDone();
  }

  const lockedOut = retryAfter > 0;

  return (
    <PinCard title="Unlock" description="Enter your PIN to decrypt your saved connections.">
      <form className="flex flex-col gap-4" onSubmit={submit}>
        <div className="flex flex-col gap-1.5">
          <Label htmlFor="unlock-pin">PIN</Label>
          <Input
            id="unlock-pin"
            type="password"
            value={pin}
            onChange={(e) => setPin(e.target.value)}
            autoComplete="current-password"
            disabled={lockedOut}
            autoFocus
          />
        </div>
        {lockedOut && (
          <Alert variant="warning">
            <AlertDescription className="text-warning">Too many wrong PINs. Try again in {formatSecs(retryAfter)}.</AlertDescription>
          </Alert>
        )}
        {!lockedOut && error && (
          <Alert variant="error">
            <AlertDescription className="text-error">{error}</AlertDescription>
          </Alert>
        )}
        <Button type="submit" disabled={busy || lockedOut || pin.length === 0}>
          {busy ? (
            <>
              <Spinner size="sm" className="mr-2" /> Unlocking…
            </>
          ) : (
            "Unlock"
          )}
        </Button>
        <Button
          type="button"
          variant="link"
          size="sm"
          className="self-start px-0"
          onClick={() => setConfirmReset(true)}
        >
          Forgot PIN?
        </Button>
      </form>

      <AlertDialog open={confirmReset} onOpenChange={setConfirmReset}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete vault?</AlertDialogTitle>
            <AlertDialogDescription>
              This permanently deletes all saved hosts and passwords. Open sessions stay connected.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={reset}>Delete everything</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </PinCard>
  );
}

function formatSecs(s: number) {
  return s >= 60 ? `${Math.ceil(s / 60)} min` : `${s}s`;
}
