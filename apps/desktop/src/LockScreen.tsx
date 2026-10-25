import { useEffect, useState, type FormEvent } from "react";
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
    <form className="card narrow" onSubmit={submit}>
      <h1>Protect your connections</h1>
      <p className="muted">
        Choose a PIN to encrypt your saved hosts and passwords on this device. It can't be
        recovered: if you forget it, saved connections have to be deleted.
      </p>
      <label>
        PIN
        <input
          type="password"
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          autoComplete="new-password"
          autoFocus
        />
      </label>
      <label>
        Confirm PIN
        <input
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
        />
      </label>
      {error && <p className="error">{error}</p>}
      <button type="submit" disabled={busy}>
        {busy ? "Creating…" : "Create vault"}
      </button>
    </form>
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
    <form className="card narrow" onSubmit={submit}>
      <h1>Unlock</h1>
      <label>
        PIN
        <input
          type="password"
          value={pin}
          onChange={(e) => setPin(e.target.value)}
          autoComplete="current-password"
          disabled={lockedOut}
          autoFocus
        />
      </label>
      {lockedOut && <p className="error">Too many wrong PINs. Try again in {formatSecs(retryAfter)}.</p>}
      {!lockedOut && error && <p className="error">{error}</p>}
      <button type="submit" disabled={busy || lockedOut || pin.length === 0}>
        {busy ? "Unlocking…" : "Unlock"}
      </button>

      {confirmReset ? (
        <div className="danger-zone">
          <p>This permanently deletes all saved hosts and passwords. Open sessions stay connected.</p>
          <div className="row">
            <button type="button" className="danger" onClick={reset}>
              Delete everything
            </button>
            <button type="button" className="secondary" onClick={() => setConfirmReset(false)}>
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <button type="button" className="link" onClick={() => setConfirmReset(true)}>
          Forgot PIN?
        </button>
      )}
    </form>
  );
}

function formatSecs(s: number) {
  return s >= 60 ? `${Math.ceil(s / 60)} min` : `${s}s`;
}
