import { useCallback, useEffect, useState, type FormEvent } from "react";
import type { ActiveSession } from "./SessionView";
import { vault, type HostInput, type HostSummary, type PasswordChange } from "./vault";

interface Props {
  onConnect: (session: ActiveSession) => void;
  onLock: () => void;
}

type Mode =
  | { kind: "list" }
  | { kind: "edit"; host: HostSummary | null }
  | { kind: "password"; host: HostSummary };

export function HostManager({ onConnect, onLock }: Props) {
  const [hosts, setHosts] = useState<HostSummary[]>([]);
  const [mode, setMode] = useState<Mode>({ kind: "list" });
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(() => {
    vault.listHosts().then(setHosts, (e) => setError(String(e)));
  }, []);
  useEffect(reload, [reload]);

  function connect(host: HostSummary) {
    if (!host.hasPassword) return setMode({ kind: "password", host });
    onConnect({ title: titleOf(host), target: { type: "saved", hostId: host.id } });
  }

  async function remove(host: HostSummary) {
    if (!window.confirm(`Delete "${titleOf(host)}"?`)) return;
    await vault.deleteHost(host.id).catch((e) => setError(String(e)));
    reload();
  }

  if (mode.kind === "edit") {
    return (
      <HostForm
        host={mode.host}
        onCancel={() => setMode({ kind: "list" })}
        onSave={async (input, connectAfter) => {
          const saved = await vault.saveHost(input);
          reload();
          setMode({ kind: "list" });
          if (connectAfter) connect(saved);
        }}
      />
    );
  }

  if (mode.kind === "password") {
    const { host } = mode;
    return (
      <PasswordPrompt
        host={host}
        onCancel={() => setMode({ kind: "list" })}
        onSubmit={(password) =>
          onConnect({
            title: titleOf(host),
            target: {
              type: "direct",
              host: host.host,
              port: host.port,
              username: host.username,
              auth: { type: "password", password },
            },
          })
        }
      />
    );
  }

  return (
    <div className="manager">
      <header className="manager-bar">
        <h1>Connections</h1>
        <button onClick={() => setMode({ kind: "edit", host: null })}>New host</button>
        <button className="secondary" onClick={onLock} title="Lock">
          Lock
        </button>
      </header>
      {error && <p className="error">{error}</p>}
      {hosts.length === 0 ? (
        <div className="empty">
          <p>No saved hosts yet.</p>
          <button onClick={() => setMode({ kind: "edit", host: null })}>Add your first host</button>
        </div>
      ) : (
        <ul className="host-list">
          {hosts.map((h) => (
            <li key={h.id} className="host" onDoubleClick={() => connect(h)}>
              <div className="host-info">
                <span className="host-label">{titleOf(h)}</span>
                <span className="muted mono">
                  {h.username}@{h.host}:{h.port}
                  {h.hasPassword ? "" : " · asks for password"}
                </span>
              </div>
              <button onClick={() => connect(h)}>Connect</button>
              <button className="secondary" onClick={() => setMode({ kind: "edit", host: h })}>
                Edit
              </button>
              <button className="secondary" onClick={() => remove(h)}>
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function titleOf(h: HostSummary) {
  return h.label || `${h.username}@${h.host}`;
}

interface HostFormProps {
  host: HostSummary | null;
  onCancel: () => void;
  onSave: (input: HostInput, connectAfter: boolean) => Promise<void>;
}

function HostForm({ host, onCancel, onSave }: HostFormProps) {
  const [label, setLabel] = useState(host?.label ?? "");
  const [hostname, setHostname] = useState(host?.host ?? "");
  const [port, setPort] = useState(String(host?.port ?? 22));
  const [username, setUsername] = useState(host?.username ?? "");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(host ? host.hasPassword : true);
  const [error, setError] = useState<string | null>(null);
  const [connectAfter, setConnectAfter] = useState(false);

  function passwordChange(): PasswordChange {
    if (!remember) return { type: "clear" };
    if (password) return { type: "set", value: password };
    return host?.hasPassword ? { type: "keep" } : { type: "clear" };
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      await onSave(
        {
          id: host?.id ?? null,
          label: label.trim(),
          host: hostname.trim(),
          port: Number(port) || 22,
          username: username.trim(),
          password: passwordChange(),
        },
        connectAfter,
      );
    } catch (err) {
      setError(String(err));
    }
  }

  return (
    <form className="card narrow" onSubmit={submit}>
      <h1>{host ? "Edit host" : "New host"}</h1>
      <label>
        Name <span className="muted">(optional)</span>
        <input value={label} onChange={(e) => setLabel(e.target.value)} placeholder="e.g. Production web" />
      </label>
      <div className="row">
        <label className="grow">
          Host
          <input value={hostname} onChange={(e) => setHostname(e.target.value)} required autoFocus />
        </label>
        <label className="port">
          Port
          <input value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" />
        </label>
      </div>
      <label>
        Username
        <input value={username} onChange={(e) => setUsername(e.target.value)} required />
      </label>
      <label>
        Password
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder={host?.hasPassword ? "Saved (leave empty to keep)" : ""}
          autoComplete="new-password"
          disabled={!remember}
        />
      </label>
      <label className="check">
        <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
        Remember password (encrypted in your vault)
      </label>
      {error && <p className="error">{error}</p>}
      <div className="row">
        <button type="submit" onClick={() => setConnectAfter(true)}>
          Save &amp; connect
        </button>
        <button type="submit" className="secondary" onClick={() => setConnectAfter(false)}>
          Save
        </button>
        <button type="button" className="link" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}

interface PasswordPromptProps {
  host: HostSummary;
  onCancel: () => void;
  onSubmit: (password: string) => void;
}

function PasswordPrompt({ host, onCancel, onSubmit }: PasswordPromptProps) {
  const [password, setPassword] = useState("");
  return (
    <form
      className="card narrow"
      onSubmit={(e) => {
        e.preventDefault();
        onSubmit(password);
      }}
    >
      <h1>{titleOf(host)}</h1>
      <p className="muted mono">
        {host.username}@{host.host}:{host.port}
      </p>
      <label>
        Password
        <input
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="current-password"
          autoFocus
        />
      </label>
      <div className="row">
        <button type="submit">Connect</button>
        <button type="button" className="link" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  );
}
