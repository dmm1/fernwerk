import { useCallback, useEffect, useState, type FormEvent } from "react";
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
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
  Checkbox,
  Empty,
  H3,
  Input,
  Label,
} from "@dmm1/daemon-ui";
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
  const [pendingDelete, setPendingDelete] = useState<HostSummary | null>(null);

  const reload = useCallback(() => {
    vault.listHosts().then(setHosts, (e) => setError(String(e)));
  }, []);
  useEffect(reload, [reload]);

  function connect(host: HostSummary) {
    if (!host.hasPassword) return setMode({ kind: "password", host });
    onConnect({ title: titleOf(host), target: { type: "saved", hostId: host.id } });
  }

  async function remove(host: HostSummary) {
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
    <div className="mx-auto w-full max-w-3xl px-4 py-8">
      <header className="mb-5 flex items-center gap-2">
        <H3 className="mr-auto text-xl">Connections</H3>
        <Button onClick={() => setMode({ kind: "edit", host: null })}>New host</Button>
        <Button variant="outline" onClick={onLock} title="Lock">
          Lock
        </Button>
      </header>
      {error && (
        <Alert variant="error" className="mb-4">
          <AlertDescription className="text-error">{error}</AlertDescription>
        </Alert>
      )}
      {hosts.length === 0 ? (
        <Empty
          icon={<span className="font-mono text-2xl text-primary">&gt;_</span>}
          title="No saved hosts"
          description="Add an SSH connection to get started."
          action={<Button onClick={() => setMode({ kind: "edit", host: null })}>Add host</Button>}
        />
      ) : (
        <ul className="flex flex-col gap-2">
          {hosts.map((h) => (
            <li key={h.id} onDoubleClick={() => connect(h)}>
              <Card className="flex-row flex-wrap items-center gap-3 px-4 py-3 transition-colors hover:border-border-strong">
                <div className="min-w-0 flex-1 basis-full sm:basis-auto">
                  <div className="truncate text-sm text-foreground-bright">{titleOf(h)}</div>
                  <div className="mt-0.5 truncate font-mono text-[11px] text-foreground-dim">
                    {h.username}@{h.host}:{h.port}
                  </div>
                </div>
                <div className="ml-auto flex items-center gap-2">
                  {!h.hasPassword && <Badge variant="warning">Asks for password</Badge>}
                  <Button size="sm" onClick={() => connect(h)}>
                    Connect
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => setMode({ kind: "edit", host: h })}>
                    Edit
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="text-error hover:bg-error/10 hover:text-error"
                    onClick={() => setPendingDelete(h)}
                  >
                    Delete
                  </Button>
                </div>
              </Card>
            </li>
          ))}
        </ul>
      )}

      <AlertDialog
        open={pendingDelete !== null}
        onOpenChange={(open) => {
          if (!open) setPendingDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete host?</AlertDialogTitle>
            <AlertDialogDescription>
              {pendingDelete
                ? `"${titleOf(pendingDelete)}" will be removed from your vault.`
                : "This host will be removed from your vault."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={() => pendingDelete && void remove(pendingDelete)}>
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
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
    <div className="mx-auto mt-[10vh] w-[calc(100%-2rem)] max-w-md">
      <form onSubmit={submit}>
        <Card>
          <CardHeader>
            <CardTitle className="text-sm text-foreground-bright">
              {host ? "Edit host" : "New host"}
            </CardTitle>
            <CardDescription>Saved hosts are encrypted with your vault PIN.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="host-name">
                Name <span className="font-normal tracking-normal normal-case">(optional)</span>
              </Label>
              <Input
                id="host-name"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="e.g. Production web"
              />
            </div>
            <div className="flex gap-3">
              <div className="flex flex-1 flex-col gap-1.5">
                <Label htmlFor="host-address">Host</Label>
                <Input
                  id="host-address"
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  required
                  autoFocus
                />
              </div>
              <div className="flex w-24 flex-col gap-1.5">
                <Label htmlFor="host-port">Port</Label>
                <Input
                  id="host-port"
                  value={port}
                  onChange={(e) => setPort(e.target.value)}
                  inputMode="numeric"
                />
              </div>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="host-username">Username</Label>
              <Input
                id="host-username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                required
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="host-password">Password</Label>
              <Input
                id="host-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={host?.hasPassword ? "Saved (leave empty to keep)" : ""}
                autoComplete="new-password"
                disabled={!remember}
              />
            </div>
            <div className="flex items-center gap-2.5">
              <Checkbox
                id="host-remember"
                checked={remember}
                onCheckedChange={setRemember}
              />
              <Label
                htmlFor="host-remember"
                className="text-xs font-normal tracking-normal normal-case text-foreground"
              >
                Remember password (encrypted in your vault)
              </Label>
            </div>
            {error && (
              <Alert variant="error">
                <AlertDescription className="text-error">{error}</AlertDescription>
              </Alert>
            )}
          </CardContent>
          <CardFooter className="flex-wrap gap-2">
            <Button type="submit" onClick={() => setConnectAfter(true)}>
              Save &amp; connect
            </Button>
            <Button type="submit" variant="outline" onClick={() => setConnectAfter(false)}>
              Save
            </Button>
            <Button type="button" variant="link" size="sm" className="ml-auto" onClick={onCancel}>
              Cancel
            </Button>
          </CardFooter>
        </Card>
      </form>
    </div>
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
    <div className="mx-auto mt-[12vh] w-[calc(100%-2rem)] max-w-sm">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit(password);
        }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="text-sm text-foreground-bright">{titleOf(host)}</CardTitle>
            <CardDescription className="font-mono">
              {host.username}@{host.host}:{host.port}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="connect-password">Password</Label>
              <Input
                id="connect-password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                autoFocus
              />
            </div>
          </CardContent>
          <CardFooter className="gap-2">
            <Button type="submit">Connect</Button>
            <Button type="button" variant="link" size="sm" className="ml-auto" onClick={onCancel}>
              Cancel
            </Button>
          </CardFooter>
        </Card>
      </form>
    </div>
  );
}
