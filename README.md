# Fernwerk

Fernwerk is an open-source SSH desktop client for Windows, macOS and Linux.

- **Shell:** [Tauri 2](https://tauri.app/)
- **SSH engine:** [`russh`](https://github.com/Eugeny/russh) in `crates/ssh-core`
- **Terminal:** [xterm.js](https://xtermjs.org/) with WebGL rendering

## Layout

```bash
apps/
  desktop/          Tauri 2 app: React UI in src/, Rust commands in src-tauri/
crates/
  ssh-core/         SSH sessions, auth, host key verification (russh)
  vault/            PIN-encrypted store for saved hosts and passwords
packages/
  terminal/         xterm.js React component
docker/             OpenSSH test server
docs/               Architecture notes and roadmap
```

The UI calls the Rust side through thin wrappers over Tauri IPC
(`apps/desktop/src/ssh.ts`, `apps/desktop/src/vault.ts`); terminal output streams
back over a Tauri channel:

```bash
   apps/desktop/src (React + xterm.js)
              │
      Tauri IPC + Channel
              │
   apps/desktop/src-tauri
              │
   crates/ssh-core (russh)
              │
         SSH server
```

## Prerequisites

- Node 22+ and pnpm 10
- Rust (stable, edition 2024)
- The [Tauri prerequisites](https://tauri.app/start/prerequisites/) for your OS
- Optional: Docker, for the local OpenSSH test server

## Getting started

```sh
pnpm install

# optional: OpenSSH server on 127.0.0.1:2222, user "dev" / password "dev"
pnpm test:server

pnpm dev:desktop
```

## Building

```sh
pnpm build:desktop   # installers in target/release/bundle/
```

Builds are per-OS: build on Windows for `.msi`/`-setup.exe`, on macOS for
`.dmg`/`.app`, on Linux for `.deb`/`.rpm`/`.AppImage` (or use CI runners for each).
Release builds are unsigned for now, so Windows SmartScreen will warn on install.

The app icon source is `assets/icon.svg`. After changing it, run `pnpm icons` to
regenerate `apps/desktop/src-tauri/icons/`.

## Checks

```sh
cargo test --workspace     # includes end-to-end tests against an in-process SSH server
cargo clippy --workspace
pnpm typecheck
pnpm build
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
