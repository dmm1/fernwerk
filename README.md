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
`.dmg`/`.app`, on Linux for `.deb`/`.rpm`/`.AppImage`. Release builds aren't
code-signed yet (macOS builds are only ad-hoc signed), so Windows SmartScreen and
macOS Gatekeeper will warn on install.

The app icon source is `assets/icon.svg`. After changing it, run `pnpm icons` to
regenerate `apps/desktop/src-tauri/icons/`.

## Releasing

```sh
pnpm release patch   # or minor / major
```

This bumps the version (workspace `Cargo.toml`, the `package.json` files and
`Cargo.lock`), commits `Release vX.Y.Z`, tags it and pushes to `origin/main`. It
refuses to run off `main`, with uncommitted changes, or when `main` isn't in sync
with `origin/main`.

The tag push starts [`.github/workflows/release.yml`](.github/workflows/release.yml),
which builds on GitHub runners for Windows (`.msi`, `-setup.exe`), macOS (`.dmg` for
Apple Silicon and Intel) and Linux (`.deb`, `.rpm`, `.AppImage`), and attaches the
installers to a **draft** GitHub release. Each installer gets a build provenance
attestation, and a final job adds `SHA256SUMS.txt`. Check the assets, then publish
the draft.

## Installing a release

Until the installers are code-signed, verify what you downloaded:

```sh
gh attestation verify Fernwerk_0.1.1_x64-setup.exe --repo dmm1/fernwerk
# or compare against SHA256SUMS.txt from the same release
```

- **Windows:** SmartScreen shows "Windows protected your PC". Click
  **More info → Run anyway**.
- **macOS:** the first launch is blocked. Open **System Settings → Privacy & Security**
  and click **Open Anyway** next to Fernwerk (or run `xattr -dr com.apple.quarantine
  /Applications/Fernwerk.app`).
- **Linux:** no extra steps.

## Checks

```sh
cargo test --workspace     # includes end-to-end tests against an in-process SSH server
cargo clippy --workspace
pnpm typecheck
pnpm build
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
