# Roadmap

## Now (scaffold)

- [x] `ssh-core`: password auth, PTY shell, resize, keepalive
- [x] Host key TOFU with an app-owned `known_hosts`; changed keys are refused
- [x] Desktop: Tauri commands + IPC channel streaming
- [x] End-to-end tests against an in-process SSH server
- [x] PIN-locked vault: Argon2id(PIN + OS-keyring device secret) -> XChaCha20-Poly1305,
      throttled unlock, idle auto-lock, passwords never sent to the UI

## Security (before any public release)

- [ ] Interactive host key prompt (show fingerprint, accept/reject) instead of silent TOFU
- [ ] Public key auth: ed25519/RSA/ECDSA, encrypted keys, `.ppk` import
- [ ] SSH agent: OpenSSH agent, Pageant, 1Password/Bitwarden agents; agent forwarding
- [ ] Keyboard-interactive (2FA/OTP)
- [ ] Change-PIN UI, configurable auto-lock, Windows Hello / Touch ID unlock
- [ ] Zeroize passwords inside ssh-core after auth

## Core features

- [ ] `crates/store`: SQLite (hosts, groups, snippets, settings) with migrations
- [ ] Import `~/.ssh/config` (Host, HostName, User, Port, IdentityFile, ProxyJump)
- [ ] Jump hosts / ProxyJump
- [ ] Port forwarding: local, remote, dynamic (SOCKS)
- [ ] SFTP browser (`russh-sftp`)
- [ ] Tabs, split panes, auto-reconnect, session logging, themes, search
- [ ] Generated TS bindings from Rust (`specta` / `tauri-specta`) instead of hand-written types
- [ ] Raw-byte IPC on desktop instead of JSON number arrays

## Product

- [ ] End-to-end encrypted sync between devices
- [ ] Auto-update (Tauri updater), code signing (Windows Trusted Signing, Apple notarization)
- [ ] Crash reporting and opt-in telemetry
