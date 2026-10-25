#!/usr/bin/env node
// Bumps the version, commits, tags `vX.Y.Z` and pushes. The tag push triggers
// .github/workflows/release.yml, which builds installers for every OS.
//
//   pnpm release patch|minor|major

import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const BUMPS = ["patch", "minor", "major"];
const CARGO_TOML = "Cargo.toml";
const PACKAGE_JSONS = ["apps/desktop/package.json", "packages/terminal/package.json"];

const bump = process.argv[2];
if (!BUMPS.includes(bump)) fail(`usage: pnpm release ${BUMPS.join("|")}`);

const git = (...args) => execFileSync("git", args, { encoding: "utf8" }).trim();

if (git("branch", "--show-current") !== "main") fail("release from main");
if (git("status", "--porcelain")) fail("working tree is not clean");
git("fetch", "--quiet", "origin", "main");
if (git("rev-parse", "HEAD") !== git("rev-parse", "origin/main")) {
  fail("main is not in sync with origin/main");
}

// The workspace version is the source of truth: every crate inherits it and
// tauri.conf.json has no version, so Tauri reads it from Cargo too.
const cargo = readFileSync(CARGO_TOML, "utf8");
const match = cargo.match(/^version = "(\d+)\.(\d+)\.(\d+)"$/m);
if (!match) fail(`no version found in ${CARGO_TOML}`);
const current = match.slice(1).map(Number);
const next = nextVersion(current, bump);
const tag = `v${next}`;

if (git("tag", "--list", tag)) fail(`tag ${tag} already exists`);

writeFileSync(CARGO_TOML, cargo.replace(match[0], `version = "${next}"`));
for (const path of PACKAGE_JSONS) {
  const pkg = JSON.parse(readFileSync(path, "utf8"));
  pkg.version = next;
  writeFileSync(path, JSON.stringify(pkg, null, 2) + "\n");
}
execFileSync("cargo", ["update", "--workspace", "--quiet"], { stdio: "inherit" });

git("add", CARGO_TOML, "Cargo.lock", ...PACKAGE_JSONS);
git("commit", "--quiet", "-m", `Release ${tag}`);
git("tag", "-a", tag, "-m", `Release ${tag}`);
git("push", "--atomic", "origin", "main", tag);

console.log(`${current.join(".")} -> ${next}: pushed ${tag}, release build started.`);

function nextVersion([major, minor, patch], kind) {
  if (kind === "major") return `${major + 1}.0.0`;
  if (kind === "minor") return `${major}.${minor + 1}.0`;
  return `${major}.${minor}.${patch + 1}`;
}

function fail(message) {
  console.error(`release: ${message}`);
  process.exit(1);
}
