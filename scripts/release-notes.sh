#!/usr/bin/env bash
# Prints release notes for a tag: every commit since the previous tag, plus
# install and verification instructions. Used by .github/workflows/release.yml.
#
#   scripts/release-notes.sh v0.3.0 [owner/repo]
set -euo pipefail

tag=${1:?usage: release-notes.sh <tag> [owner/repo]}
repo=${2:-dmm1/fernwerk}
prev=$(git describe --tags --abbrev=0 "$tag^" 2>/dev/null || true)

echo "## What's changed"
echo
# The version-bump commit made by scripts/release.mjs isn't worth listing.
git log "${prev:+$prev..}$tag" --no-merges --pretty='- %s (%h)' | grep -v -E '^- Release v[0-9]' || true
echo
if [[ -n $prev ]]; then
  echo "**Full changelog:** https://github.com/$repo/compare/$prev...$tag"
  echo
fi
echo '## Install'
echo
echo 'Download the installer for your OS from the assets below. Already installed?'
echo 'Fernwerk offers the update itself within a few hours.'
echo
echo "The installers aren't code-signed yet. Verify a download with"
echo "\`gh attestation verify <file> --repo $repo\` or against \`SHA256SUMS.txt\`."
