#!/usr/bin/env bash
# One-time mint: generate the dedicated demo principal + agent identities and
# issue the mandate. Writes fixtures/ (secret identities are git-ignored; the
# signed public mandate carrier + meta are committed). Prints the mandate_id.
#
# This is the demo's SINGLE AGPL touch — everything after it is permissive.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build -p elara-mint >/dev/null 2>&1 || cargo build -p elara-mint
MID="$(./target/debug/elara-mint provision --out fixtures)"
echo "$MID"
