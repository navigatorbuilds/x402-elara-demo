#!/usr/bin/env bash
# End-to-end THESIS demo (no x402 payment layer yet — that is a later increment).
#
# Proves the claim: a payment act by an autonomous agent can be turned into a
# post-act, post-quantum, OFFLINE-VERIFIABLE receipt that answers a question no
# timestamp or bare signature can — "was this agent AUTHORIZED, by whom, and did
# that authority still hold when it acted?" — using only the permissive verifier.
#
# Flow:
#   1. [AGPL, one-time]  mint principal + agent + mandate
#   2. [AGPL, per-act]   agent signs a payment act referencing the mandate
#   3. [permissive]      assemble the offline envelope
#   4. [permissive]      verify it offline  -> ✓ CONSISTENT (authorized)
#   5. [permissive]      the accountability counter-cases -> ✗ NOT AUTHORIZED
set -euo pipefail
cd "$(dirname "$0")/.."

MINT=./target/debug/elara-mint
RECEIPT=./target/debug/x402-work-receipt
mkdir -p envelopes

echo "== 1. one-time mint (AGPL) =="
MID="$($MINT provision --out fixtures)"
echo "mandate_id: $MID"
echo

echo "== 2. agent signs a payment act (AGPL signer) =="
# A representative x402 payment fact-set (real settlement is wired in a later
# increment; here the fields are illustrative and labelled as such in the README).
PAYLOAD='{"resource":"/premium-report","asset":"USDC","amount":"0.001","network":"base-sepolia","facilitator":"cdp","note":"illustrative payload — real Base Sepolia settlement wired in the x402 increment"}'
ACTION_REF="$($MINT sign-act --agent fixtures/agent.identity.json --mandate-ref "$MID" --payload-json "$PAYLOAD" --out envelopes/act.authorized.json)"
echo "action_ref (32-byte x402-STARK-compatible handle): $ACTION_REF"
echo

echo "== 2b. permissive verifier RE-DERIVES the same action_ref (only elara-record) =="
RE_DERIVED="$($RECEIPT action-ref --act envelopes/act.authorized.json)"
echo "re-derived: $RE_DERIVED"
[ "$ACTION_REF" = "$RE_DERIVED" ] || { echo "FAIL: action_ref mismatch"; exit 1; }
echo "match ✓  (the mint's signer and the offline verifier agree on the 32-byte handle)"
echo

echo "== 3+4. assemble + verify the AUTHORIZED envelope (permissive, offline) =="
$RECEIPT assemble --act envelopes/act.authorized.json --mandate fixtures/mandate.carrier.json --out envelopes/envelope.authorized.json
$RECEIPT verify --envelope envelopes/envelope.authorized.json
echo

echo "== 5. accountability counter-case: principal REVOKES, agent acts AFTER =="
$MINT revoke --principal fixtures/principal.identity.json --mandate-ref "$MID" --reason "agent key rotation" --out envelopes/revocation.json >/dev/null
$MINT sign-act --agent fixtures/agent.identity.json --mandate-ref "$MID" --payload-json "$PAYLOAD" --out envelopes/act.postrevoke.json >/dev/null
$RECEIPT assemble --act envelopes/act.postrevoke.json --mandate fixtures/mandate.carrier.json --revocation envelopes/revocation.json --out envelopes/envelope.postrevoke.json
# This MUST be NOT AUTHORIZED (post_revocation): verify exits non-zero, which is
# the CORRECT outcome here, so invert it.
if $RECEIPT verify --envelope envelopes/envelope.postrevoke.json; then
  echo "FAIL: post-revocation act verified as authorized — that is a soundness bug"
  exit 1
else
  echo
  echo "(non-zero exit above is EXPECTED — the post-revocation act is correctly NOT AUTHORIZED)"
fi

echo
echo "== thesis demo complete: authorized -> ✓ CONSISTENT ; post-revocation -> ✗ NOT AUTHORIZED =="
