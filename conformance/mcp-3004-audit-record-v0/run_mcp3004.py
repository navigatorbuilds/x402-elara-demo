#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Conformance runner for the SEP-3004 `authority-evidence` extension.

Two halves, deliberately separate:

  vendor/run_reference.ts  the RECORD side — the SEP's own reference verifier,
                           vendored byte-pinned, run over these fixtures.
  this file                the EVIDENCE side — whether what the extension points
                           at actually recomputes.

The split is the argument. SEP-3004 answers "is this history internally intact";
the evidence profile answers "is this record bound to something that happened".
A record can pass every check on the left and still be evidence of nothing,
which is what E4 demonstrates.

Run from repo root: python3 conformance/mcp-3004-audit-record-v0/run_mcp3004.py
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FIX = HERE / "fixtures"
sys.path.insert(0, str(HERE))
from canon import compute_event_hash, canonical_preimage  # noqa: E402

# FIPS 204 ML-DSA-65 parameter sizes, in bytes.
MLDSA65_PK = 1952
MLDSA65_SIG = 3309

CASES = [
    ("authorized", "evidence/envelope.authorized.json", "evidence/act.authorized.json",
     "verdict.authorized.json", "consistent"),
    ("postrevoke", "evidence/envelope.postrevoke.json", "evidence/act.postrevoke.json",
     "verdict.postrevoke.json", "not_authorized"),
]

results = []


def check(cid, ok, detail):
    results.append((cid, ok, detail))


def sha3_hex(path):
    return hashlib.sha3_256(path.read_bytes()).hexdigest()


segment = json.loads((FIX / "segment.json").read_text())
triple = json.loads((FIX / "three-extension-kat.json").read_text())

# ---------------------------------------------------------------------------
# E0 — THE ANCHOR. canon.py is an independent reimplementation of the `gif-audit/2`
# canonical form, written from the SEP's specification text rather than ported from
# the reference TypeScript. Here it recomputes the SEP's own two published
# known-answer digests from their published preimage inputs. If these do not come
# out, this directory's canonicalizer is not the one the SEP describes and every
# other check here is void. (R0 in vendor/run_reference.ts makes the mirror-image
# assertion for the vendored TypeScript; the two together are what "independent
# reproduction" means — same digests, two languages, neither derived from the other.)
# ---------------------------------------------------------------------------
KAT_CORE = {
    "event_id": "99999999-9999-9999-9999-999999999999",
    "occurred_at": "2026-06-06T12:00:00.000Z",
    "principal_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    "event_type": "tool_call",
    "tool_name": "export",
    "outcome": "deferred",
    "previous_hash": None,
}
KAT_CG_BODY = {
    "flagged": False,
    "invoked_by_principal_id": None,
    "purpose_declared": "reconcile June invoices",
    "session_id": "55555555-5555-5555-5555-555555555555",
}
KAT_RS_BODY = {
    "drift_status": "confirmed",
    "evidence_hash": "sha256:b2c547e2c8f17eafc72ef5c2d4d7b6b4d0f7437ab52bae573a9af14ff5e2d9be",
    "policy_id": "example.org/runtime-drift@3",
    "quarantine_decision": "quarantine",
    "severity": "high",
}
KAT_1X = "d494769c1ae442ea88dd190068747abf63c0568a3b856f85791b1a50a99d48b4"
KAT_2X = "f733fed9cc757165f810b778e4baba1f51a45504988e937707aaab4361b2f064"

got_1x = compute_event_hash({**KAT_CORE, "extensions": {"caller-governance": KAT_CG_BODY}})
got_2x = compute_event_hash({**KAT_CORE, "extensions": {"caller-governance": KAT_CG_BODY,
                                                        "runtime-security": KAT_RS_BODY}})
kat_ok = got_1x == KAT_1X and got_2x == KAT_2X
check("E0-published-kat-anchor", kat_ok,
      "independent Python canonicalizer reproduces both published SEP digests "
      f"({KAT_1X[:8]}…, {KAT_2X[:8]}…)" if kat_ok
      else f"KAT MISMATCH: 1x={got_1x} 2x={got_2x}")

# ---------------------------------------------------------------------------
# E1 — the digests the extension carries resolve to the committed artifacts.
# A third party recomputes them with any SHA3-256; nothing is taken on trust.
# ---------------------------------------------------------------------------
bad = []
for (case, env_rel, _act_rel, verdict_name, _v), rec in zip(CASES, segment):
    ae = rec["extensions"]["authority-evidence"]
    env_digest = sha3_hex(ROOT / env_rel)
    verdict_digest = sha3_hex(FIX / verdict_name)
    if ae["evidence_digest"] != f"sha3-256:{env_digest}":
        bad.append(f"{case}: evidence_digest != envelope bytes")
    if ae["evidence_uri"] != f"elara:envelope/sha3-256:{env_digest}":
        bad.append(f"{case}: evidence_uri disagrees with evidence_digest")
    if ae["verdict_digest"] != f"sha3-256:{verdict_digest}":
        bad.append(f"{case}: verdict_digest != verdict bytes")
check("E1-evidence-resolves", not bad,
      "; ".join(bad) or "every evidence_digest/verdict_digest recomputes from committed bytes")

# ---------------------------------------------------------------------------
# E2 — the carried verdict is the offline verifier's own output, not an
# independent assertion by the emitter.
# ---------------------------------------------------------------------------
enum = {"CONSISTENT": "consistent", "NOT AUTHORIZED": "not_authorized"}
bad = []
for (case, _e, _a, verdict_name, expected), rec in zip(CASES, segment):
    v = json.loads((FIX / verdict_name).read_text())
    got = rec["extensions"]["authority-evidence"]["authority_verdict"]
    if enum[v["verdict"]] != got or got != expected:
        bad.append(f"{case}: verdict file says {v['verdict']}, record carries {got}")
check("E2-verdict-is-derived", not bad,
      "; ".join(bad) or "authority_verdict equals the verifier's own verdict in both cases")

# ---------------------------------------------------------------------------
# E3 — cross-binding. The core's `occurred_at` is the RECORDER's clock and is
# not caller-settable (§2.1), so the record core cannot attest when the caller
# actually acted. `act_signed_at` and `principal_id` are checked against the
# signed act and the verdict — the binding the core structurally cannot make.
# ---------------------------------------------------------------------------
bad = []
for (case, _e, act_rel, verdict_name, _v), rec in zip(CASES, segment):
    act = json.loads((ROOT / act_rel).read_text())
    v = json.loads((FIX / verdict_name).read_text())
    ae = rec["extensions"]["authority-evidence"]
    act_ms = round(act["timestamp"] * 1000)
    claimed = ae["act_signed_at"]
    from datetime import datetime, timezone
    claimed_ms = int(datetime.strptime(claimed, "%Y-%m-%dT%H:%M:%S.%fZ")
                     .replace(tzinfo=timezone.utc).timestamp() * 1000)
    if abs(claimed_ms - act_ms) > 1:
        bad.append(f"{case}: act_signed_at {claimed} != signed act time {act_ms}ms")
    if v["act_timestamp_ms"] != claimed_ms:
        bad.append(f"{case}: verifier act time {v['act_timestamp_ms']} != {claimed_ms}")
    if rec["principal_id"] != v["signer"]:
        bad.append(f"{case}: principal_id != verdict signer")
    if rec["event_id"] != act["id"]:
        bad.append(f"{case}: event_id != act id")
check("E3-cross-binding", not bad,
      "; ".join(bad) or "act_signed_at, principal_id and event_id all bind to the signed act")

# ---------------------------------------------------------------------------
# E4 — THE COMPLEMENTARY FAILURE. Mutate one byte of the evidence artifact. The
# audit record is untouched, so the SEP-3004 chain still verifies perfectly —
# and the evidence no longer resolves. Internal integrity and external binding
# are independent properties; this is the direction SEP-3004 alone cannot see.
# ---------------------------------------------------------------------------
rec = segment[0]
env_bytes = bytearray((ROOT / CASES[0][1]).read_bytes())
env_bytes[-2] ^= 0x01  # flip one bit inside the committed envelope
tampered_digest = hashlib.sha3_256(bytes(env_bytes)).hexdigest()
chain_still_ok = compute_event_hash(rec) == rec["event_hash"]
evidence_now_broken = rec["extensions"]["authority-evidence"]["evidence_digest"] != f"sha3-256:{tampered_digest}"
check("E4-chain-blind-to-evidence-tamper", chain_still_ok and evidence_now_broken,
      "record still verifies against its own chain; evidence digest no longer resolves"
      if chain_still_ok and evidence_now_broken else "unexpected: see fixture state")

# ---------------------------------------------------------------------------
# E5 — the declared algorithm is checkable from the artifact itself: ML-DSA-65
# (FIPS 204) has a 1952-byte public key and a 3309-byte signature.
# ---------------------------------------------------------------------------
bad = []
for (case, _e, act_rel, _vn, _v), rec in zip(CASES, segment):
    act = json.loads((ROOT / act_rel).read_text())
    pk, sig = len(act["creator_public_key"]), len(act["signature"])
    alg = rec["extensions"]["authority-evidence"]["signature_alg"]
    if alg != "ML-DSA-65" or pk != MLDSA65_PK or sig != MLDSA65_SIG:
        bad.append(f"{case}: declared {alg} but pk={pk}B sig={sig}B")
check("E5-declared-alg-matches-artifact", not bad,
      "; ".join(bad) or f"pk={MLDSA65_PK}B sig={MLDSA65_SIG}B in both acts — the declared ML-DSA-65 sizes")

# ---------------------------------------------------------------------------
# E6 — the three-extension record's authority-evidence body is byte-identical to
# the chained one, so the composition record adds an extension and nothing else.
# ---------------------------------------------------------------------------
same = triple["extensions"]["authority-evidence"] == segment[0]["extensions"]["authority-evidence"]
check("E6-composition-is-additive", same,
      "three-extension KAT carries the same authority-evidence body verbatim" if same
      else "composition record diverges from the chained record")

# ---------------------------------------------------------------------------
# E7 — re-run the actual offline verifier, if built, and confirm it still
# produces the verdict bytes these digests commit to. Skipped, loudly, when the
# binary is absent: a skipped check is never reported as a pass.
# ---------------------------------------------------------------------------
BIN = ROOT / "target" / "debug" / "x402-work-receipt"
if BIN.exists():
    bad = []
    for case, env_rel, _a, verdict_name, _v in CASES:
        out = subprocess.run([str(BIN), "verify", "--envelope", str(ROOT / env_rel), "--json"],
                             capture_output=True, text=True)
        marker = "--- raw BundleVerdict (verbatim) ---"
        raw = out.stdout.split(marker, 1)[1].lstrip("\n") if marker in out.stdout else ""
        if hashlib.sha3_256(raw.encode()).hexdigest() != sha3_hex(FIX / verdict_name):
            bad.append(f"{case}: re-run verdict bytes differ from the committed verdict")
    check("E7-verifier-reproduces", not bad,
          "; ".join(bad) or "offline verifier re-run reproduces both committed verdicts byte-for-byte")
else:
    check("E7-verifier-reproduces", None,
          f"SKIPPED — build it with `cargo build --bin x402-work-receipt` to check this leg")

# ---------------------------------------------------------------------------
print()
for cid, ok, detail in results:
    glyph = "○" if ok is None else ("✓" if ok else "✗")
    print(f"  {glyph} {cid} — {detail}")

failed = sum(1 for _, ok, _ in results if ok is False)
skipped = sum(1 for _, ok, _ in results if ok is None)
ran = len(results) - skipped
print(f"\n{len(results)} evidence checks — {ran - failed} passed, {failed} failed, {skipped} skipped")
print(f"\nthree-extension known-answer digest: {triple['event_hash']}")
print("reproduce it with stock tools:")
print(f"  printf '%s' '{canonical_preimage(triple)}' | sha256sum")
sys.exit(1 if failed else 0)
