#!/usr/bin/env python3
"""Run the UPSTREAM x402 settlement-receipt checker over the `elara` rail.

The checker file next to this script is a byte-identical copy of
vaaraio/vaara `tests/vectors/x402_settlement_v0/_check_independent.py` at tag
v1.1.1 (commit 719827c, tree c25f5fca, git blob 0669786027). This runner:

  1. refuses to run unless that copy still hashes to the pinned sha256 —
     the verdict logic is upstream's, verifiably unmodified;
  2. imports it and calls its `_rail_verdicts("elara")` — the only thing we
     supply is the rail name (their `main()` hardcodes its two rails; the
     verdict functions are rail-generic by construction);
  3. compares the verdicts against the committed expected.json;
  4. additionally re-resolves the receipt's backLink: the attestationDigest
     must equal sha256 over the committed post-quantum envelope file
     (evidence/envelope.payment.json, the committed copy) — the content-addressed join from the
     classical receipt to the ML-DSA mandate attestation.

The one verdict this cannot outsource to Python is the scope digest itself:
`scope` carries the act's sha3-256 record hash, and the tool that re-derives
it from the signed act is the Rust verifier (second conformance command):

    cargo run -p x402-work-receipt -- action-ref --act envelopes/act.payment.json

Run from the repo root:  python3 conformance/x402-settlement-v0/run_elara.py
Requires: rfc8785, cryptography (same as upstream). Exit 0 iff everything
matches.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CHECKER = HERE / "_check_independent.py"
CHECKER_SHA256 = "c6af0937632b83c8563c7197eddfa40a5838d78a238bcbe00f097061d3c3a07d"
# evidence/ is the COMMITTED copy of the same bytes (verified byte-identical
# at repoint time). envelopes/ is per-run mint output and gitignored, so a
# bare clone lacks it — reported by MarkovianProtocol on erc-8004#77
# (2026-08-03): every vendored leg passed, then the backLink leg died on the
# missing file. The stranger path is the product; point at what ships.
ENVELOPE = ROOT / "evidence" / "envelope.payment.json"


def main() -> int:
    got_sha = hashlib.sha256(CHECKER.read_bytes()).hexdigest()
    if got_sha != CHECKER_SHA256:
        print(f"[FAIL] vendored checker drifted from the upstream pin:\n"
              f"       expected {CHECKER_SHA256}\n"
              f"       got      {got_sha}")
        return 1
    print(f"[OK] checker is upstream's, byte-identical (sha256 {got_sha[:16]}…)")

    spec = importlib.util.spec_from_file_location("upstream_checker", CHECKER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    got = {"elara": mod._rail_verdicts("elara")}
    expected = json.loads((HERE / "expected.json").read_text())

    for step in ("step0", "step1"):
        for k, v in got["elara"][step].items():
            print(f"[{'OK' if v else 'FAIL'}] elara.{step}.{k}: {v}")
    lv = got["elara"]["lifecycle_distinguishes_terminal"]
    print(f"[{'OK' if lv else 'FAIL'}] elara.lifecycle_distinguishes_terminal: {lv}")

    ok = got == expected

    for step in ("step0", "step1"):
        receipt = json.loads(
            (HERE / "elara" / step / "receipt.json").read_text())
        back = receipt["backLink"]["attestationDigest"]
        env_digest = "sha256:" + hashlib.sha256(ENVELOPE.read_bytes()).hexdigest()
        resolved = back == env_digest
        print(f"[{'OK' if resolved else 'FAIL'}] elara.{step}."
              f"backlink_resolves_pq_envelope: {resolved}")
        ok = ok and resolved

    print(f"\n{'all verdicts matched expected' if ok else 'MISMATCH vs expected'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
