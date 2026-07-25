#!/usr/bin/env python3
"""ERC-8004 validation-bridge checker — stdlib only, no chain, no trust in us.

For each case (authorized / postrevoke) this recomputes, from committed files
alone, everything the fixtures claim:

  1. requestHash  == "0x" + SHA3-256(committed envelope file)     [NIST SHA3-256]
  2. requestURI   embeds the same digest (content-addressed evidence pointer)
  3. responseHash == "0x" + SHA3-256(committed verdict JSON)
  4. responseURI  embeds the same digest
  5. response score matches the verdict's own content:
        100 <=> verdict.authorized == true  (✓ CONSISTENT)
          0 <=> verdict.authorized == false (✗ NOT AUTHORIZED)

The second, independent command re-derives the verdict itself (Rust, offline):
    cargo run -p x402-work-receipt -- verify --envelope envelopes/envelope.payment.json

Exit 0 iff every check passes. Run from the repo root:
    python3 conformance/erc8004-validation-v0/run_bridge.py
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FIX = HERE / "fixtures"

ok = True


def check(label: str, cond: bool) -> None:
    global ok
    print(f"[{'OK' if cond else 'FAIL'}] {label}")
    ok = ok and cond


for case in ("authorized", "postrevoke"):
    req = json.loads((FIX / case / "validation-request.json").read_text())
    resp = json.loads((FIX / case / "validation-response.json").read_text())

    env_digest = hashlib.sha3_256((ROOT / req["_evidence_file"]).read_bytes()).hexdigest()
    check(f"{case}.requestHash recomputes from envelope", req["requestHash"] == "0x" + env_digest)
    check(f"{case}.requestURI is content-addressed", req["requestURI"].endswith(env_digest))
    check(f"{case}.request/response join on requestHash", resp["requestHash"] == req["requestHash"])

    verdict_path = ROOT / resp["_evidence_file"]
    verdict_digest = hashlib.sha3_256(verdict_path.read_bytes()).hexdigest()
    check(f"{case}.responseHash recomputes from verdict", resp["responseHash"] == "0x" + verdict_digest)
    check(f"{case}.responseURI is content-addressed", resp["responseURI"].endswith(verdict_digest))

    verdict = json.loads(verdict_path.read_text())
    expected = 100 if verdict.get("authorized") is True else 0
    check(f"{case}.response score matches verdict content ({resp['response']}=={expected})",
          resp["response"] == expected)
    check(f"{case}.response within registry bound (<=100)", 0 <= resp["response"] <= 100)

print("\n" + ("all bridge checks passed" if ok else "MISMATCH"))
sys.exit(0 if ok else 1)
