#!/usr/bin/env python3
"""Check the ERC-8004 validation-entry vector: an ERC-8004 Validation Registry
entry that carries its own recomputable evidence.

ERC-8004's Validation Registry (contracts/ValidationRegistryUpgradeable.sol)
records a validation as `validationRequest(validatorAddress, agentId,
requestURI, bytes32 requestHash)`: `requestURI` points at off-chain data and
`requestHash` is that data's content hash — an OPAQUE bytes32 the registry
stores as a mapping key and never recomputes on-chain. This vector shows the
JOIN: the off-chain data is a post-quantum, revocation-aware Elara mandate
envelope, and its `requestHash` is recomputable by anyone, so the registry
entry does not have to be taken on faith.

This runner uses ONLY the Python standard library and the committed,
self-contained artifacts in examples/ (no secrets, no mint step, no network).
For each case (authorized, postrevoke) it:

  1. recomputes SHA-256 over the committed envelope bytes at requestURI and
     asserts the `0x`-prefixed bytes32 equals both the entry's requestHash and
     the committed expected.json — the entry's evidence recomputes;
  2. asserts the entry's requestURI matches expected;
  3. if a prebuilt `x402-work-receipt` binary is present (target/release or
     target/debug), runs `verify --envelope <requestURI>` and asserts the exit
     code + flag match expected (authorized -> 0/valid, postrevoke ->
     1/post_revocation). If no binary is built, this leg is announced as
     deferred to the second README command (`cargo run ... verify`) and does
     not fail the run — the digest recompute above is the self-contained proof.

Run from the repo root:  python3 conformance/erc-8004-validation-v0/run_erc8004.py
Exit 0 iff every recompute matched (and, when the binary was available, verify
matched too).
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CASES = ("authorized", "postrevoke")


def _bytes32(content: bytes) -> str:
    return "0x" + hashlib.sha256(content).hexdigest()


def _find_binary() -> Path | None:
    for rel in ("target/release/x402-work-receipt", "target/debug/x402-work-receipt"):
        p = ROOT / rel
        if p.is_file():
            return p
    return None


def _parse_field(text: str, field: str) -> str | None:
    # verifier human render: lines like "  flag                : valid"
    for line in text.splitlines():
        if line.strip().startswith(field):
            _, _, rest = line.partition(":")
            return rest.strip()
    return None


def main() -> int:
    expected = json.loads((HERE / "expected.json").read_text())
    binary = _find_binary()
    ok = True

    for case in CASES:
        exp = expected[case]
        entry = json.loads((HERE / f"entry.{case}.json").read_text())
        env = ROOT / exp["requestURI"]

        # (1) requestURI agreement
        uri_ok = entry["requestURI"] == exp["requestURI"]
        print(f"[{'OK' if uri_ok else 'FAIL'}] {case}.requestURI: {entry['requestURI']}")
        ok = ok and uri_ok

        # (2) digest recomputes from the committed envelope bytes
        got = _bytes32(env.read_bytes())
        digest_ok = got == exp["requestHash"] == entry["requestHash"]
        print(f"[{'OK' if digest_ok else 'FAIL'}] {case}.requestHash recomputes: {got}")
        if not digest_ok:
            print(f"       expected {exp['requestHash']}  entry {entry['requestHash']}")
        ok = ok and digest_ok

        # (3) offline verify leg (only if a binary is already built)
        if binary is None:
            print(f"[note] {case}.offline_verify: deferred to `cargo run -p "
                  f"x402-work-receipt -- verify --envelope {exp['requestURI']}` "
                  f"(no prebuilt binary found)")
            continue
        proc = subprocess.run([str(binary), "verify", "--envelope", str(env)],
                              capture_output=True, text=True)
        out = proc.stdout + proc.stderr
        exit_ok = proc.returncode == exp["verify_exit"]
        flag_ok = _parse_field(out, "flag") == exp["flag"]
        auth_ok = _parse_field(out, "authorized") == str(exp["authorized"]).lower()
        leg_ok = exit_ok and flag_ok and auth_ok
        print(f"[{'OK' if leg_ok else 'FAIL'}] {case}.offline_verify: "
              f"exit={proc.returncode} flag={_parse_field(out, 'flag')} "
              f"authorized={_parse_field(out, 'authorized')}")
        ok = ok and leg_ok

    if binary is None:
        print("\n[note] offline-verify legs deferred — build with "
              "`cargo build -p x402-work-receipt` to run them here, or use the "
              "second README command.")
    print(f"\n{'all recomputes matched expected' if ok else 'MISMATCH vs expected'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
