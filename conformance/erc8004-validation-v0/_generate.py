#!/usr/bin/env python3
"""Dev-time generator for the ERC-8004 validation-bridge fixtures.

Everything checkable derives from committed artifacts:
  requestHash / requestURI  -> NIST SHA3-256 over the committed offline envelope
                               file bytes (the evidence a validator is asked to
                               validate). NOT keccak256 — the registry treats
                               bytes32 as opaque; the URI names the function.
  responseHash / responseURI-> NIST SHA3-256 over the committed verifier-verdict
                               JSON (the response IS recomputable evidence: re-run
                               the offline verifier, get the same verdict bytes'
                               meaning — "not a signature to trust but a proof to
                               recompute").
  response (uint8 0..100)   -> the mandate verdict is deterministic, so only the
                               endpoints are used: 100 = ✓ CONSISTENT,
                               0 = ✗ NOT AUTHORIZED. No invented scores.
validatorAddress / agentId are illustrative placeholders (this bridge shows the
join shape; on-chain identity is the adopter's side of the seam).

Run from repo root: python3 conformance/erc8004-validation-v0/_generate.py
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FIX = HERE / "fixtures"

CASES = {
    "authorized": ("envelopes/envelope.payment.json", "verdict.payment.json", 100),
    "postrevoke": ("envelopes/envelope.postrevoke.json", "verdict.postrevoke.json", 0),
}


def sha3_hex(path: Path) -> str:
    return hashlib.sha3_256(path.read_bytes()).hexdigest()


for case, (env_rel, verdict_name, score) in CASES.items():
    env_digest = sha3_hex(ROOT / env_rel)
    verdict_digest = sha3_hex(FIX / verdict_name)
    d = FIX / case
    d.mkdir(parents=True, exist_ok=True)

    request = {
        "validatorAddress": "0x0000000000000000000000000000000000000000",
        "agentId": 1,
        "requestURI": f"elara:envelope/sha3-256:{env_digest}",
        "requestHash": "0x" + env_digest,
        "_evidence_file": env_rel,
        "_note": "validatorAddress/agentId illustrative; requestHash = NIST SHA3-256 over the committed envelope file bytes",
    }
    response = {
        "requestHash": "0x" + env_digest,
        "response": score,
        "responseURI": f"elara:verdict/sha3-256:{verdict_digest}",
        "responseHash": "0x" + verdict_digest,
        "tag": "elara-mandate-bundle-v0",
        "_evidence_file": f"conformance/erc8004-validation-v0/fixtures/{verdict_name}",
        "_note": "response is deterministic-endpoint only: 100 iff the offline verifier returns CONSISTENT, 0 iff NOT AUTHORIZED",
    }
    (d / "validation-request.json").write_text(json.dumps(request, indent=2, sort_keys=True) + "\n")
    (d / "validation-response.json").write_text(json.dumps(response, indent=2, sort_keys=True) + "\n")
    print(f"{case}: request 0x{env_digest[:12]}… response {score} 0x{verdict_digest[:12]}…")
