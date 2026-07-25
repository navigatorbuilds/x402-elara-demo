#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Dev-time generator for the SEP-3004 `authority-evidence` extension fixtures.

Every checkable value derives from an artifact committed in this repo — nothing
here is hand-typed:

  evidence_digest  -> NIST SHA3-256 over the committed offline envelope bytes
                      (the evidence a third party is asked to recompute).
  verdict_digest   -> NIST SHA3-256 over the committed verifier-verdict bytes.
                      The verdict is the OUTPUT of a deterministic offline
                      verifier, so this digest commits to a recomputable result,
                      not to an opinion.
  authority_verdict-> read from that verdict file's own `verdict` field, lowered
                      to the extension's enum. Never asserted independently.
  event_id         -> the act record's own UUIDv7.
  act_signed_at    -> the act record's own signed timestamp.
  principal_id     -> the agent identity the verdict reports as signer.
  tool_name        -> the resource named in the act's signed payload.
  event_hash       -> computed by canon.py, the independent reproduction of the
                      SEP's canonical form.

The two chained records are the SAME agent under the SAME mandate performing the
SAME act payload 166 ms apart, straddling a revocation. That is what makes the
pair load-bearing: every core field a SEP-3004 record protects is identical
except the event_id, the timestamp and the chain link, both records verify, and
only the evidence tells them apart.

Run from repo root: python3 conformance/mcp-3004-audit-record-v0/_generate.py
"""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))
from canon import compute_event_hash  # noqa: E402

FIX = HERE / "fixtures"

# The registered profile identifier this extension commits to. Versioned, so a
# later profile with different soundness cannot masquerade as this one.
EVIDENCE_PROFILE = "elara/mandate-bundle@v0"

# The two cases, in chain order.
CASES = [
    ("authorized", "evidence/envelope.authorized.json", "verdict.authorized.json",
     "evidence/act.authorized.json"),
    ("postrevoke", "evidence/envelope.postrevoke.json", "verdict.postrevoke.json",
     "evidence/act.postrevoke.json"),
]

VERDICT_ENUM = {
    "CONSISTENT": "consistent",
    "NOT AUTHORIZED": "not_authorized",
}


def sha3_hex(path: Path) -> str:
    return hashlib.sha3_256(path.read_bytes()).hexdigest()


def rfc3339_ms(epoch_seconds: float) -> str:
    dt = datetime.fromtimestamp(epoch_seconds, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def build_record(case, env_rel, verdict_name, act_rel, previous_hash):
    env_digest = sha3_hex(ROOT / env_rel)
    verdict_path = FIX / verdict_name
    verdict_digest = sha3_hex(verdict_path)
    verdict = json.loads(verdict_path.read_text())
    act = json.loads((ROOT / act_rel).read_text())

    resource = act["metadata"]["x402_payment"]["resource"]
    signed_at = rfc3339_ms(act["timestamp"])

    record = {
        "event_id": act["id"],
        # Recorder clock per §2.1. In these fixtures it is pinned to the act's
        # observed time so the vectors are byte-deterministic; a live emitter
        # writes its own host clock here. The CALLER-side signed time is not
        # representable in the core at all — it lives in the evidence, which is
        # exactly why `act_signed_at` is carried (and chained) in the extension.
        "occurred_at": signed_at,
        "principal_id": verdict["signer"],
        "event_type": "tool_call",
        "tool_name": resource,
        # Both records say `allowed`: the host DID dispatch both calls. The
        # audit core is a truthful record of the host's disposition, and it is
        # unchanged by the revocation. That is the point.
        "outcome": "allowed",
        "previous_hash": previous_hash,
        "extensions": {
            "caller-governance": {
                "flagged": False,
                "purpose_declared": f"settle x402 payment for {resource}",
            },
            "authority-evidence": {
                "evidence_profile": EVIDENCE_PROFILE,
                "evidence_digest": f"sha3-256:{env_digest}",
                "evidence_uri": f"elara:envelope/sha3-256:{env_digest}",
                "authority_verdict": VERDICT_ENUM[verdict["verdict"]],
                "verdict_digest": f"sha3-256:{verdict_digest}",
                "act_signed_at": signed_at,
                "signature_alg": "ML-DSA-65",
            },
        },
    }
    record["event_hash"] = compute_event_hash(record)
    return record


def main():
    previous_hash = None
    segment = []
    for case, env_rel, verdict_name, act_rel in CASES:
        rec = build_record(case, env_rel, verdict_name, act_rel, previous_hash)
        previous_hash = rec["event_hash"]
        segment.append(rec)
        print(f"{case}: {rec['extensions']['authority-evidence']['authority_verdict']:<14} "
              f"event_hash {rec['event_hash'][:12]}…")

    (FIX / "segment.json").write_text(json.dumps(segment, indent=2) + "\n")

    # The three-extension composition record: caller-governance (the SEP's worked
    # extension) + runtime-security (registered from its implementer's normative
    # text) + authority-evidence, side by side under ONE digest. Its
    # caller-governance and runtime-security bodies are byte-identical to the
    # SEP's own two-extension known-answer fixture, so the ONLY delta against the
    # published digest f733fed9… is this extension — which is what makes it a
    # clean test of the registration mechanism rather than of our own record
    # shape. The runtime-security values are the SEP's, reproduced verbatim.
    ae = segment[0]["extensions"]["authority-evidence"]
    triple = {
        "event_id": "99999999-9999-9999-9999-999999999999",
        "occurred_at": "2026-06-06T12:00:00.000Z",
        "principal_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "event_type": "tool_call",
        "tool_name": "export",
        "outcome": "deferred",
        "previous_hash": None,
        "extensions": {
            "caller-governance": {
                "flagged": False,
                "invoked_by_principal_id": None,
                "purpose_declared": "reconcile June invoices",
                "session_id": "55555555-5555-5555-5555-555555555555",
            },
            "runtime-security": {
                "drift_status": "confirmed",
                "evidence_hash": "sha256:b2c547e2c8f17eafc72ef5c2d4d7b6b4d0f7437ab52bae573a9af14ff5e2d9be",
                "policy_id": "example.org/runtime-drift@3",
                "quarantine_decision": "quarantine",
                "severity": "high",
            },
            "authority-evidence": ae,
        },
    }
    triple["event_hash"] = compute_event_hash(triple)
    (FIX / "three-extension-kat.json").write_text(json.dumps(triple, indent=2) + "\n")
    print(f"three-extension KAT: {triple['event_hash']}")


if __name__ == "__main__":
    main()
