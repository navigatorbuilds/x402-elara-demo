#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Dev-time generator for the A2A #2028 `actorChain` + `proof_ref` vectors.

The chain shape is the one proposed in the issue body — `actorChain.origin` plus
an ordered `actorChain.actors[]`, each hop carrying the scopes it held — with the
refinements the thread converged on:

  (iss, sub) per hop      keying on a bare subject collides across issuers.
  proof_ref               an OPAQUE, content-addressed reference. Not a
                          capability URL: no host, no path, no bearer secret.
                          Dereference is authorized separately, and because the
                          reference IS the digest, a resolver cannot lie about
                          what it returned — you hash the bytes you got and
                          compare. A wrong or hostile resolver is detected, not
                          trusted.

Everything a vector asserts derives from bytes committed in this repo. The two
principal chains are IDENTICAL in every field a well-formedness checker can see,
including the full scope sets at every hop; they differ only in which committed
envelope the terminal hop's proof_ref resolves to. That is the point.

Run from repo root: python3 conformance/a2a-2028-actor-chain-v0/_generate.py
"""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FIX = HERE / "fixtures"
MCP_FIX = ROOT / "conformance" / "mcp-3004-audit-record-v0" / "fixtures"

# The issuer of our mandates. A real deployment uses its own; the point of the
# (iss, sub) pair is that `agent:settler` under a different issuer is a different
# actor, and keying on `sub` alone would silently merge them.
ISS = "elara:testnet"

# Scope vocabulary. Hop scopes MUST narrow monotonically down the chain — that is
# the thread's well-formedness invariant, and it is checked from the payload alone.
ORIGIN_SCOPES = ["repo:read", "ci:trigger", "pay:x402"]
HOP1_SCOPES = ["repo:read", "pay:x402"]
HOP2_SCOPES = ["pay:x402"]


def sha3_hex(path: Path) -> str:
    return hashlib.sha3_256(path.read_bytes()).hexdigest()


def proof_ref(envelope_rel: str) -> str:
    """Content-addressed, opaque. The reference is the digest."""
    return f"elara:envelope/sha3-256:{sha3_hex(ROOT / envelope_rel)}"


def chain(terminal_proof_ref, *, hop2_scopes=None, origin_scopes=None):
    """The canonical two-hop chain.

    Hop 1 is a coordinator whose grant is genuinely outside this bundle — it
    carries NO proof_ref. Per the thread's normative rule, that absence means
    "no reconciliation aid was supplied", NOT "no grant occurred". Modelling it
    honestly is the realistic case: chains will be partially evidenced for a
    long time, and a verifier has to say `unresolvable` rather than `denied`.
    """
    hop2 = {
        "iss": ISS,
        "sub": "agent:x402-settler",
        "scopes": list(hop2_scopes if hop2_scopes is not None else HOP2_SCOPES),
        "requested_action": "pay:x402",
    }
    if terminal_proof_ref is not None:
        hop2["proof_ref"] = terminal_proof_ref
    return {
        "actorChain": {
            "origin": {
                "iss": ISS,
                "sub": "user:principal-18b6d2fc",
                "scopes": list(origin_scopes if origin_scopes is not None else ORIGIN_SCOPES),
            },
            "actors": [
                {
                    "iss": ISS,
                    "sub": "agent:coordinator",
                    "scopes": list(HOP1_SCOPES),
                    "requested_action": "pay:x402",
                    # no proof_ref — deliberately. See docstring.
                },
                hop2,
            ],
        }
    }


def main():
    FIX.mkdir(exist_ok=True)

    authorized_ref = proof_ref("evidence/envelope.authorized.json")
    revoked_ref = proof_ref("evidence/envelope.postrevoke.json")

    vectors = {
        # AC-1 / AC-2 — THE PAIR. Byte-identical apart from the terminal
        # proof_ref target. Both narrow perfectly. Opposite authority verdicts.
        "ac1-authorized.json": chain(authorized_ref),
        "ac2-revoked.json": chain(revoked_ref),

        # AC-3 — aeoess's case, made concrete: "a made-up chain can still narrow
        # perfectly at every step". Same shape, same scopes, well-formed by every
        # payload-level check; the reference resolves to nothing at all.
        "ac3-fabricated.json": chain(
            "elara:envelope/sha3-256:" + "00" * 32),

        # AC-4 — the honest partially-evidenced chain: terminal hop supplies no
        # proof_ref. MUST come back `unresolvable`, never `not_authorized`.
        "ac4-no-proof-ref.json": chain(None),

        # AC-5 — NEGATIVE. Terminal hop holds `ci:trigger`, which its predecessor
        # never held. Narrowing violation; the confused-deputy shape from #153.
        "ac5-narrowing-violation.json": chain(
            authorized_ref, hop2_scopes=["pay:x402", "ci:trigger"]),
    }

    for name, body in vectors.items():
        (FIX / name).write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        print(f"  {name}")

    # AC-6 — NEGATIVE, append-only. A delegating agent appended its own hop but
    # ALSO rewrote its predecessor's scopes upward. The rewritten chain narrows
    # perfectly and would pass a naive check; it is caught only by comparing
    # against the chain as it was received.
    received = chain(authorized_ref)
    rewritten = json.loads(json.dumps(received))
    rewritten["actorChain"]["actors"][0]["scopes"] = ORIGIN_SCOPES[:]
    (FIX / "ac6-prior-hop-rewritten.json").write_text(
        json.dumps({"received": received, "forwarded": rewritten},
                   indent=2, sort_keys=True) + "\n")
    print("  ac6-prior-hop-rewritten.json")

    # The verdicts these proof_refs resolve to are the SAME committed verdict
    # bytes the MCP SEP-3004 vectors carry. Copied here so this directory stands
    # alone, and pinned by check A6 so the two can never drift apart — that
    # equality IS the transport-neutrality claim, checked rather than asserted.
    for name in ("verdict.authorized.json", "verdict.postrevoke.json"):
        (FIX / name).write_bytes((MCP_FIX / name).read_bytes())
        print(f"  {name} (mirrored from the SEP-3004 vectors)")


if __name__ == "__main__":
    main()
