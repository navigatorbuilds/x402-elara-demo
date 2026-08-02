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
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FIX = HERE / "fixtures"
MCP_FIX = ROOT / "conformance" / "mcp-3004-audit-record-v0" / "fixtures"
VERIFIER = ROOT / "target" / "debug" / "x402-work-receipt"
VERDICT_MARKER = "--- raw BundleVerdict (verbatim) ---"

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


def make_badsig_envelope() -> None:
    """Deterministic tamper: the authorized envelope with ONE act-signature byte
    incremented (index len//2, +1 mod 256). The file still parses, its digest is
    well-defined, and the reference to it RESOLVES — the failure is inside the
    resolved bytes, which is the case aeoess asked about: present, resolves,
    invalid signature. Regenerating always yields the same bytes."""
    e = json.loads((ROOT / "evidence/envelope.authorized.json").read_text())
    sig = e["act"]["signature"]
    i = len(sig) // 2
    sig[i] = (sig[i] + 1) % 256
    (ROOT / "evidence/envelope.badsig.json").write_text(
        json.dumps(e, indent=2, sort_keys=True) + "\n")


def run_verifier_verdict(envelope_rel: str, out_name: str) -> None:
    """The committed verdict is the verbatim output of the real offline
    verifier over the committed envelope — produced, never hand-written."""
    if not VERIFIER.exists():
        sys.exit(f"FATAL: {VERIFIER} missing — build with `cargo build --bin "
                 "x402-work-receipt` before generating verdicts")
    out = subprocess.run(
        [str(VERIFIER), "verify", "--envelope", str(ROOT / envelope_rel), "--json"],
        capture_output=True, text=True)
    if VERDICT_MARKER not in out.stdout:
        sys.exit(f"FATAL: verifier output carries no verdict marker for {envelope_rel}")
    raw = out.stdout.split(VERDICT_MARKER, 1)[1].lstrip("\n")
    (FIX / out_name).write_text(raw)
    print(f"  {out_name} (verbatim verifier output over {envelope_rel})")


def main():
    FIX.mkdir(exist_ok=True)

    make_badsig_envelope()
    authorized_ref = proof_ref("evidence/envelope.authorized.json")
    revoked_ref = proof_ref("evidence/envelope.postrevoke.json")
    badsig_ref = proof_ref("evidence/envelope.badsig.json")

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

        # AC-7 — the reference is PRESENT and RESOLVES (digest matches the
        # committed bytes) but the resolved envelope's act signature is invalid.
        # A third failure state, distinct from both `unresolvable` (nothing to
        # check) and `not_authorized` (checked, authority absent). The chain
        # itself is byte-identical to ac1's shape.
        "ac7-invalid-signature.json": chain(badsig_ref),
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

    # AC-8 / AC-9 — the RESERVED `originAnchor` slot (thread, 2026-07-31→08-01):
    # named now, consulted never. An anchor describes where a hop CAME FROM —
    # never what it may do. Reserving the name is cheap only if it is provably
    # inert, so both vectors populate it aggressively: one ref is well-formed
    # but resolves to nothing (the slot's evidence class does not exist yet),
    # and one ref RESOLVES to a committed envelope — the most tempting possible
    # anchor, and it must still change nothing.
    #
    # AC-8 — FORWARD-COMPAT. ac1's chain with anchors populated on the origin
    # and the terminal hop. Every check outcome must be identical to ac1's, and
    # stripping the anchors must yield ac1 exactly — proof the reservation was
    # actually free.
    ac8 = chain(authorized_ref)
    ac8["actorChain"]["origin"]["originAnchor"] = {
        "ref": "elara:envelope/sha3-256:" + "11" * 32}
    ac8["actorChain"]["actors"][1]["originAnchor"] = {"ref": authorized_ref}
    (FIX / "ac8-origin-anchor-forward-compat.json").write_text(
        json.dumps(ac8, indent=2, sort_keys=True) + "\n")
    print("  ac8-origin-anchor-forward-compat.json")

    # AC-9 — NO PRIVILEGE VIA ANCHOR. ac5's narrowing violation with a
    # RESOLVABLE anchor on both the violating hop and the evidence-less
    # coordinator hop. The violation must be flagged identically, and the
    # anchored no-proof_ref hop must stay `unresolvable` — an anchor never
    # stands in for scope the predecessor actually held, and never becomes
    # evidence for a hop that supplied none.
    ac9 = chain(authorized_ref, hop2_scopes=["pay:x402", "ci:trigger"])
    ac9["actorChain"]["actors"][0]["originAnchor"] = {"ref": authorized_ref}
    ac9["actorChain"]["actors"][1]["originAnchor"] = {"ref": authorized_ref}
    (FIX / "ac9-anchor-grants-nothing.json").write_text(
        json.dumps(ac9, indent=2, sort_keys=True) + "\n")
    print("  ac9-anchor-grants-nothing.json")

    # The verdicts these proof_refs resolve to are the SAME committed verdict
    # bytes the MCP SEP-3004 vectors carry. Copied here so this directory stands
    # alone, and pinned by check A6 so the two can never drift apart — that
    # equality IS the transport-neutrality claim, checked rather than asserted.
    for name in ("verdict.authorized.json", "verdict.postrevoke.json"):
        (FIX / name).write_bytes((MCP_FIX / name).read_bytes())
        print(f"  {name} (mirrored from the SEP-3004 vectors)")

    # verdict.badsig.json is a2a-local (the MCP vector set has no bad-signature
    # case) and is the real verifier's verbatim output, never hand-written.
    run_verifier_verdict("evidence/envelope.badsig.json", "verdict.badsig.json")


if __name__ == "__main__":
    main()
