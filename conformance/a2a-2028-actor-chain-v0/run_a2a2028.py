#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Conformance runner for A2A #2028 — `actorChain` well-formedness vs. authority.

The thread converged on two properties that must not be conflated:

  1. WELL-FORMEDNESS — each hop's scopes are a subset of its predecessor's, and
     hops are append-only. Checkable from the payload alone, no network, no
     cross-hop log join. Checks W1-W3 implement exactly this rule and nothing
     more.

  2. AUTHORITY — whether any hop was actually granted what it claims. Because
     `actorChain` is caller-supplied, a fabricated chain satisfies (1) perfectly.
     Checks A1-A6 resolve each hop's `proof_ref` against committed evidence and
     re-derive a verdict from an offline verifier.

The headline is A1: two chains that are byte-identical in every field a
well-formedness checker can see, both passing W1-W3, resolving to OPPOSITE
authority verdicts. Narrowing is a check on the reported chain, not proof of
authority — this runner is that statement, executable.

WHAT THE EVIDENCE PROVES, PRECISELY. The offline verifier used here decides the
WHO and the WHEN: signer identity, mandate validity window, and whether the
mandate was revoked before the act was signed. It records but does not offline-
check a mandate's op/zone/amount scope (its own `scope_note` says so, and A5
asserts that caveat is actually present in the verdict). So `proof_ref`
resolution does NOT prove the hop's `scopes` were granted — that would be
precisely the conflation this thread is trying to avoid. Narrowing covers scope
consistency; the evidence covers identity, liveness and revocation. Neither
implies the other, which is why both belong in the extension text.

Run from repo root: python3 conformance/a2a-2028-actor-chain-v0/run_a2a2028.py
"""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
FIX = HERE / "fixtures"
MCP_FIX = ROOT / "conformance" / "mcp-3004-audit-record-v0" / "fixtures"

PREFIX = "elara:envelope/sha3-256:"

results = []


def check(cid, ok, detail):
    results.append((cid, ok, detail))


def load(name):
    return json.loads((FIX / name).read_text())


# ---------------------------------------------------------------------------
# The thread's well-formedness rule, implemented as specified and no further.
# ---------------------------------------------------------------------------
def hops(doc):
    ac = doc["actorChain"]
    return [ac["origin"]] + ac["actors"]


def narrowing_violations(doc):
    """Each hop's scopes MUST be a subset of its predecessor's."""
    bad = []
    chain = hops(doc)
    for i in range(1, len(chain)):
        prev, cur = set(chain[i - 1]["scopes"]), set(chain[i]["scopes"])
        excess = cur - prev
        if excess:
            bad.append(f"hop {i} ({chain[i]['sub']}) holds {sorted(excess)} "
                       f"its predecessor never held")
    return bad


def append_only_violations(received, forwarded):
    """A delegating agent appends exactly one hop and MUST NOT modify prior ones."""
    r, f = hops(received), hops(forwarded)
    bad = []
    if len(f) < len(r):
        bad.append("forwarded chain is shorter than the one received")
    for i in range(min(len(r), len(f))):
        if r[i] != f[i]:
            bad.append(f"hop {i} ({r[i]['sub']}) was modified in flight")
    return bad


# ---------------------------------------------------------------------------
# Evidence resolution. `proof_ref` is content-addressed, so resolution is
# self-verifying: hash whatever the resolver returned and compare it to the
# reference. A wrong or hostile resolver is DETECTED, never trusted. Nothing
# here dereferences a URL or presents a credential.
# ---------------------------------------------------------------------------
KNOWN = {}
for rel in ("evidence/envelope.authorized.json", "evidence/envelope.postrevoke.json",
            "evidence/envelope.badsig.json"):
    raw = (ROOT / rel).read_bytes()
    KNOWN[hashlib.sha3_256(raw).hexdigest()] = rel

VERDICT_FOR = {
    "evidence/envelope.authorized.json": "verdict.authorized.json",
    "evidence/envelope.postrevoke.json": "verdict.postrevoke.json",
    "evidence/envelope.badsig.json": "verdict.badsig.json",
}


def resolve(hop):
    """-> (status, detail). status in {consistent, not_authorized, invalid,
    unresolvable}.

    Four states, deliberately not three. `unresolvable` = nothing to check
    (absent ref / unknown scheme / resolves to nothing). `not_authorized` =
    checked, and the authority was absent (revoked, lapsed, wrong agent…).
    `invalid` = the reference RESOLVED but the resolved evidence fails
    verification itself (e.g. a bad carrier signature) — no authority judgment
    was ever reached. Folding `invalid` into `not_authorized` would misreport
    broken evidence as a denial; an earlier revision of this very file did
    exactly that (any non-CONSISTENT verdict mapped to not_authorized), which
    is the conflation aeoess's check-order comment warns about."""
    ref = hop.get("proof_ref")
    if ref is None:
        # The thread's normative rule: absence means no reconciliation aid was
        # supplied. It is NOT evidence that no grant occurred.
        return "unresolvable", "no proof_ref supplied"
    if not ref.startswith(PREFIX):
        return "unresolvable", f"unrecognised proof_ref scheme: {ref[:24]}…"
    digest = ref[len(PREFIX):]
    rel = KNOWN.get(digest)
    if rel is None:
        return "unresolvable", "reference resolves to nothing"
    verdict = json.loads((FIX / VERDICT_FOR[rel]).read_text())
    if verdict["verdict"] == "CONSISTENT":
        return "consistent", verdict["explanation"]
    if verdict["verdict"] == "FAILED":
        return "invalid", verdict["reason"]
    return "not_authorized", verdict["explanation"]


def terminal(doc):
    return doc["actorChain"]["actors"][-1]


ac1, ac2 = load("ac1-authorized.json"), load("ac2-revoked.json")
ac3, ac4 = load("ac3-fabricated.json"), load("ac4-no-proof-ref.json")
ac5 = load("ac5-narrowing-violation.json")
ac6 = load("ac6-prior-hop-rewritten.json")
ac7 = load("ac7-invalid-signature.json")
ac8 = load("ac8-origin-anchor-forward-compat.json")
ac9 = load("ac9-anchor-grants-nothing.json")


def strip_anchors(doc):
    """Remove every `originAnchor` — the reserved slot must be exactly this
    removable: no check below may change outcome when it disappears."""
    d = json.loads(json.dumps(doc))
    d["actorChain"]["origin"].pop("originAnchor", None)
    for h in d["actorChain"]["actors"]:
        h.pop("originAnchor", None)
    return d

# ---------------------------------------------------------------------------
# W1 — every well-formed vector passes the narrowing check.
# ---------------------------------------------------------------------------
bad = []
for name, doc in [("ac1", ac1), ("ac2", ac2), ("ac3", ac3), ("ac4", ac4)]:
    v = narrowing_violations(doc)
    if v:
        bad.append(f"{name}: {'; '.join(v)}")
check("W1-narrowing-holds", not bad,
      "; ".join(bad) or "ac1-ac4 all narrow monotonically at every hop")

# ---------------------------------------------------------------------------
# W2 — the negative vector is caught. A checker that never rejects proves nothing.
# ---------------------------------------------------------------------------
v5 = narrowing_violations(ac5)
check("W2-narrowing-violation-caught", len(v5) == 1,
      v5[0] if v5 else "UNEXPECTED: narrowing violation went undetected")

# ---------------------------------------------------------------------------
# W3 — append-only. A hop rewritten in flight is caught only against the chain
# as received; the rewritten chain narrows perfectly on its own.
# ---------------------------------------------------------------------------
v6 = append_only_violations(ac6["received"], ac6["forwarded"])
self_consistent = not narrowing_violations(ac6["forwarded"])
check("W3-prior-hop-rewrite-caught", len(v6) == 1 and self_consistent,
      f"{v6[0]}; and the rewritten chain still narrows perfectly on its own"
      if v6 and self_consistent else "UNEXPECTED: see fixture state")

# ---------------------------------------------------------------------------
# A1 — THE GAP. ac1 and ac2 are identical in every field a well-formedness
# checker can see — same origin, same hops, same (iss, sub), same scope sets at
# every level. Both pass W1. They differ in exactly one byte-range: which
# committed envelope the terminal proof_ref addresses. The verdicts are opposite.
# ---------------------------------------------------------------------------
def blind_view(doc):
    """Everything a payload-level checker can see. proof_ref is opaque to it."""
    d = json.loads(json.dumps(doc))
    for h in d["actorChain"]["actors"]:
        h.pop("proof_ref", None)
    return d


identical = blind_view(ac1) == blind_view(ac2)
s1, e1 = resolve(terminal(ac1))
s2, e2 = resolve(terminal(ac2))
check("A1-the-gap", identical and s1 == "consistent" and s2 == "not_authorized",
      f"identical to every well-formedness check, both narrow; verdicts differ: "
      f"{s1} vs {s2} ({e2})" if identical
      else "vectors differ in a visible field, weakening the demonstration")

# ---------------------------------------------------------------------------
# A2 — a fabricated chain narrows perfectly and resolves to nothing. This is the
# thread's own sentence, executable: "a made-up chain can still narrow perfectly
# at every step."
# ---------------------------------------------------------------------------
s3, e3 = resolve(terminal(ac3))
check("A2-fabricated-chain-narrows-but-resolves-to-nothing",
      not narrowing_violations(ac3) and s3 == "unresolvable",
      f"ac3 passes every payload-level check; proof_ref {e3}")

# ---------------------------------------------------------------------------
# A3 — absence of proof_ref is `unresolvable`, NEVER `not_authorized`. Silence is
# not evidence of a missing grant, and a verifier that conflates them will punish
# every deployment that has not finished wiring evidence.
# ---------------------------------------------------------------------------
s4, _ = resolve(terminal(ac4))
mid, _ = resolve(ac1["actorChain"]["actors"][0])
check("A3-absence-is-unresolvable-not-denial",
      s4 == "unresolvable" and mid == "unresolvable",
      "a hop with no proof_ref returns unresolvable in both the terminal and "
      "the mid-chain position — never a denial")

# ---------------------------------------------------------------------------
# A4 — resolution is self-verifying. Feed the resolver the WRONG bytes for a
# reference and it is caught by the reference itself, with no trusted registry,
# no signature over the pointer, and no authorization to dereference.
# ---------------------------------------------------------------------------
ref = terminal(ac1)["proof_ref"]
wrong = (ROOT / "evidence/envelope.postrevoke.json").read_bytes()
caught = hashlib.sha3_256(wrong).hexdigest() != ref[len(PREFIX):]
is_opaque = ("://" not in ref) and ("?" not in ref)
check("A4-content-addressed-resolver-cannot-lie", caught and is_opaque,
      "swapped bytes are rejected by the reference itself; the ref carries no "
      "host, path or query — an opaque identifier, not a capability URL")

# ---------------------------------------------------------------------------
# A5 — the verdict states its own limits. It is derived from the offline
# verifier, and it declares that op/zone/amount scope is recorded but NOT
# offline-checked in v0. So proof_ref resolution evidences the WHO and the WHEN,
# not that the hop's `scopes` were granted. Asserting otherwise would be exactly
# the conflation this thread is correcting.
# ---------------------------------------------------------------------------
v = json.loads((FIX / "verdict.postrevoke.json").read_text())
has_caveat = "not checked offline in v0" in v.get("scope_note", "")
derived = v["verdict"] == "NOT AUTHORIZED" and v["flag"] == "post_revocation"
check("A5-verdict-declares-its-own-limits", has_caveat and derived,
      "verdict is the verifier's own output (post_revocation) and carries the "
      "scope_note caveat: identity + window + revocation, not scope")

# ---------------------------------------------------------------------------
# A6 — transport neutrality, checked. The verdict bytes these A2A proof_refs
# resolve to are byte-identical to the ones the MCP SEP-3004 audit records carry
# for the same acts. One evidence profile, two protocols, no re-derivation.
# ---------------------------------------------------------------------------
same = all((FIX / n).read_bytes() == (MCP_FIX / n).read_bytes()
           for n in ("verdict.authorized.json", "verdict.postrevoke.json"))
check("A6-same-evidence-across-protocols", same,
      "verdict bytes identical to the SEP-3004 vectors — the evidence layer is "
      "transport-neutral, and drift here fails the build")

# ---------------------------------------------------------------------------
# A7 — present, resolves, INVALID. The reference matches the committed bytes
# (so this is not A4's wrong-bytes case and not A2/A3's unresolvable), but the
# resolved envelope's act signature does not verify. Three assertions:
#   (i)  the status is `invalid` — distinct from `unresolvable` AND from
#        `not_authorized`; broken evidence is not a denial.
#   (ii) the committed verdict carries NO lifecycle flag (flag=input_error,
#        never post_revocation/lapsed/…) — an invalid signature cannot be
#        misreported as "expired" or "revoked".
#   (iii) ORDER, proven from the verdict's own audit trail: exactly one check
#        ran (`act signature`, fail) and no window/revocation check ever
#        executed. Signature validity short-circuits BEFORE lifecycle, so the
#        expired-masking-broken-sig failure mode cannot occur by construction.
# ---------------------------------------------------------------------------
s7, d7 = resolve(terminal(ac7))
v7 = json.loads((FIX / "verdict.badsig.json").read_text())
trail = [(c["name"], c["status"]) for c in v7.get("checks", [])]
lifecycle_ran = any(("window" in n or "revocation" in n or "scope" in n)
                    for n, _ in trail)
check("A7-invalid-is-not-a-denial-and-order-is-proven",
      not narrowing_violations(ac7)
      and s7 == "invalid"
      and v7["verdict"] == "FAILED" and v7["flag"] == "input_error"
      and "signature" in v7["reason"]
      and trail == [("act signature", "fail")]
      and not lifecycle_ran,
      f"resolves, then fails verification itself: {v7['reason']}; audit trail "
      f"= {trail} — signature checked first, no lifecycle check ever ran")

# ---------------------------------------------------------------------------
# W4 — the RESERVED `originAnchor` slot is inert (forward-compat). ac8 is ac1
# with anchors populated on the origin (well-formed ref that resolves to
# nothing) and the terminal hop (a ref that RESOLVES to a committed envelope —
# the most tempting possible anchor). Everything must come out exactly as ac1,
# and stripping the anchors must yield ac1 itself: the reservation was
# actually free.
# ---------------------------------------------------------------------------
s8, _ = resolve(terminal(ac8))
s8_stripped, _ = resolve(terminal(strip_anchors(ac8)))
check("W4-reserved-originAnchor-is-inert",
      not narrowing_violations(ac8)
      and s8 == "consistent"
      and s8_stripped == s8
      and strip_anchors(ac8) == ac1,
      "anchors populated on origin + terminal (one even resolvable); narrowing "
      "and resolution identical to ac1, and stripped it IS ac1 — unknown-slot "
      "tolerance proven, not assumed")

# ---------------------------------------------------------------------------
# A8 — NO PRIVILEGE VIA ANCHOR. ac9 is ac5's narrowing violation wearing
# resolvable anchors on both the violating hop and the evidence-less
# coordinator. The violation is flagged identically; the coordinator stays
# `unresolvable` (an anchor is not evidence and cannot stand in for a missing
# proof_ref); the terminal verdict is unchanged. Anchors describe where a hop
# came from — never what it may do.
# ---------------------------------------------------------------------------
v9 = narrowing_violations(ac9)
mid9, _ = resolve(ac9["actorChain"]["actors"][0])
t9, _ = resolve(terminal(ac9))
t5_again, _ = resolve(terminal(ac5))
check("A8-no-privilege-via-anchor",
      len(v9) == 1
      and v9 == narrowing_violations(ac5)
      and mid9 == "unresolvable"
      and t9 == t5_again,
      "ac5's violation flagged identically with anchors present; the anchored "
      "no-proof_ref hop is still unresolvable and the terminal verdict is "
      "unchanged — an anchor grants nothing, rescues nothing")

# ---------------------------------------------------------------------------
print()
for cid, ok, detail in results:
    print(f"  {'✓' if ok else '✗'} {cid} — {detail}")
failed = sum(1 for _, ok, _ in results if not ok)
print(f"\n{len(results)} checks — {len(results) - failed} passed, {failed} failed")
sys.exit(1 if failed else 0)
