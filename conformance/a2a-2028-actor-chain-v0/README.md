# `actorChain` + a resolvable `proof_ref` — runnable vectors for A2A #2028

Vectors for the actor-chain extension discussed in
[a2aproject/A2A#2028](https://github.com/a2aproject/A2A/issues/2028), built
around the distinction the thread converged on: **well-formedness and authority
are two properties, and the first does not imply the second.**

```
python3 run_a2a2028.py        # 9 checks, under a second, no network
```

---

## The two properties, kept apart

**W1–W3 implement the thread's own rule and nothing more.** Each hop's `scopes`
must be a subset of its predecessor's, and hops are append-only. Checkable from
the payload alone — no cross-hop log join, no network. W2 and W3 are negative
vectors, because a checker that never rejects proves nothing:

- **W2** — a terminal hop holding `ci:trigger`, which its predecessor never held.
  The confused-deputy shape from #153.
- **W3** — a delegating agent that appended its own hop *and* quietly rewrote its
  predecessor's scopes upward. Caught only against the chain as received; the
  rewritten chain narrows perfectly on its own.

**A1–A6 are the other property.** `actorChain` is caller-supplied, so a
fabricated chain satisfies well-formedness at every step. These checks resolve
each hop's `proof_ref` and re-derive a verdict from an offline verifier.

## The gap, executable

`ac1-authorized.json` and `ac2-revoked.json` are **identical in every field a
well-formedness checker can see** — same origin, same hops, same `(iss, sub)`,
same scope sets at every level. Both pass W1. They differ in exactly one thing:
which committed envelope the terminal `proof_ref` addresses.

One resolves to a mandate that was live when the act was signed. The other
resolves to the same mandate *after the principal revoked it*. Opposite verdicts,
from payloads a narrowing check cannot tell apart. **A1** asserts precisely that.

`ac3-fabricated.json` is the thread's own sentence made executable — a chain that
narrows perfectly at every step and whose `proof_ref` resolves to nothing at all.

## What the evidence proves, precisely

`proof_ref` resolution here evidences **the WHO and the WHEN**: signer identity,
mandate validity window, and whether the mandate was revoked before the act was
signed. The offline verifier records but does not offline-check a mandate's
op/zone/amount scope — its own `scope_note` says so, and **A5** asserts that
caveat is actually present in the verdict rather than taking it on trust.

So resolution does **not** prove a hop's `scopes` were granted. Claiming it did
would be the exact conflation this thread is correcting. Narrowing covers scope
consistency; the evidence covers identity, liveness and revocation. Neither
implies the other — which is the argument for specifying both.

## `proof_ref` as an opaque, content-addressed reference

The thread asked for "an opaque reference rather than a capability URL, with
dereference authorized separately." These vectors use:

```
elara:envelope/sha3-256:<hex>
```

No host, no path, no query, no bearer secret — **A4** asserts that. Because the
reference *is* the digest, resolution is self-verifying: hash whatever the
resolver returned and compare. A4 feeds the resolver deliberately wrong bytes and
they are rejected by the reference itself. **A resolver cannot lie about what it
returned, so it does not have to be trusted** — no registry, no signature over
the pointer, no authorization needed to check the answer.

## Absence is not denial

`ac4-no-proof-ref.json` carries no `proof_ref`, and hop 1 of *every* vector is a
coordinator whose grant is genuinely outside this bundle. Both return
`unresolvable`, never `not_authorized` (**A3**). Partially-evidenced chains are
the realistic case for a long time, and a verifier that reads silence as denial
punishes every deployment still wiring evidence up.

## Missing, unresolvable, and invalid are three different states

`ac7-invalid-signature.json` (**A7**) is the case between them: the reference is
**present and resolves** — the digest matches the committed bytes — but the
resolved envelope's act signature does not verify (one signature byte differs;
`_generate.py` reproduces the tamper deterministically). The runner reports it
as `invalid`: distinct from `unresolvable` (there was nothing to check) and
distinct from `not_authorized` (the check ran and authority was absent). Folding
`invalid` into `not_authorized` would report broken evidence as a denial — an
earlier revision of this runner did exactly that, and A7 now pins the
distinction.

A7 also proves **check order** from the verdict's own audit trail rather than
asserting it: the committed `verdict.badsig.json` shows exactly one executed
check — `act signature: fail` — and no window/revocation/scope check ever ran.
Signature validity short-circuits *before* any lifecycle question, so an
invalid signature can never be masked as "expired" or "revoked". The flag is
`input_error`, never a lifecycle flag.

## One evidence profile, two protocols

**A6** asserts the verdict bytes these `proof_ref`s resolve to are byte-identical
to the ones carried by the SEP-3004 audit records in
[`../mcp-3004-audit-record-v0`](../mcp-3004-audit-record-v0) for the same acts —
so the evidence layer is transport-neutral in the way #2028 asks for, and drift
between the two fails the build rather than rotting quietly.

## Honest claims

- The acts come from a small self-hosted testnet, not a production network. The
  payload they carry is illustrative; the signatures, mandate, revocation and
  verdicts are real.
- The verifier is signing-incapable, MIT/Apache, and offline. A `CONSISTENT`
  verdict proves the carrier signatures are valid and the authority held at the
  act's signed time **given only the records in that bundle** — not that they are
  on a ledger, sealed, or time-anchored. Full caveats ship inside every verdict
  file in `fixtures/`.
- The hop identities and scope vocabulary are illustrative; the chain *shape* is
  the one proposed in #2028, with the `(iss, sub)` and `proof_ref` refinements
  the thread converged on.
- This is an unsolicited contribution, not an endorsement by the issue's author
  or by A2A maintainers, and it proposes no extension namespace or governance
  outcome — those are theirs.

## Regenerating

```
python3 _generate.py     # every vector derives from committed bytes
```
