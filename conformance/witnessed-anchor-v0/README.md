# `witnessed-anchor-v0` — third-party transparency-log anchor, re-verified offline

*You are in the **witnessed-anchor** vector: it checks a third-party log's claim that this
repo's mandate envelope existed at a time in a witnessed order. It says nothing about whether
the envelope authorizes anything — that is
[`erc-8004-validation-v0/`](../erc-8004-validation-v0/) and the offline verifier.*

```bash
python3 conformance/witnessed-anchor-v0/run_anchor.py   # exit 0, stdlib only
```

## What is being claimed, and what is not

The authorized mandate envelope's SHA-256 (`95b7791e…` — the same content-address
[`erc-8004-validation-v0`](../erc-8004-validation-v0/) recomputes as ERC-8004 `requestHash`)
was appended as a typed leaf to a C2SP `tlog-checkpoint` transparency log at
[log.markovianprotocol.com](https://log.markovianprotocol.com), operated by
**MarkovianProtocol** — not by us. The leaf carries its own scope line:

> existence and witnessed order of these bytes only; no authority or validity claim

That boundary is the whole point, and both sides stated it independently before the join was
made (erc-8004/erc-8004-contracts#77). Inclusion in a witnessed log is a **timestamp with
witnesses**: it proves these exact bytes were in the log at a point in a tamper-evident order.
It is not a signature over their meaning. Whether the mandate authorizes a payment stays
where every other vector in this repo puts it — in an offline recompute over the committed
bytes, by the reader, with no scorer to trust.

## What `run_anchor.py` recomputes

Nothing here is taken on the log operator's word; each step is recomputed from committed bytes.

| # | Check | Why it matters |
|---|---|---|
| 1 | `SHA-256(examples/envelope.authorized.example.json)` equals the `request_hash` inside the leaf | the anchor is over **our** bytes, not something adjacent to them |
| 2 | the committed leaf is byte-exact and its digest matches the published one | the leaf we verify is the leaf they published |
| 3 | RFC 6962 inclusion proof folds leaf 6312 to the published root at tree size 6322 | the leaf is genuinely *in* the tree that root commits to |
| 4 | the live checkpoint carries a valid **Ed25519** signature under the log's published vkey | the tree head is the operator's, not an attacker's |
| 5 | RFC 6962 consistency proof: the size-6322 tree is a prefix of the signed size-6355 tree | nothing was rewritten underneath our leaf afterwards |

Hashing is RFC 6962: leaf hash = `SHA-256(0x00 ‖ leaf)`, interior node =
`SHA-256(0x01 ‖ left ‖ right)`. Leaves are RFC 8785 (JCS) canonical JSON — the same
canonicalization discipline applied on both sides of the join, which is what makes
recompute-equality meaningful across it.

**Ed25519 verification is implemented in this file from RFC 8032**, in ~60 lines of integer
arithmetic, rather than pulled from a dependency. Every runner in this repo is stdlib-only so
that a stranger can check our claims from a bare clone with nothing installed — a property an
outside reviewer tested and found broken once already (#77), which is exactly why it is a rule
here and not a preference.

## Honest limits

- **Witness cosignatures are recorded, not verified.** The committed checkpoint carries
  cosignatures from 7 independent witnesses beyond the log's own key (Geomys/navigli,
  stagemole, little-garden, Google staging, rgdd, smartit, remora) over a 4-of-7 quorum.
  `run_anchor.py` verifies the **log's** signature and reports the witness names; verifying
  each cosignature would require fetching each witness's own public key from that witness, and
  we do not ship keys we did not fetch ourselves. Treat the witness list as evidence to follow
  up, not as a checked claim.
- **The artifacts here are a snapshot** taken 2026-08-03. They are committed so the check is
  reproducible offline and forever; re-fetch the live endpoints (commands in `run_anchor.py`'s
  docstring) to confirm the log still serves a history consistent with them.
- **Only the authorized envelope is anchored.** The post-revocation counter-case
  (`07557dbc…`) is not, so this vector timestamps one side of the pair.
- **A log proves order, not truth.** A witnessed log would faithfully record a leaf pointing at
  a worthless envelope. The value comes entirely from step 1 binding it to bytes whose meaning
  is independently recomputable.

## Provenance

Leaf appended by the log operator at our request in
[erc-8004/erc-8004-contracts#77](https://github.com/erc-8004/erc-8004-contracts/issues/77);
artifacts in `fixtures/` were fetched from that log's public endpoints on 2026-08-03 and are
committed verbatim.
