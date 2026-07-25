# `authority-evidence` — a registered evidence profile for SEP-3004

A runnable mapping for the **Tamper-Evident Audit Record Contract**
([modelcontextprotocol#3004](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004)),
built against the contract's own extension mechanism.

The contract's layering is explicit in the thread: the record core answers
*"is this audit history internally intact?"*, and a registered extension commits
to its own guarantee under its own profile identifier. This directory is a
worked second example of that — an extension whose guarantee is that the record
is **bound to a signed act that a third party can recompute**, and whose central
claim is that the two properties are independent.

Both halves run in under a second, on stock tooling, from committed bytes.

```
node --experimental-strip-types vendor/run_reference.ts   # 8 reference checks
python3 run_mcp3004.py                                    # 7 evidence checks
```

---

## What this shows

**The registration costs exactly one line.** `vendor/run_reference.ts` runs the
SEP's own reference verifier — vendored byte-for-byte, `sha256` pinned in
`vendor/SHA256SUMS`, not one character patched — over these fixtures. Before the
registry entry it *rejects* the records (`unregistered extension type:
authority-evidence`); after it, they validate, hash and chain. That is the
contract's "new emitter types add an extension, not a new chain" claim,
exercised rather than restated.

**Two implementations agree.** `canon.py` is an independent reimplementation of
the `gif-audit/2` canonical form, written from the specification text rather
than ported from the TypeScript. Check R3 asserts the two agree on every
fixture, and R0 asserts the vendored verifier still reproduces both published
known-answer digests (`d494769c…`, `f733fed9…`) — so if the vendored copy were
ever not the one the SEP describes, every other result here is void by
construction.

**Three extensions, one digest.** `fixtures/three-extension-kat.json` carries
`caller-governance` + `runtime-security` + `authority-evidence` side by side.
Its first two bodies are byte-identical to the SEP's own two-extension fixture,
so the only delta against the published `f733fed9…` is this extension. New
known-answer digest, reproducible with stock tools:

```
81aea291a50bdfd0e0db10e64479117cac9a19126cb28311dbaef70a8efa46b3
```

`run_mcp3004.py` prints the exact `printf … | sha256sum` line that produces it.

**The gap, demonstrated in both directions.** The two chained records are the
*same* agent, under the *same* mandate, performing the *same* signed act
payload, 166 ms apart — straddling the moment the principal revoked the mandate.
Every protected core field is identical except `event_id`, `occurred_at` and the
chain link. Both are `outcome: allowed`, because the host did dispatch both
calls, and the audit core is a truthful record of that.

- **R7** — the segment verifies. SEP-3004 verification passes for *both*
  records. It cannot distinguish the authorized act from the post-revocation
  one, because nothing in the protected core differs.
- **E4** — flip one bit inside the evidence artifact. The audit record is
  untouched, so the chain still verifies perfectly; the evidence digest simply
  stops resolving. Internal integrity is blind to this.

Neither property implies the other. That is the entire argument for a registered
evidence profile, and it is why the extension's value is that it *can contradict
the record it rides in* — an extension that only ever agreed with `outcome`
would carry no information.

**The core cannot make this binding itself.** §2.1 defines `occurred_at` as the
recorder's clock, explicitly not caller-settable — so the record structurally
cannot attest *when the caller acted*. `act_signed_at` is checked (E3) against
the timestamp inside the signed act, and `principal_id` against the signer the
offline verifier reports.

---

## Proposed registration (§2.2 shape)

**Type ID:** `authority-evidence`

Commits a record to independently recomputable evidence that the event was
performed under authority that held at the act's signed time. All values are
strings or `null`, per the `/2` no-bare-numbers convention.

| Field | Req | Description |
|---|---|---|
| `evidence_profile` | ✔ | Versioned profile identifier; defines what the evidence proves and its soundness limits. Here: `elara/mandate-bundle@v0`. |
| `evidence_digest` | ✔ | `<alg>:<hex>` over the evidence artifact's bytes. |
| `authority_verdict` | ✔ | `consistent` \| `not_authorized` \| `unresolvable`. |
| `verdict_digest` | ✔ | `<alg>:<hex>` over the deterministic verifier output. |
| `evidence_uri` | — | Resolvable reference to the artifact. |
| `act_signed_at` | — | RFC 3339 UTC; the caller-side signed time, which the core cannot carry. |
| `signature_alg` | — | Algorithm of the underlying signature. Here `ML-DSA-65`. |

**Conformance requirement — recomputability, not agreement.** Given
`evidence_digest` and a resolved artifact, an independent party MUST obtain
`authority_verdict` by re-running the named profile's procedure. The extension
makes no claim about the core `outcome`; a `not_authorized` verdict on an
`allowed` outcome is conformant and is the detection case.

**Relationship to the other registrations.** `runtime-security` commits to
runtime drift evidence, `admission-control` (per #2809) to the admission
decision, and this to the caller's authority to have acted at all. Same
mechanism, one digest, three independent guarantees.

---

## Honest claims

- The verdicts here come from a **signing-incapable, MIT/Apache offline
  verifier** over a committed bundle. E7 re-runs it and confirms it still
  reproduces the committed verdict bytes.
- A `consistent` verdict proves the carrier signatures are valid and the
  authority held at the act's signed time **given only the records in that
  bundle**. It does *not* prove the records are on a ledger, sealed, or
  time-anchored. The full soundness caveats ship inside every verdict file in
  `fixtures/` — read them; they are part of the evidence, not a footnote.
- The acts are from a small self-hosted testnet, not a production network. The
  `x402_payment` payload is illustrative; the signatures, mandate, revocation
  and verdicts are real.
- `ML-DSA-65` is checkable from the artifacts themselves (E5): the committed
  acts carry a 1952-byte public key and a 3309-byte signature, the FIPS 204
  parameter sizes. The implementation is `dilithium-rs` 0.2.0, which reports a
  bit-for-bit match against the NIST KAT vectors; this directory asserts the
  parameter sizes, not an independent FIPS validation.
- The vendored `audit-record-contract.ts` is Apache-2.0, © Notboatanchor Labs
  LLC, unmodified, from
  [`gif@e1f02a95`](https://github.com/notboatanchor/gif/tree/e1f02a95506e81e7766c3ba3a684ecad7cfff12f/mcp-server/conformance/audit-record-contract).
  The registration line lives in our driver, never in their file.
- This is an unsolicited mapping, not an endorsement by the SEP's authors, and
  the type id, field names and enum are a **proposal** — the SEP's authors own
  the registry.

## Regenerating

```
cargo build --bin x402-work-receipt          # the offline verifier (E7)
python3 _generate.py                         # fixtures, from committed bytes only
```
