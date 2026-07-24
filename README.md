# x402 × Elara — a work-layer receipt for an agent's payment act

A small, runnable demo: an autonomous agent pays for an [x402](https://www.x402.org)-
protected resource on Base Sepolia, and that payment act is turned into a
**post-act, post-quantum, offline-verifiable receipt** that answers a question no
transaction hash or bare signature can:

> *Was **this** agent **authorized** — by whom, under what mandate, and did that
> authority still hold the moment it acted?*

The receipt verifies **fully offline** with a signing-incapable MIT/Apache
verifier. It is designed to **compose with** x402's payment receipts, not compete
with them — it occupies the layer the STARK-receipt draft's own `action_ref`
field explicitly leaves to "the work layer."

> **Status / honesty.** This is a working demo backed by a small, self-hosted
> Elara testnet, not a production network. Every claim below distinguishes
> *designed-for* from *demonstrated-here*. See [Honest claims](#honest-claims).

---

## Where this sits (composes, does not compete)

x402 settles agent **payments**, and its community is standardizing *payment*
receipts — the STARK-receipt draft ([#2357](https://github.com/x402-foundation/x402/issues/2357)
+ [`draft-vauban-x402-stark-receipts-02`](https://datatracker.ietf.org/doc/draft-vauban-x402-stark-receipts/),
liaison [#2428](https://github.com/x402-foundation/x402/issues/2428)); a
Bitcoin-anchored provenance proposal ([#2740](https://github.com/x402-foundation/x402/issues/2740));
a PQC extension proposal ([#2664](https://github.com/x402-foundation/x402/issues/2664),
ML-DSA-65). AP2 — now **FIDO-governed** — produces *authorization* evidence for
commerce, on classical signatures (sample alg RS256) with no published
post-quantum roadmap.

None of these receipt the agent's **non-payment acts** — the commit, the deploy,
the publish. Elara is a shipped work-layer receipt for **any** signed agent act:
post-quantum (FIPS 204 / 205), bound to a **revocable on-mesh mandate**, verifiable
fully offline by a signing-incapable MIT/Apache verifier. The STARK draft's
`action_ref` (§8: *"the receipt format does not interpret the action_ref
preimage… defined by the work layer"*) explicitly leaves act-digest semantics to
the work layer — **this is such a work layer**, composing with those payment
receipts rather than competing with them.

This demo applies that work layer to the payment act itself: the same primitive
that receipts a commit or a deploy also receipts *"agent A was mandated to make
this x402 payment."* It is the pattern [#2650](https://github.com/x402-foundation/x402/issues/2650)
asks for — binding a settlement to an off-chain signed execution receipt — with
the receipt carrying provable, revocable **authority-to-act**.

---

## Quickstart

Prereqs: a Rust toolchain, and a checkout of
[`elara-mesh`](https://github.com/navigatorbuilds/elara-mesh) as a **sibling
directory** of this repo (the path dependencies expect `../elara-runtime`).

### The thesis, in one command (no payment, no funds, no network)

```bash
bash scripts/thesis-demo.sh
```

This mints a dedicated demo mandate, signs an agent act under it, assembles the
offline envelope, and verifies it — printing `✓ CONSISTENT` for an authorized act
and `✗ NOT AUTHORIZED` for a post-revocation act. It is the whole differentiator,
with zero external dependencies.

### The full x402 payment flow

```bash
# 1. one-time mint (the demo's single AGPL touch)
bash scripts/mint.sh

# 2. run the paywalled resource (terminal A)
cargo run -p paywalled-resource        # listens on :4021

# 3. run the paying agent (terminal B)
cargo run -p paying-agent
```

With no funded wallet the agent runs a clearly-labelled **SIMULATED** payment and
still produces a real, offline-verifiable receipt (the receipt certifies
*authority*, not settlement). For **LIVE** Base Sepolia settlement, see
[Real settlement](#real-base-sepolia-settlement-best-effort).

---

## The verifier's actual output (verbatim)

Running the offline verifier on the committed reference envelope
([`examples/envelope.authorized.example.json`](examples/envelope.authorized.example.json))
— reproduce with `cargo run -p x402-work-receipt -- verify --envelope examples/envelope.authorized.example.json`:

```
✓ CONSISTENT
  flag                : valid
  authorized          : true
  attributes to principal: true
  network             : testnet
  signer (agent)      : a3c7f1eab997868541bcc306efd60eea5e843c00482ac4ace02a69e50eddf7a7
  principal           : f04de39fa448100fce45798c0aa88e5ba2b7bf75a924934de5bde6aeaeb058fa
  act timestamp (ms)  : 1784062714469
  explanation         : this agent WAS authorized by the principal at the act's signed time — given the records in this bundle
  lineage (leaf→root) :
      - 612553684eaf7803 (principal f04de39fa448100f → agent a3c7f1eab9978685)
  scope note          : v0 enforces agent identity + validity window + revocation (the WHO and the WHEN). A mandate's op/zone/amount scope is recorded but not checked offline in v0 — sound, node-invariant scope enforcement is a later slice.
  checks:
      [pass] act signature — Dilithium3 valid over the act's canonical bytes
      [pass] mandate[0] — verified + principal-bound; indexed under content id 612553684eaf…
  soundness caveats (what an offline envelope CANNOT prove):
      • A ✓ CONSISTENT verdict proves the carrier signatures are valid and the authority held at the act's signed time — GIVEN ONLY the records in this bundle.
      • It does NOT prove these records exist on the Elara ledger, are sealed, or are time-anchored. For that, query a node's /mandate/status or run `elara-verify --seal --anchor`.
      • The bundle's author chooses what it contains: this verifier CANNOT detect a revocation that was withheld, nor confirm either identity has ever submitted records to any node. Cross-check the principal against a node before relying on the attribution.
```

Note the discipline: the green verdict is **`CONSISTENT`**, never an unqualified
`AUTHORIZED`, and the soundness caveats ride in every response. The post-revocation
counter-case ([`examples/verdict.postrevoke.txt`](examples/verdict.postrevoke.txt))
returns `✗ NOT AUTHORIZED (post_revocation)` — the accountability property a
timestamp cannot express.

---

## The 32-byte `action_ref` seam

Each act's `action_ref` is `SHA3-256` of the canonical signed record — a 32-byte
opaque handle. The **permissive verifier re-derives it** from the act alone
(`cargo run -p x402-work-receipt -- action-ref --act <act.json>`), matching the
value the signer emitted. A downstream x402 STARK receipt can carry this exact
value in its `action_ref` field (§8), cryptographically joining the *payment*
receipt to this *work-layer* receipt without either layer interpreting the other's
internals. That is the composition point.

---

## Conformance (x402 settlement-receipt binding, `elara` rail)

The composition point above is no longer hypothetical: the x402
settlement-receipt binding extension
([x402-foundation/x402#2666](https://github.com/x402-foundation/x402/pull/2666))
specifies a content-addressed join between a settlement and a receipt, with
committed conformance vectors and an independent checker (stdlib + JCS + ES256,
imports neither x402 nor any receipt framework) in
[vaaraio/vaara](https://github.com/vaaraio/vaara)
`tests/vectors/x402_settlement_v0/`.

[`conformance/x402-settlement-v0/`](conformance/x402-settlement-v0/) commits an
**`elara` rail in that suite's exact fixture format**, binding the upstream join
to this demo's authority leg — by content address in both directions, exactly as
the extension's three-legs framing advises:

- the action tuple's `scope` is the committed payment act's content address
  (`elara:act/sha3-256:23892d77…` — the same 32-byte record hash the seam
  section describes), and `timestampMs` is the act's own signed timestamp;
- the receipt's `backLink.attestationDigest` is `sha256` over the committed
  offline envelope (`envelopes/envelope.payment.json`) — the classical receipt
  chains back to the post-quantum (ML-DSA) mandate attestation;
- `actionRef` and `evidenceRef` recompute per the upstream math, unchanged.

Two commands, runnable by a stranger from the repo root:

```bash
# 1. The UPSTREAM checker (vendored byte-identical, sha256-pinned; the runner
#    refuses to start if the copy drifted) consumes the elara rail unmodified:
pip install rfc8785 cryptography
python3 conformance/x402-settlement-v0/run_elara.py     # exit 0, all verdicts OK

# 2. The Rust verifier re-derives the digest that scope commits to, and
#    verifies the PQ envelope the backLink chains to — fully offline:
cargo run -p x402-work-receipt -- action-ref --act envelopes/act.payment.json
cargo run -p x402-work-receipt -- verify --envelope envelopes/envelope.payment.json
```

Both directions were verified before committing: the upstream suite reproduces
at its pinned tree (`python tests/vectors/x402_settlement_v0/_check_independent.py`
→ exit 0, all 14 verdicts), and the `elara` rail passes the same checker file.

**Upstream pin — by content, not by ref.** #2666 pins `vaaraio/vaara` tag
`v1.1.1` at commit `088a869`. As of 2026-07-24 that SHA is orphaned: the tag
resolves to `719827c` (same message, same committer timestamp — a metadata-only
rewrite, re-tagged). The **trees are identical** (`c25f5fca…`), so the vectors
#2666 verified are byte-for-byte the vectors the tag serves today — the content
survived; the ref did not. That is this repo's whole thesis in one accident, so
our pin names the content: tree `c25f5fcac8d965d0a90021ce97fca54468961fe7`,
checker blob `06697860273c7e585b75550856ca31193b8a1e3d`, file sha256 in
[`CHECKER.sha256`](conformance/x402-settlement-v0/CHECKER.sha256).

Two deliberate differences from the upstream corpus, both documented in the
fixtures' generator (`_generate.py`):

- **The ES256 test private key is published** (`keys/es256_private.TEST-ONLY.pem`).
  Upstream commits only the public key, so only the vector owner can mint new
  passing receipts; this rail is re-mintable by anyone. The key signs nothing
  but these fixtures.
- **No risk-score fields.** The mandate verdict is deterministic — signatures
  and the authority chain either verify or they do not — so `decisionDerived`
  asserts no `riskScore`/thresholds. The checker digests the blocks as given.

---

## Architecture (a deliberate license + capability split)

The demo mirrors the real protocol's node/verifier split:

| Crate | License | Role |
|---|---|---|
| `crates/elara-mint` | **AGPL-3.0-only** | The one-time mint **+** act signer. The *only* piece that can generate a keypair or sign — because signing is a node-side capability **by design** (a verifier that could forge what it checks would be worthless). Links the AGPL Elara node. |
| `crates/x402-work-receipt` | **MIT OR Apache-2.0** | The reusable half: assemble the offline envelope, verify it, re-derive the `action_ref`. Depends **only** on `elara-record` + `elara-verify` (both MIT/Apache). No AGPL, no signing. |
| `apps/paywalled-resource` | MIT/Apache | An x402-axum server (Base Sepolia USDC). |
| `apps/paying-agent` | MIT/Apache | The paying agent. Delegates the one signing step to `elara-mint` by **subprocess**, so it carries no AGPL obligation. |

The agent's identities are **dedicated, throwaway demo keys**, minted fresh by
`scripts/mint.sh` — never a production maintainer identity. Secret-key material is
git-ignored; only signed, public artifacts are committed.

The verdict core (`evaluate_mandate_bundle`) is the **exact pure function** the
live node's `GET /mandate/status` endpoint calls, so the offline answer can never
drift from the on-node answer.

---

## Why x402-rs (and not the official TS SDK)

The audited decision was "x402-rs first, official SDK fallback — decide in-repo
and say so." **We use x402-rs** (`x402-axum` / `x402-reqwest` v2.0.2, community-
maintained, last updated 2026-07-13):

- Elara's verifier crates (`elara-record`, `elara-verify`) are **Rust**. A Rust
  payment client composes with them in-process — no FFI, no second runtime, one
  toolchain.
- The official SDKs (TypeScript / Python / Go / Java) would put a language
  boundary between the payment step and the receipt step for no benefit here.
- x402-rs speaks x402 **protocol v2** against any compatible facilitator and the
  same Base Sepolia USDC path the official stack uses.

If x402-rs had been unavailable we would have shelled the TS SDK from the agent;
it was available and maintained, so the demo stays single-language.

---

## Real Base Sepolia settlement (best-effort)

The `$0` path is real: the [Circle testnet USDC faucet](https://faucet.circle.com/)
(Base Sepolia, no account) funds a wallet, and a fee-free facilitator settles.
The live client is **opt-in** behind the `live-x402` feature — the default build
is SIM, so the quickstart needs no wallet and none of the heavy Ethereum stack.
For a **LIVE** run:

```bash
# Terminal A — the x402 resource server:
cargo run -p paywalled-resource

# Terminal B — the agent, compiled with the real Base Sepolia client:
export X402_PAY_TO=0xYourReceivingAddress            # server: where USDC lands
export X402_AGENT_PRIVATE_KEY=0xYourFundedTestKey    # agent: a funded Base Sepolia wallet
# (optional) export X402_FACILITATOR=https://facilitator.x402.rs
cargo run -p paying-agent --features live-x402
```

Funding the demo wallet at the faucet is the **one manual step** (the faucet is
interactive; this repo does not automate account-gated services). The live client
path is **compile-verified** here; the 402 challenge, the EIP-3009 payment
authorization, settlement via the facilitator, and the receipt are wired
end-to-end, but an actual on-chain settlement is yours to run with a funded key.
When the wallet is funded, the agent binds the **real settlement tx hash** into
the act; when it is not, it records `settled: false` and still produces the
authority receipt. **The thesis does not depend on settlement completing** — it
certifies authority-to-act, which is exactly the property settlement alone cannot
give you.

---

## Honest claims

- **Scale.** Elara is *designed for* a large mesh; this demo runs against a
  **small, self-hosted testnet**. "10T records/day" and similar are design
  targets, never claims about this demo.
- **`CONSISTENT` ≠ `AUTHORIZED`.** The offline envelope proves the carrier
  signatures and authority-at-signing **given the records in the bundle**. It does
  not prove on-ledger existence, sealing, or time-anchoring, and cannot detect a
  *withheld* revocation. For the stronger claim, query a node's `/mandate/status`
  or run `elara-verify --seal --anchor`.
- **Offline is the demonstrated path on purpose.** Elara's live hot tier is
  garbage-collected, so a demo act's live route ages out. The **offline envelope**
  is self-contained and permanent — which is precisely the thesis, so the demo
  leans on it rather than on live routes.
- **v0 scope.** The mandate layer enforces agent identity + validity window +
  revocation (the *who* and the *when*). Op/zone/amount scope is *recorded* but not
  yet enforced offline; the demo never claims a scope check it does not perform.
- **x402 precision.** x402's core `SettleResponse` is a tx hash (no facilitator
  signature); signed settlement receipts are an optional resource-server
  extension. We never claim "x402 has no receipt" — only that none of the existing
  receipts cover **non-payment** acts.

---

## Prior art referenced (all real, all payment-scoped)

- **[#2357](https://github.com/x402-foundation/x402/issues/2357)** — STARK receipt
  extension (proof of *payment conditions*, offline) + the IETF individual
  submission **`draft-vauban-x402-stark-receipts-02`** (liaison
  **[#2428](https://github.com/x402-foundation/x402/issues/2428)**). Source of the
  `action_ref` "work layer" seam this demo plugs into.
- **[#2740](https://github.com/x402-foundation/x402/issues/2740)** — Bitcoin-
  anchored provenance receipt (payment / settlement).
- **[#2664](https://github.com/x402-foundation/x402/issues/2664)** — PQC extension
  roadmap (ML-DSA-65) for payment auth.
- **[#2650](https://github.com/x402-foundation/x402/issues/2650)** — asks for a
  pattern binding settlement to an off-chain signed execution receipt: the natural
  host thread for this work.

## License

Split by design — see the table above. `elara-mint` is AGPL-3.0-only; everything
reusable (`x402-work-receipt` and the apps) is MIT OR Apache-2.0.
