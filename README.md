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
  offline envelope (`evidence/envelope.payment.json`) — the classical receipt
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
cargo run -p x402-work-receipt -- action-ref --act evidence/act.payment.json
cargo run -p x402-work-receipt -- verify --envelope evidence/envelope.payment.json
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

### ERC-8004 validation bridge (`conformance/erc8004-validation-v0/`)

The same authority leg, bridged to [ERC-8004](https://github.com/erc-8004/erc-8004-contracts)'s
Validation Registry — the "off-chain delegation chains anchoring to on-chain agent
identity" question its design discussion raises. The registry's `requestHash` /
`responseHash` are opaque `bytes32` content hashes with URI pointers; our fixtures
fill that shape so that **the validation response is not a score to trust but a
proof to recompute**:

- `requestHash` = NIST SHA3-256 over the committed offline envelope (the evidence);
- `responseHash` = NIST SHA3-256 over the committed verifier verdict JSON;
- `response` uses only the deterministic endpoints — **100** iff the offline
  verifier returns ✓ CONSISTENT, **0** iff ✗ NOT AUTHORIZED (the post-revocation
  counter-case is a committed fixture pair, not a footnote);
- no chain interaction on our side: the fixtures show the join, and anyone
  re-derives every hash and the verdict itself from this repo alone.

```bash
# 1. Recompute every fixture claim from committed files (stdlib only):
python3 conformance/erc8004-validation-v0/run_bridge.py   # exit 0, 14 checks

# 2. Re-derive the verdict the response content-addresses — fully offline:
cargo run -p x402-work-receipt -- verify --envelope evidence/envelope.payment.json
```

Two deliberate differences from the upstream corpus, both documented in the
fixtures' generator (`_generate.py`):

- **The ES256 test private key is published** (`keys/es256_private.TEST-ONLY.pem`).
  Upstream commits only the public key, so only the vector owner can mint new
  passing receipts; this rail is re-mintable by anyone. The key signs nothing
  but these fixtures.
- **No risk-score fields.** The mandate verdict is deterministic — signatures
  and the authority chain either verify or they do not — so `decisionDerived`
  asserts no `riskScore`/thresholds. The checker digests the blocks as given.

### MCP SEP-3004 evidence profile (`conformance/mcp-3004-audit-record-v0/`)

The same authority leg registered as an extension of the MCP **Tamper-Evident
Audit Record Contract** ([modelcontextprotocol#3004](https://github.com/modelcontextprotocol/modelcontextprotocol/pull/3004)),
whose thread names the seam precisely: the record core answers *"is this audit
history internally intact"*, and a registered extension commits to its own
guarantee under its own profile identifier.

The SEP's reference verifier is vendored byte-pinned and run **unmodified** over
our fixtures; the entire proposed change is one registry entry, and the runner
shows the same record rejected before it and accepted after. The demonstration
is a two-record chain — same agent, same mandate, same signed payload, 166 ms
apart, straddling the revocation:

- both records verify and thread under SEP-3004; every protected core field is
  identical except `event_id`, `occurred_at` and the chain link, so the contract
  alone **cannot** tell the authorized act from the post-revocation one;
- flip one bit of the evidence artifact and the chain still verifies perfectly —
  the evidence just stops resolving.

Neither property implies the other, which is the argument for the profile.

```bash
node --experimental-strip-types \
  conformance/mcp-3004-audit-record-v0/vendor/run_reference.ts   # 8 reference checks
python3 conformance/mcp-3004-audit-record-v0/run_mcp3004.py      # 8 evidence checks
```

`canon.py` is an independent second-language reproduction of the SEP's canonical
form, written from the spec text; the runner asserts it agrees with the vendored
TypeScript on every fixture and that both still reproduce the SEP's published
known-answer digests. The three-extension composition record
(`caller-governance` + `runtime-security` + `authority-evidence` under one
digest) yields a new known-answer value reproducible with stock `sha256sum`.
Proposal only — the SEP's authors own the registry; see the
[directory README](conformance/mcp-3004-audit-record-v0/README.md) for the
registration shape and the honest claims.

---

## Conformance (ERC-8004 validation entry, offline-recomputable evidence)

The same work-layer receipt composes with the on-chain agent registries too.
[ERC-8004](https://github.com/erc-8004/erc-8004-contracts) (live on Ethereum
mainnet) gives agents identity / reputation / **validation** registries; its
open design thread [#77 *"Off-chain delegation chains bridging to ERC-8004"*](https://github.com/erc-8004/erc-8004-contracts/issues/77)
asks what the *off-chain* authority half looks like. This is that half.

ERC-8004's Validation Registry records a validation as
`validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)`
(`contracts/ValidationRegistryUpgradeable.sol`): `requestURI` points at off-chain
data, and `requestHash` is that data's content hash — an **opaque `bytes32`
mapping key the registry never recomputes on-chain**. So the entry is only as
trustworthy as whatever fills that field.
[`conformance/erc-8004-validation-v0/`](conformance/erc-8004-validation-v0/)
fills it with an Elara mandate envelope, content-addressed and
offline-recomputable:

- the off-chain data is a **post-quantum, revocation-aware mandate envelope**
  (`examples/envelope.*.example.json`), and `requestHash` is **SHA-256 over its
  bytes** — the *same* content-address this demo's x402 receipt back-links to, so
  one published envelope anchors both registries;
- anyone recomputes the digest and re-verifies the envelope **fully offline** with
  the signing-incapable MIT/Apache verifier — no scorer to trust, exactly the
  *"a proof to recompute, not a signature to trust"* limit case #77 converged on;
- `entry.postrevoke.json` references an act signed **after** the mandate was
  revoked → **NOT AUTHORIZED**: a revocation lifecycle the classical
  off-chain-delegation sketch lacks (alongside PQ signatures over its Ed25519).

We compose, we do not compete: this is the off-chain work-layer a Validation
Registry entry *points to*, not a competing chain — no chain interaction happens
on our side.

Two commands, runnable by a stranger from the repo root (anchored to the
committed `examples/`, so they reproduce from a bare clone — no secrets, no mint):

```bash
# 1. Recompute each entry's requestHash from the committed envelope bytes and
#    check it against the entries + expected.json (Python stdlib only; also runs
#    the offline verify leg if x402-work-receipt is already built):
python3 conformance/erc-8004-validation-v0/run_erc8004.py     # exit 0

# 2. Verify the referenced envelopes offline:
cargo run -p x402-work-receipt -- verify --envelope examples/envelope.authorized.example.json   # ✓ CONSISTENT     (exit 0)
cargo run -p x402-work-receipt -- verify --envelope examples/envelope.postrevoke.example.json   # ✗ NOT AUTHORIZED (exit 1)
```

`requestHash` is SHA-256, not Solidity `keccak256` — ERC-8004's `bytes32` is
algorithm-agnostic (opaque to the registry), and an implementer preferring
keccak256 swaps one hash call; the join is identical. The on-chain identity and
the `response`/`responseHash` fields are illustrative (the validator's side); the
vector demonstrates the off-chain request side, which is ours. Details and full
honest-claims in [the vector's README](conformance/erc-8004-validation-v0/README.md).

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
