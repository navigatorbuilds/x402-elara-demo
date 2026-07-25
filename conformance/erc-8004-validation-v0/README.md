# ERC-8004 validation entry — offline-recomputable evidence

An [ERC-8004](https://github.com/erc-8004/erc-8004-contracts) Validation Registry
entry that **carries its own recomputable evidence**. ERC-8004's Validation
Registry records a validation as

```solidity
validationRequest(address validatorAddress, uint256 agentId, string requestURI, bytes32 requestHash)
```

— `requestURI` points at off-chain data and `requestHash` is that data's content
hash, stored as an **opaque `bytes32` mapping key the registry never recomputes
on-chain** (see `contracts/ValidationRegistryUpgradeable.sol`). This vector shows
the **join**: the off-chain data is a post-quantum, revocation-aware Elara mandate
envelope, and its `requestHash` is recomputable by anyone — so the registry entry
does not have to be taken on faith, and a signing-incapable verifier can confirm
the underlying authority **fully offline**.

We compose, we do not compete: ERC-8004's three registries handle
identity/reputation/validation **on-chain**; this is the off-chain work-layer a
Validation Registry entry can content-address. This is not a blockchain project —
no chain interaction happens on our side.

## What Elara brings that a classical off-chain-delegation sketch lacks
- **Post-quantum signatures** (FIPS 204 ML-DSA) — classical Ed25519 receipts are
  harvest-now-forge-later for long-horizon agent reputation.
- **Revocation lifecycle** — `entry.postrevoke.json` references an act signed
  *after* the principal revoked the mandate; the verdict is **NOT AUTHORIZED**.
- **Recomputable evidence** — the `bytes32` resolves to an envelope anyone
  re-hashes and re-verifies offline; no scorer to trust.

## Two commands a stranger can run (from the repo root)

```bash
# 1. Recompute the requestHash of each committed envelope and check it against
#    the entries + expected.json. Python standard library only; no secrets, no
#    mint step, no network. (If x402-work-receipt is already built, it also runs
#    the offline verify leg.)
python3 conformance/erc-8004-validation-v0/run_erc8004.py     # exit 0

# 2. Verify the referenced envelopes offline with the signing-incapable verifier:
cargo run -p x402-work-receipt -- verify --envelope examples/envelope.authorized.example.json   # ✓ CONSISTENT   (exit 0)
cargo run -p x402-work-receipt -- verify --envelope examples/envelope.postrevoke.example.json   # ✗ NOT AUTHORIZED (exit 1)
```

## Files
- `entry.authorized.json` / `entry.postrevoke.json` — off-chain views of an
  ERC-8004 validation entry; the flat fields mirror the contract's function args.
  Elara supplies `requestURI` + `requestHash`; the on-chain identity and the
  validator response are the registry's side (illustrative placeholders).
- `expected.json` — committed expected recomputations.
- `run_erc8004.py` — the stdlib-only checker.
- Anchored to the committed, self-contained `examples/envelope.*.example.json`
  (not the gitignored per-run `envelopes/`), so it reproduces from a bare clone.

## Honest claims
- `requestHash` is **SHA-256** over the envelope bytes — the same content-address
  this demo's x402 settlement receipt back-links to, so one published envelope
  anchors both registries. ERC-8004's `bytes32` is algorithm-agnostic (opaque
  to the registry); an implementer preferring Ethereum-native keccak256 swaps one
  hash call and the join is identical. We do **not** claim this equals a Solidity
  `keccak256(...)`.
- The on-chain `validatorAddress`/`agentId` and the `response`/`responseHash`
  fields are **illustrative** — the vector demonstrates the off-chain request
  side (Elara's contribution). `responseHash` is left `null` rather than pinning a
  hash of human-rendered verdict text.
- This is a working demo on a small self-hosted Elara testnet, not a production
  network. A ✓ CONSISTENT verdict proves the carrier signatures are valid and the
  authority held at the act's signed time **given only the records in the bundle**
  — it does not prove those records are sealed or time-anchored on a live ledger.
