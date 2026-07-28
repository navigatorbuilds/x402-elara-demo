# ERC-8004 validation **bridge** vectors

> **Two similarly-named directories exist — this is deliberate, they are different artifacts:**
> - **`erc8004-validation-v0/` (this one)** — the *validation bridge*: fixtures showing how the
>   registry's `requestHash` / `responseHash` pair content-addresses an offline evidence envelope
>   and its recomputable verdict (14 checks over committed bytes).
> - **[`erc-8004-validation-v0/`](../erc-8004-validation-v0/)** (hyphenated) — the *validation-entry
>   vector*: the worked entry shape for the registry discussion
>   ([erc-8004/erc-8004-contracts#77](https://github.com/erc-8004/erc-8004-contracts/issues/77)),
>   with its own README.

The bridge fills ERC-8004's opaque `bytes32` slots so the validation response is **not a score to
trust but a proof to recompute**:

- `requestHash` = NIST SHA3-256 over the committed offline evidence envelope;
- `responseHash` = NIST SHA3-256 over the committed verifier verdict JSON;
- `response` uses only the deterministic endpoints — **100** iff the offline verifier returns
  ✓ CONSISTENT, **0** iff ✗ NOT AUTHORIZED (the post-revocation counter-case is a committed
  fixture pair, not a footnote);
- no chain interaction on our side: anyone re-derives every hash and the verdict itself from this
  repo alone.

## Run it

```bash
# Recompute every fixture claim from committed files (Python stdlib only):
python3 run_bridge.py            # exit 0, 14 checks

# Re-derive the verdict the response content-addresses — fully offline:
cargo run -p x402-work-receipt -- verify --envelope ../../evidence/envelope.payment.json
```

Fixtures: `fixtures/{authorized,postrevoke}/validation-{request,response}.json` plus the verdict
JSONs they content-address. Regenerate with `_generate.py` (deterministic).

Full context: the [repo README's bridge section](../../README.md#erc-8004-validation-bridge-conformanceerc8004-validation-v0).
