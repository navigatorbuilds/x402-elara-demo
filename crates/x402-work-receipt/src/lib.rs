//! x402-work-receipt — the PERMISSIVE, verify-only half of the demo.
//!
//! Given a signed agent act (produced by the AGPL `elara-mint`) and the signed
//! mandate carrier, this crate:
//!   1. assembles the offline **envelope** (the mandate bundle), and
//!   2. verifies it fully offline via `elara_verify::mandate_bundle`,
//!   3. and re-derives the 32-byte **action_ref** the mint printed — proving a
//!      consumer needs only `elara-record` to reproduce it.
//!
//! It depends ONLY on `elara-record` + `elara-verify` (MIT OR Apache-2.0) and
//! carries NO signing capability. The verdict it renders is the EXACT output of
//! the same pure verdict core the live node's `GET /mandate/status` calls, so the
//! offline answer can never drift from the on-node answer — with the honest scope
//! caveats (a `✓ CONSISTENT` proves the carrier signatures + authority-at-signing
//! GIVEN THIS BUNDLE, not on-ledger existence) carried verbatim.

use elara_record::record::ValidationRecord;
pub use elara_verify::mandate_bundle::{
    evaluate_mandate_bundle, BundleVerdict, MANDATE_BUNDLE_VERSION,
};

/// Assemble the offline envelope (a mandate bundle) from a signed act, one or
/// more signed mandate carriers, and any signed revocations. Each input is the
/// JSON of a `ValidationRecord` as written by `elara-mint`. Returns the pretty
/// envelope JSON that [`verify`] (and the browser verifier) consume.
pub fn assemble_envelope(
    act_json: &str,
    mandate_carrier_jsons: &[String],
    revocation_jsons: &[String],
) -> Result<String, String> {
    let act: serde_json::Value =
        serde_json::from_str(act_json).map_err(|e| format!("act is not valid JSON: {e}"))?;
    let mandates = parse_all(mandate_carrier_jsons, "mandate carrier")?;
    let revocations = parse_all(revocation_jsons, "revocation")?;

    let envelope = serde_json::json!({
        "bundle_version": MANDATE_BUNDLE_VERSION,
        "act": act,
        "mandates": mandates,
        "revocations": revocations,
    });
    serde_json::to_string_pretty(&envelope).map_err(|e| format!("serialize envelope: {e}"))
}

fn parse_all(items: &[String], label: &str) -> Result<Vec<serde_json::Value>, String> {
    items
        .iter()
        .enumerate()
        .map(|(i, s)| {
            serde_json::from_str::<serde_json::Value>(s)
                .map_err(|e| format!("{label}[{i}] is not valid JSON: {e}"))
        })
        .collect()
}

/// Re-derive the 32-byte `action_ref` for an act — the SHA3-256 record hash,
/// recomputed by the permissive verifier with no help from the signer. This is
/// the opaque 32-byte handle a downstream x402 STARK receipt would carry in its
/// `action_ref` field (the STARK draft §8 leaves the preimage semantics to "the
/// work layer" — this IS that work layer).
pub fn action_ref(act_json: &str) -> Result<[u8; 32], String> {
    let rec: ValidationRecord =
        serde_json::from_str(act_json).map_err(|e| format!("act is not a ValidationRecord: {e}"))?;
    Ok(rec.record_hash())
}

/// Verify an offline envelope. Thin, honest pass-through to the audited pure core
/// — never panics; every malformed input surfaces as a `FAILED`/`NOT AUTHORIZED`
/// verdict with a reason.
pub fn verify(envelope_json: &str) -> BundleVerdict {
    evaluate_mandate_bundle(envelope_json)
}

/// Render a verdict as a human-readable block for the terminal / README. This is
/// a faithful transcription of the verifier's own `BundleVerdict` fields — it
/// adds no claim the verdict does not carry, and prints the soundness caveats in
/// full (dropping them would be lying on the verifier's behalf).
pub fn render_human(v: &BundleVerdict) -> String {
    let mut out = String::new();
    out.push_str(&format!("{} {}\n", v.glyph, v.verdict));
    out.push_str(&format!("  flag                : {}\n", v.flag));
    out.push_str(&format!("  authorized          : {}\n", v.authorized));
    out.push_str(&format!("  attributes to principal: {}\n", v.attributes_to_principal));
    out.push_str(&format!("  network             : {}\n", v.network));
    out.push_str(&format!("  signer (agent)      : {}\n", v.signer));
    match &v.principal {
        Some(p) => out.push_str(&format!("  principal           : {}\n", p)),
        None => out.push_str("  principal           : (not named — the flag does not attribute to a principal)\n"),
    }
    out.push_str(&format!("  act timestamp (ms)  : {}\n", v.act_timestamp_ms));
    out.push_str(&format!("  explanation         : {}\n", v.explanation));
    if !v.lineage.is_empty() {
        out.push_str("  lineage (leaf→root) :\n");
        for hop in &v.lineage {
            out.push_str(&format!(
                "      - {} (principal {} → agent {})\n",
                short(&hop.mandate_id),
                short(&hop.principal),
                short(&hop.agent),
            ));
        }
    }
    out.push_str(&format!("  scope note          : {}\n", v.scope_note));
    out.push_str("  checks:\n");
    for c in &v.checks {
        out.push_str(&format!("      [{}] {} — {}\n", c.status, c.name, c.detail));
    }
    out.push_str("  soundness caveats (what an offline envelope CANNOT prove):\n");
    for cav in &v.soundness_caveats {
        out.push_str(&format!("      • {}\n", cav));
    }
    out
}

fn short(s: &str) -> &str {
    &s[..s.len().min(16)]
}
