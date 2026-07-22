//! elara-mint — the ONE-TIME AGPL touch in this demo.
//!
//! Signing is a node-side capability in Elara BY DESIGN: `elara-record` and
//! `elara-verify` are signing-incapable (a verifier that could forge what it
//! checks would be worthless). So the two acts that require a private key —
//! (1) minting the demo's dedicated principal + agent identities and issuing the
//! mandate, and (2) signing each agent act — live here, in the one crate that
//! links the AGPL node. Everything downstream (assembling the offline envelope,
//! verifying it) is done by the permissive `x402-work-receipt` crate.
//!
//! The identities minted here are DEDICATED, throwaway demo keys. They are NEVER
//! the production maintainer identity. The secret-bearing JSON is written to
//! `fixtures/` and git-ignored; only the signed, public mandate carrier record is
//! committed.
//!
//! Subcommands:
//!   provision   generate principal + agent, issue the mandate, write fixtures
//!   sign-act    sign one agent act referencing the mandate; print its 32-byte
//!               action_ref (== the record hash, an x402 STARK-receipt-compatible
//!               opaque handle for the work layer)
//!   revoke      sign a principal revocation of the mandate (for the NOT-AUTHORIZED
//!               demonstration path)

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use elara_runtime::identity::{CryptoProfile, EntityType, Identity};
use elara_runtime::mandate::{
    MandateRecord, MandateScope, RevocationRecord, MANDATE_OP_KEY, MANDATE_REF_METADATA_KEY,
    MANDATE_REVOCATION_OP_KEY,
};
use elara_runtime::record::{Classification, ValidationRecord};
use serde::Serialize;
use serde_json::{json, Value};

/// The demo network id. `ValidationRecord` carries no network field; the judged
/// network is taken from the leaf mandate's own signed `network_id` (see
/// `mandate_bundle`), so this value is self-consistent within the demo.
const NETWORK: &str = "testnet";
/// A wide, FIXED validity window (2023-11-14 .. 2033-05-18, unix ms) so an act
/// signed at real wall-clock "now" always falls inside it. Honest-claims: this is
/// a demo mandate window, not a production SLA.
const WINDOW_OPEN_MS: u64 = 1_700_000_000_000;
const WINDOW_CLOSE_MS: u64 = 2_000_000_000_000;
/// Fixed nonce — re-authorizing is always a NEW mandate, never an un-revoke.
const MANDATE_NONCE: &str = "x402-elara-demo-root-0001";
/// The op this mandate scopes the agent to. v0 RECORDS op/zone scope but enforces
/// only identity + window + revocation; the README says so without overclaiming.
const SCOPE_OP: &str = "x402_payment";

#[derive(Parser)]
#[command(name = "elara-mint", about = "One-time AGPL mint + act signer (x402 × Elara demo)")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate the dedicated principal + agent identities and issue the mandate.
    Provision {
        /// Directory to write fixtures into.
        #[arg(long, default_value = "fixtures")]
        out: PathBuf,
    },
    /// Sign one agent act referencing the mandate. Prints the 32-byte action_ref.
    SignAct {
        /// Path to the agent identity JSON (from `provision`).
        #[arg(long, default_value = "fixtures/agent.identity.json")]
        agent: PathBuf,
        /// The mandate_id the act is performed under (from `provision`).
        #[arg(long)]
        mandate_ref: String,
        /// The x402 payment facts to bind into the act, as a JSON object
        /// (e.g. `{"tx_hash":"0x..","amount":"0.001","asset":"USDC","network":"base-sepolia","resource":"/report"}`).
        #[arg(long, default_value = "{}")]
        payload_json: String,
        /// Where to write the signed act record (ValidationRecord JSON).
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a principal revocation of the mandate (NOT-AUTHORIZED demo path).
    Revoke {
        #[arg(long, default_value = "fixtures/principal.identity.json")]
        principal: PathBuf,
        #[arg(long)]
        mandate_ref: String,
        #[arg(long, default_value = "agent key rotation")]
        reason: String,
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Provision { out } => provision(&out),
        Cmd::SignAct { agent, mandate_ref, payload_json, out } => {
            sign_act(&agent, &mandate_ref, &payload_json, &out)
        }
        Cmd::Revoke { principal, mandate_ref, reason, out } => {
            revoke(&principal, &mandate_ref, &reason, &out)
        }
    }
}

/// Real wall-clock seconds. The act's timestamp is honest — the agent really
/// acted at this instant — and 2026-07 sits inside the fixed window above.
fn ts_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(1_700_000_100.0)
}

/// Build a REAL signed carrier record. `ts_secs` is applied BEFORE signing (the
/// timestamp is inside `signable_bytes()`), then the signature is re-verified —
/// mirroring the node's ingest path so a fixture can never be silently unsigned.
fn signed_record(
    signer: &Identity,
    content: &[u8],
    meta: BTreeMap<String, Value>,
    ts_secs: f64,
) -> Result<ValidationRecord> {
    let mut rec = ValidationRecord::create(
        content,
        signer.public_key.clone(),
        vec![],
        Classification::Public,
        Some(meta),
    );
    rec.timestamp = ts_secs;
    signer
        .sign_record(&mut rec)
        .map_err(|e| anyhow!("sign carrier record: {e}"))?;
    let sig = rec.signature.as_ref().ok_or_else(|| anyhow!("record is unsigned after sign"))?;
    let ok = Identity::verify(&rec.signable_bytes(), sig, &rec.creator_public_key)
        .map_err(|e| anyhow!("verify call: {e}"))?;
    if !ok {
        return Err(anyhow!("carrier signature failed to verify over canonical bytes"));
    }
    Ok(rec)
}

fn provision(out: &Path) -> Result<()> {
    std::fs::create_dir_all(out).with_context(|| format!("create {}", out.display()))?;

    let principal = Identity::generate(EntityType::Human, CryptoProfile::ProfileB)
        .map_err(|e| anyhow!("keygen principal: {e}"))?;
    let agent = Identity::generate(EntityType::Ai, CryptoProfile::ProfileB)
        .map_err(|e| anyhow!("keygen agent: {e}"))?;

    let scope = MandateScope {
        allowed_ops: vec![SCOPE_OP.to_string()],
        allowed_zones: vec!["*".to_string()],
        max_amount: None,
    };
    let m = MandateRecord::new_root(
        NETWORK,
        &principal.identity_hash,
        &agent.identity_hash,
        scope,
        WINDOW_OPEN_MS,
        WINDOW_CLOSE_MS,
        0, // sub_delegation_max_depth
        MANDATE_NONCE,
    );
    if !m.is_well_formed() {
        return Err(anyhow!("minted mandate is not well-formed"));
    }
    let mandate_id = m.mandate_id();

    // Wrap the mandate in a carrier record signed by the PRINCIPAL. The carrier
    // signature IS the principal's signature over the mandate (ingest binding:
    // sha3(carrier creator pk) == principal_identity_hash).
    let mut issue_meta = BTreeMap::new();
    issue_meta.insert(MANDATE_OP_KEY.to_string(), serde_json::to_value(&m)?);
    let carrier = signed_record(&principal, b"x402-elara-mandate-issue", issue_meta, ts_now())?;
    let carrier_principal = elara_runtime::crypto::hash::sha3_256_hex(&carrier.creator_public_key);
    if carrier_principal != principal.identity_hash {
        return Err(anyhow!("principal-binding invariant failed"));
    }

    // Persist. Secret-bearing identities are git-ignored; the signed public
    // mandate carrier + a public meta summary are committed.
    write_json(&out.join("agent.identity.json"), &agent.to_json())?;
    write_json(&out.join("principal.identity.json"), &principal.to_json())?;
    write_json(&out.join("mandate.carrier.json"), &carrier)?;
    write_json(
        &out.join("mandate.meta.json"),
        &json!({
            "network": NETWORK,
            "mandate_id": mandate_id,
            "principal_identity_hash": principal.identity_hash,
            "agent_identity_hash": agent.identity_hash,
            "scope_ops": [SCOPE_OP],
            "scope_zones": ["*"],
            "window_open_ms": WINDOW_OPEN_MS,
            "window_close_ms": WINDOW_CLOSE_MS,
            "nonce": MANDATE_NONCE,
            "_note": "v0 enforces agent identity + window + revocation; op/zone scope is recorded, not checked offline.",
        }),
    )?;

    eprintln!("provisioned dedicated demo identities + mandate (network={NETWORK}):");
    eprintln!("  principal : {}", &principal.identity_hash);
    eprintln!("  agent     : {}", &agent.identity_hash);
    eprintln!("  mandate_id: {mandate_id}");
    // stdout = just the mandate_id, so `MID=$(elara-mint provision)` works.
    println!("{mandate_id}");
    Ok(())
}

fn sign_act(agent_path: &Path, mandate_ref: &str, payload_json: &str, out: &Path) -> Result<()> {
    let agent = load_identity(agent_path)?;
    let payload: Value = serde_json::from_str(payload_json)
        .with_context(|| "payload_json must be valid JSON")?;

    // The act's CONTENT is the canonical x402 payment facts; the record's
    // content_hash therefore commits to the exact payment. The 32-byte action_ref
    // we surface is the RECORD hash (binds content + mandate_ref + signer + time).
    let content = serde_json::to_vec(&payload)?;

    let mut meta = BTreeMap::new();
    meta.insert(
        MANDATE_REF_METADATA_KEY.to_string(),
        Value::String(mandate_ref.to_string()),
    );
    meta.insert("op".to_string(), Value::String(SCOPE_OP.to_string()));
    meta.insert("x402_payment".to_string(), payload);

    let rec = signed_record(&agent, &content, meta, ts_now())?;
    let action_ref = rec.record_hash(); // 32 bytes, SHA3-256 of canonical record bytes

    write_json(out, &rec)?;
    eprintln!("signed act under mandate {mandate_ref}");
    eprintln!("  act record id : {}", rec.id);
    eprintln!("  signer (agent): {}", elara_runtime::crypto::hash::sha3_256_hex(&rec.creator_public_key));
    eprintln!("  action_ref    : {} (32-byte x402-STARK-receipt-compatible handle)", hex::encode(action_ref));
    // stdout = the action_ref hex only.
    println!("{}", hex::encode(action_ref));
    Ok(())
}

fn revoke(principal_path: &Path, mandate_ref: &str, reason: &str, out: &Path) -> Result<()> {
    let principal = load_identity(principal_path)?;
    let rev = RevocationRecord::new(NETWORK, mandate_ref.to_string(), reason.to_string());
    let mut meta = BTreeMap::new();
    meta.insert(MANDATE_REVOCATION_OP_KEY.to_string(), serde_json::to_value(&rev)?);
    let rec = signed_record(&principal, b"x402-elara-mandate-revoke", meta, ts_now())?;
    write_json(out, &rec)?;
    eprintln!("signed revocation of mandate {mandate_ref} by principal (reason: {reason})");
    println!("{}", rec.id);
    Ok(())
}

fn load_identity(path: &Path) -> Result<Identity> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let map: BTreeMap<String, Value> =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;
    Identity::from_json(&map).map_err(|e| anyhow!("reconstruct identity from {}: {e}", path.display()))
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let s = serde_json::to_string_pretty(value)?;
    std::fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}
