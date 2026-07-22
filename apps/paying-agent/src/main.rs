//! The autonomous paying agent.
//!
//! 1. Pays for an x402-protected resource on Base Sepolia (real USDC settlement
//!    via the facilitator) — or, with no funded key, runs a clearly-labelled
//!    SIMULATED payment so the full pipeline is runnable by anyone.
//! 2. Turns the payment act into an Elara work-receipt: it delegates the single
//!    SIGNING step to the AGPL `elara-mint` binary (subprocess), then assembles
//!    the offline envelope and verifies it with the permissive verifier.
//!
//! The receipt answers what a tx hash cannot: was THIS agent AUTHORIZED (by a
//! revocable, post-quantum mandate) to make this payment, at the time it did?
//!
//! Config (env):
//!   RESOURCE_URL           the x402 resource (default: http://127.0.0.1:4021/premium-report)
//!   X402_AGENT_PRIVATE_KEY EVM private key of a FUNDED Base Sepolia wallet →
//!                          LIVE mode. Unset → SIMULATED mode.
//!   X402_FACILITATOR       facilitator URL (recorded into the receipt; default x402.rs)
//!   ELARA_MINT_BIN         path to elara-mint (default: ./target/debug/elara-mint)
//!   MANDATE_META           fixtures/mandate.meta.json (default)
//!   MANDATE_CARRIER        fixtures/mandate.carrier.json (default)
//!   AGENT_IDENTITY         fixtures/agent.identity.json (default)

use std::path::PathBuf;
use std::process::Command;

use anyhow::{anyhow, Context, Result};

const DEFAULT_FACILITATOR: &str = "https://facilitator.x402.rs";

#[tokio::main]
async fn main() -> Result<()> {
    let resource_url = std::env::var("RESOURCE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:4021/premium-report".into());
    let facilitator =
        std::env::var("X402_FACILITATOR").unwrap_or_else(|_| DEFAULT_FACILITATOR.into());
    let mint_bin =
        std::env::var("ELARA_MINT_BIN").unwrap_or_else(|_| "./target/debug/elara-mint".into());
    let mandate_meta =
        std::env::var("MANDATE_META").unwrap_or_else(|_| "fixtures/mandate.meta.json".into());
    let mandate_carrier =
        std::env::var("MANDATE_CARRIER").unwrap_or_else(|_| "fixtures/mandate.carrier.json".into());
    let agent_identity =
        std::env::var("AGENT_IDENTITY").unwrap_or_else(|_| "fixtures/agent.identity.json".into());

    let mandate_id = read_mandate_id(&mandate_meta)?;
    println!("agent: paying for {resource_url}");
    println!("agent: acting under mandate {mandate_id}");

    // ── 1. Pay (LIVE if a funded key is present + the live-x402 feature is on,
    //        else SIMULATED) ─────────────────────────────────────────────────
    let outcome = match std::env::var("X402_AGENT_PRIVATE_KEY") {
        Ok(key) if !key.trim().is_empty() => {
            pay_or_note(&resource_url, &facilitator, key.trim()).await
        }
        _ => {
            eprintln!(
                "agent: X402_AGENT_PRIVATE_KEY not set → SIMULATED payment \
                 (fund a Base Sepolia wallet via the Circle faucet for a real tx)"
            );
            Ok(simulated_outcome(&resource_url, &facilitator))
        }
    };
    let facts = match outcome {
        Ok(f) => f,
        Err(e) => {
            // A live payment failure (e.g. unfunded wallet) is NOT fatal to the
            // thesis: we still mint an honest receipt recording settled=false.
            eprintln!("agent: live payment did not settle: {e:#}");
            failed_outcome(&resource_url, &facilitator, &format!("{e:#}"))
        }
    };
    println!(
        "agent: payment {} (mode={}, tx={})",
        if facts["settled"].as_bool().unwrap_or(false) { "SETTLED" } else { "NOT settled" },
        facts["mode"].as_str().unwrap_or("?"),
        facts["tx_hash"].as_str().unwrap_or("none"),
    );

    // ── 2. Sign the act (AGPL elara-mint subprocess) ────────────────────────
    std::fs::create_dir_all("envelopes").ok();
    let act_out = PathBuf::from("envelopes/act.payment.json");
    let action_ref = sign_act(&mint_bin, &agent_identity, &mandate_id, &facts, &act_out)?;
    println!("agent: signed act, action_ref = {action_ref}");

    // ── 3. Assemble the offline envelope + verify (permissive) ──────────────
    let act_json = std::fs::read_to_string(&act_out)?;
    let carrier_json = std::fs::read_to_string(&mandate_carrier)
        .with_context(|| format!("read {mandate_carrier}"))?;
    let envelope = x402_work_receipt::assemble_envelope(&act_json, &[carrier_json], &[])
        .map_err(|e| anyhow!("assemble envelope: {e}"))?;
    let env_out = "envelopes/envelope.payment.json";
    std::fs::write(env_out, &envelope)?;
    println!("agent: wrote offline envelope {env_out}\n");

    let verdict = x402_work_receipt::verify(&envelope);
    println!("{}", x402_work_receipt::render_human(&verdict));

    if verdict.authorized {
        println!("\nagent: ✓ this payment act is an authorized, offline-verifiable Elara work-receipt.");
        Ok(())
    } else {
        Err(anyhow!("receipt did not verify as authorized: {}", verdict.flag))
    }
}

fn read_mandate_id(path: &str) -> Result<String> {
    let meta: serde_json::Value = serde_json::from_slice(
        &std::fs::read(path).with_context(|| format!("read {path} (run scripts/mint.sh first)"))?,
    )?;
    meta.get("mandate_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("{path} has no mandate_id"))
}

/// Dispatch to the real client when built with `--features live-x402`; otherwise
/// note the upstream blocker and fall back to a labelled simulated outcome.
#[cfg(feature = "live-x402")]
async fn pay_or_note(resource_url: &str, facilitator: &str, key: &str) -> Result<serde_json::Value> {
    pay_live(resource_url, facilitator, key).await
}

#[cfg(not(feature = "live-x402"))]
async fn pay_or_note(resource_url: &str, facilitator: &str, _key: &str) -> Result<serde_json::Value> {
    eprintln!(
        "agent: a key is set, but this is a SIM-only build (no `live-x402` \
         feature) → SIMULATED payment. Rebuild with `--features live-x402` to \
         compile the real Base Sepolia client and settle on-chain."
    );
    Ok(simulated_outcome(resource_url, facilitator))
}

/// Real x402 payment: register the EIP-155 exact scheme with a wallet signer and
/// let the middleware auto-handle the 402 → sign → settle flow.
#[cfg(feature = "live-x402")]
async fn pay_live(resource_url: &str, facilitator: &str, key: &str) -> Result<serde_json::Value> {
    use std::sync::Arc;

    use alloy_signer_local::PrivateKeySigner;
    use reqwest::Client;
    use x402_chain_eip155::V1Eip155ExactClient;
    use x402_reqwest::{ReqwestWithPayments, ReqwestWithPaymentsBuild, X402Client};

    let signer = Arc::new(
        key.parse::<PrivateKeySigner>()
            .map_err(|e| anyhow!("invalid X402_AGENT_PRIVATE_KEY: {e}"))?,
    );
    let payer = format!("{:?}", alloy_signer_local::PrivateKeySigner::address(&signer));
    let x402_client = X402Client::new().register(V1Eip155ExactClient::new(signer));
    let http = Client::new().with_payments(x402_client).build();

    let resp = http
        .get(resource_url)
        .send()
        .await
        .map_err(|e| anyhow!("x402 request failed: {e}"))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::json!({}));
    if !status.is_success() {
        return Err(anyhow!("resource returned {status}; body={body}"));
    }

    // The server echoes the SettleResponse in `x402_settlement`.
    let settlement = body.get("x402_settlement").cloned().unwrap_or(serde_json::Value::Null);
    let tx = settlement.get("transaction").and_then(|v| v.as_str());
    let net = settlement
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("base-sepolia");
    Ok(serde_json::json!({
        "mode": "live",
        "settled": tx.is_some(),
        "resource": resource_url,
        "asset": "USDC",
        "amount": "0.001",
        "network": net,
        "payer": payer,
        "tx_hash": tx,
        "facilitator": facilitator,
        "note": "real x402 payment; settlement echoed by the resource server",
    }))
}

fn simulated_outcome(resource_url: &str, facilitator: &str) -> serde_json::Value {
    serde_json::json!({
        "mode": "simulated",
        "settled": false,
        "resource": resource_url,
        "asset": "USDC",
        "amount": "0.001",
        "network": "base-sepolia",
        "payer": null,
        "tx_hash": null,
        "facilitator": facilitator,
        "note": "SIMULATED payment (no funded wallet). The Elara receipt below is real and \
                 offline-verifiable regardless — it certifies AUTHORITY, not settlement.",
    })
}

fn failed_outcome(resource_url: &str, facilitator: &str, err: &str) -> serde_json::Value {
    serde_json::json!({
        "mode": "live",
        "settled": false,
        "resource": resource_url,
        "asset": "USDC",
        "amount": "0.001",
        "network": "base-sepolia",
        "payer": null,
        "tx_hash": null,
        "facilitator": facilitator,
        "note": format!("live payment attempted but did not settle: {err}"),
    })
}

/// Delegate the one signing step to the AGPL `elara-mint` binary. Its stdout is
/// the 32-byte action_ref (the record hash) in hex.
fn sign_act(
    mint_bin: &str,
    agent_identity: &str,
    mandate_id: &str,
    facts: &serde_json::Value,
    out: &PathBuf,
) -> Result<String> {
    let out_str = out.to_string_lossy().to_string();
    let output = Command::new(mint_bin)
        .args([
            "sign-act",
            "--agent",
            agent_identity,
            "--mandate-ref",
            mandate_id,
            "--payload-json",
            &facts.to_string(),
            "--out",
            &out_str,
        ])
        .output()
        .with_context(|| format!("run {mint_bin} sign-act (build it first: cargo build -p elara-mint)"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "elara-mint sign-act failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}
