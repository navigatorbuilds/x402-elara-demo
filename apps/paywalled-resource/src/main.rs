//! An x402-paywalled resource on Base Sepolia USDC.
//!
//! `GET /premium-report` is protected by the x402-axum middleware: without a
//! valid payment it returns `402 Payment Required` describing the price; with one
//! it settles via the facilitator and returns the report PLUS the settlement
//! result (tx hash / payer) in the body, so the paying agent can bind the
//! on-chain settlement into its Elara work-receipt.
//!
//! Config (env):
//!   X402_FACILITATOR  facilitator base URL (default: https://facilitator.x402.rs)
//!   X402_PAY_TO       EVM address that receives the USDC (required for LIVE)
//!   X402_PRICE        price in USDC (default: 0.001)
//!   PORT              listen port (default: 4021)

use axum::{extract::Extension, response::IntoResponse, routing::get, Json, Router};
use std::net::SocketAddr;
use x402_axum::X402Middleware;
use x402_chain_eip155::{KnownNetworkEip155, V1Eip155Exact};
use x402_types::networks::USDC;
use x402_types::proto::SettleResponse;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,x402_axum=info".into()),
        )
        .init();

    let facilitator =
        std::env::var("X402_FACILITATOR").unwrap_or_else(|_| "https://facilitator.x402.rs".into());
    // Default pay-to is a well-known burn-ish placeholder; LIVE runs MUST set
    // X402_PAY_TO to an address the operator controls to actually receive USDC.
    let pay_to_str = std::env::var("X402_PAY_TO")
        .unwrap_or_else(|_| "0x0000000000000000000000000000000000000001".into());
    let price = std::env::var("X402_PRICE").unwrap_or_else(|_| "0.001".into());
    let port: u16 = std::env::var("PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(4021);

    let pay_to = pay_to_str
        .parse::<alloy_primitives::Address>()
        .expect("X402_PAY_TO must be a valid EVM address");

    // x402 V1 "exact" scheme, Base Sepolia USDC. settle_before_execution so the
    // handler can read the SettleResponse (tx hash) and echo it to the payer.
    let x402 = X402Middleware::new(facilitator.as_str()).settle_before_execution();
    let price_tag = V1Eip155Exact::price_tag(
        pay_to,
        USDC::base_sepolia().parse(price.as_str()).expect("valid USDC price"),
    );

    let app = Router::new()
        .route("/premium-report", get(premium_report).layer(x402.with_price_tag(price_tag)))
        .route("/health", get(|| async { "ok" }));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!(%facilitator, pay_to = %pay_to_str, price = %price, %addr, "paywalled-resource up");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    axum::serve(listener, app).await.expect("serve");
}

/// The protected handler. By the time it runs (settle_before_execution), the
/// payment has settled; we surface the settlement result in the body so the
/// agent can bind the real Base Sepolia tx hash into its Elara act record.
async fn premium_report(
    Extension(settlement): Extension<Option<SettleResponse>>,
) -> impl IntoResponse {
    let settlement_json = settlement.map(|s| s.0);
    Json(serde_json::json!({
        "report": {
            "title": "Premium liveness report",
            "finding": "mesh nominal; 2 nodes reporting; 0 forks observed",
            "generated": "on demand, behind an x402 paywall",
        },
        "x402_settlement": settlement_json,
    }))
}
