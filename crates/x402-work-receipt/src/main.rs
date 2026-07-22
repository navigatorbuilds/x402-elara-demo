//! x402-work-receipt CLI — assemble an offline envelope, verify it, or re-derive
//! an act's 32-byte action_ref. Permissive + verify-only (no signing, no AGPL).

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "x402-work-receipt", about = "Assemble + offline-verify an Elara work-layer receipt")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Assemble the offline envelope from a signed act + mandate carrier(s) [+ revocations].
    Assemble {
        #[arg(long)]
        act: PathBuf,
        #[arg(long = "mandate")]
        mandates: Vec<PathBuf>,
        #[arg(long = "revocation")]
        revocations: Vec<PathBuf>,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify an offline envelope. Exit 0 only on ✓ CONSISTENT.
    Verify {
        #[arg(long)]
        envelope: PathBuf,
        /// Also print the raw BundleVerdict JSON (the verifier's verbatim output).
        #[arg(long)]
        json: bool,
    },
    /// Re-derive the 32-byte action_ref for a signed act (SHA3-256 record hash).
    ActionRef {
        #[arg(long)]
        act: PathBuf,
    },
}

fn main() -> ExitCode {
    match Cli::parse().cmd {
        Cmd::Assemble { act, mandates, revocations, out } => {
            match run_assemble(&act, &mandates, &revocations, &out) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("assemble error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Cmd::Verify { envelope, json } => run_verify(&envelope, json),
        Cmd::ActionRef { act } => match std::fs::read_to_string(&act)
            .map_err(|e| e.to_string())
            .and_then(|s| x402_work_receipt::action_ref(&s))
        {
            Ok(ar) => {
                println!("{}", hex::encode(ar));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("action-ref error: {e}");
                ExitCode::FAILURE
            }
        },
    }
}

fn run_assemble(
    act: &PathBuf,
    mandates: &[PathBuf],
    revocations: &[PathBuf],
    out: &PathBuf,
) -> Result<(), String> {
    let act_json = std::fs::read_to_string(act).map_err(|e| format!("read act: {e}"))?;
    let mandate_jsons = read_all(mandates)?;
    let revocation_jsons = read_all(revocations)?;
    let envelope = x402_work_receipt::assemble_envelope(&act_json, &mandate_jsons, &revocation_jsons)?;
    std::fs::write(out, &envelope).map_err(|e| format!("write envelope: {e}"))?;
    eprintln!("wrote offline envelope: {}", out.display());
    Ok(())
}

fn read_all(paths: &[PathBuf]) -> Result<Vec<String>, String> {
    paths
        .iter()
        .map(|p| std::fs::read_to_string(p).map_err(|e| format!("read {}: {e}", p.display())))
        .collect()
}

fn run_verify(envelope: &PathBuf, json: bool) -> ExitCode {
    let envelope_json = match std::fs::read_to_string(envelope) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("read envelope: {e}");
            return ExitCode::FAILURE;
        }
    };
    let verdict = x402_work_receipt::verify(&envelope_json);
    print!("{}", x402_work_receipt::render_human(&verdict));
    if json {
        match serde_json::to_string_pretty(&verdict) {
            Ok(s) => println!("\n--- raw BundleVerdict (verbatim) ---\n{s}"),
            Err(e) => eprintln!("(could not render raw verdict JSON: {e})"),
        }
    }
    // Exit 0 ONLY on the authorizing green. Everything else is a non-zero exit so
    // the demo script fails loudly if a verdict ever regresses.
    if verdict.authorized {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
