#!/usr/bin/env python3
"""Dev-time generator for the `elara` rail of the x402 settlement-receipt
binding vectors (upstream suite: vaaraio/vaara tests/vectors/x402_settlement_v0).

Everything checkable is DERIVED, never typed in:

  scope          the content address of the committed, ML-DSA-signed payment act
                 (envelopes/act.payment.json): "elara:act/sha3-256:<hex>", where
                 <hex> is the 32-byte record hash the permissive Rust verifier
                 re-derives via `x402-work-receipt action-ref`. This is the
                 authority leg entering the settlement tuple as a
                 content-addressed reference — nothing more.
  timestampMs    the act's own signed timestamp, truncated to ms.
  actionRef      sha256 over the JCS-canonical six-key action tuple — the
                 upstream join-key math, reproduced bit-for-bit.
  evidenceRef    sha256 over the JCS-canonical settlement record.
  backLink       sha256 over the committed offline envelope file bytes
                 (envelopes/envelope.payment.json) — the receipt chains back to
                 the post-quantum attestation by content address.

The ES256 keypair is a PUBLISHED test key (keys/es256_private.TEST-ONLY.pem is
committed on purpose): unlike a corpus whose private key stays with the vector
owner, this rail is re-mintable by anyone, so the fixtures never have to be
taken on faith. The key signs nothing but these fixtures.

Run from the repo root:  python3 conformance/x402-settlement-v0/_generate.py
Requires: rfc8785, cryptography; and target/debug/x402-work-receipt (for the
act digest — `cargo build -p x402-work-receipt` first).
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import rfc8785
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
KEYS = HERE / "keys"
ACT = ROOT / "envelopes" / "act.payment.json"
ENVELOPE = ROOT / "envelopes" / "envelope.payment.json"
RECEIPT_BIN = ROOT / "target" / "debug" / "x402-work-receipt"

_ACTION_KEYS = ("agentId", "actionType", "scope", "timestampMs", "seq",
                "terminal")


def _jcs(obj) -> bytes:
    return rfc8785.dumps(obj)


def _sha256_hex(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def _load_or_mint_keys() -> ec.EllipticCurvePrivateKey:
    priv_path = KEYS / "es256_private.TEST-ONLY.pem"
    pub_path = KEYS / "es256_public.pem"
    if priv_path.exists():
        return serialization.load_pem_private_key(priv_path.read_bytes(),
                                                  password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    priv_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    pub_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def _act_digest_hex() -> str:
    if not RECEIPT_BIN.exists():
        sys.exit("build the verifier first: cargo build -p x402-work-receipt")
    out = subprocess.run([str(RECEIPT_BIN), "action-ref", "--act", str(ACT)],
                         capture_output=True, text=True, check=True)
    digest = out.stdout.strip().splitlines()[-1]
    if len(digest) != 64 or set(digest) - set("0123456789abcdef"):
        sys.exit(f"unexpected action-ref output: {digest!r}")
    return digest


def _sign(key: ec.EllipticCurvePrivateKey, payload: bytes) -> str:
    der = key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big").hex() + s.to_bytes(32, "big").hex()


def _write(path: Path, obj) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def main() -> None:
    key = _load_or_mint_keys()
    act = json.loads(ACT.read_text())
    agent_identity = json.loads(
        (ROOT / "fixtures" / "agent.identity.json").read_text())

    act_digest = _act_digest_hex()
    timestamp_ms = int(act["timestamp"] * 1000)
    decided_at = _dt.datetime.fromtimestamp(
        act["timestamp"], _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    agent_id = "agent:elara/" + agent_identity["identity_hash"]
    envelope_digest = _sha256_hex(ENVELOPE.read_bytes())
    payment_hash = "0x" + hashlib.sha256(
        b"elara:x402:demo:payment:INV-ELARA-1").hexdigest()

    for seq, terminal in ((0, False), (1, True)):
        action = {
            "agentId": agent_id,
            "actionType": "x402.payment",
            "scope": f"elara:act/sha3-256:{act_digest}",
            "timestampMs": timestamp_ms,
            "seq": seq,
            "terminal": terminal,
        }
        settlement = dict(action)
        settlement["actionRef"] = _sha256_hex(_jcs(
            {k: action[k] for k in _ACTION_KEYS}))
        settlement["paymentHash"] = payment_hash
        settlement["schema"] = "x402.settlement/v0"

        receipt = {
            "version": 1,
            "alg": "ES256",
            "backLink": {
                "attestationDigest": envelope_digest,
                "attestationNonce": f"x402-elara-{seq}",
            },
            "decisionDerived": {
                "decidedAt": decided_at,
                "decision": "allow",
                "evidenceRef": {
                    "canonicalization": "JCS",
                    "digest": _sha256_hex(_jcs(settlement)),
                    "ref": "x402:action_ref/" + settlement["actionRef"],
                    "schema": "x402.settlement/v0",
                },
                "policyId": "policy:elara-mandate-bundle/1",
                # The mandate verdict is deterministic (signature + authority
                # chain either verify or they do not), so there is no risk
                # score to assert — the receipt carries none.
                "reason": "offline mandate bundle verifies: agent was "
                          "authorized by the principal at act time "
                          "(x402-work-receipt: ✓ CONSISTENT)",
            },
            "issuerAsserted": {
                "alg": "ES256",
                "iat": decided_at,
                "iss": "issuer://elara-work-layer",
                "nonce": f"d-elara-{seq}",
                "secretVersion": "v1",
                "sub": agent_id,
            },
        }
        blocks = ("version", "alg", "backLink", "decisionDerived",
                  "issuerAsserted")
        receipt["signature"] = _sign(key, _jcs({k: receipt[k] for k in blocks}))

        step = HERE / "elara" / f"step{seq}"
        step.mkdir(parents=True, exist_ok=True)
        _write(step / "settlement.json", settlement)
        _write(step / "receipt.json", receipt)
        print(f"step{seq}: actionRef {settlement['actionRef']}")

    expected = {
        "elara": {
            "lifecycle_distinguishes_terminal": True,
            "step0": {
                "action_ref_recomputes": True,
                "receipt_signature_ok": True,
                "settlement_binding_resolves": True,
            },
            "step1": {
                "action_ref_recomputes": True,
                "receipt_signature_ok": True,
                "settlement_binding_resolves": True,
            },
        },
    }
    _write(HERE / "expected.json", expected)
    print(f"scope binds act digest sha3-256:{act_digest}")
    print(f"backLink binds envelope {envelope_digest}")


if __name__ == "__main__":
    main()
