#!/usr/bin/env python3
"""Witnessed-anchor vector — offline re-verification of a third-party transparency-log
anchor over this repo's committed mandate envelope. Python stdlib only.

Claim boundary (the log operator's own wording, carried in the leaf's `scope` field):
inclusion in a witnessed log proves *these bytes existed in a witnessed order*, and
nothing else. Authority and validity stay with the offline recompute over the committed
envelope — `conformance/erc-8004-validation-v0/run_erc8004.py` and the MIT/Apache
verifier — exactly where the other vectors put them.

What this recomputes from committed bytes, taking nothing on trust:

  1. SHA-256 over examples/envelope.authorized.example.json equals the request_hash
     inside the log leaf  (the anchor is over OUR bytes, not something adjacent)
  2. the committed leaf is byte-identical to the one the log serves, and its SHA-256
     matches the digest published alongside it
  3. the RFC 6962 inclusion proof folds leaf 6312 up to the published root at tree
     size 6322
  4. the live checkpoint carries a valid Ed25519 signature under the log's published
     vkey  (Ed25519 verification implemented here from RFC 8032 — no dependencies)
  5. the RFC 6962 consistency proof shows the size-6322 tree is a prefix of the
     signed size-6355 tree — i.e. nothing was rewritten under our leaf

Re-fetch the live artifacts and re-run to check the log against its own history:
  curl -s https://log.markovianprotocol.com/checkpoint
  curl -s "https://log.markovianprotocol.com/inclusion?leaf=6312&size=6322"
  curl -s "https://log.markovianprotocol.com/consistency?old=6322&new=6355"
  curl -s https://log.markovianprotocol.com/leaf/6312

Provenance: leaf appended by the log operator (MarkovianProtocol) at our request in
erc-8004/erc-8004-contracts#77; every artifact here was fetched from the endpoints above.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIX = HERE / "fixtures"
ROOT = HERE.parent.parent

LEAF_INDEX = 6312
PROOF_SIZE = 6322
ENVELOPE_REL = "examples/envelope.authorized.example.json"

ok = True


def check(label, cond, detail=""):
    global ok
    ok = ok and bool(cond)
    print(f"[{'OK' if cond else 'FAIL'}] {label}" + (f": {detail}" if detail else ""))


# ---------------------------------------------------------------- RFC 6962 hashing
def h_leaf(b):
    return hashlib.sha256(b"\x00" + b).digest()


def h_node(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def root_from_inclusion(leaf_hash, index, size, proof):
    """RFC 6962 s2.1.1."""
    if index >= size:
        raise ValueError("leaf index beyond tree size")
    fn, sn, r = index, size - 1, leaf_hash
    for sibling in proof:
        if sn == 0:
            raise ValueError("inclusion proof too long")
        if (fn & 1) or (fn == sn):
            r = h_node(sibling, r)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            r = h_node(r, sibling)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise ValueError("inclusion proof too short")
    return r


def consistent(first, second, proof, first_root, second_root):
    """RFC 6962 s2.1.2 — is the size-`first` tree a prefix of the size-`second` tree?"""
    if first > second:
        return False, "first > second"
    if first == second:
        return (not proof and first_root == second_root), "equal sizes"
    if first == 0:
        return (not proof), "empty first tree"
    p = list(proof)
    if first & (first - 1) == 0:            # exact power of two: old root is implicit
        p = [first_root] + p
    if not p:
        return False, "empty proof"
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = p[0]
    for c in p[1:]:
        if sn == 0:
            return False, "consistency proof too long"
        if (fn & 1) or (fn == sn):
            fr = h_node(c, fr)
            sr = h_node(c, sr)
            while fn != 0 and (fn & 1) == 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = h_node(sr, c)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        return False, "consistency proof too short"
    if fr != first_root:
        return False, "old root does not reproduce"
    if sr != second_root:
        return False, "new root does not reproduce"
    return True, "ok"


# ------------------------------------------------- Ed25519 verify (RFC 8032, stdlib)
# Kept dependency-free on purpose: every other runner in this repo is stdlib-only so a
# stranger can check our claims from a bare clone with nothing installed.
P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _xrecover(y):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * I) % P
    if x % 2 != 0:
        x = P - x
    return x


_By = 4 * pow(5, P - 2, P)
_B = (_xrecover(_By) % P, _By % P)


def _add(pt, q):
    x1, y1 = pt
    x2, y2 = q
    k = D * x1 * x2 * y1 * y2
    x3 = (x1 * y2 + x2 * y1) * pow(1 + k, P - 2, P)
    y3 = (y1 * y2 + x1 * x2) * pow(1 - k, P - 2, P)
    return (x3 % P, y3 % P)


def _mul(pt, e):
    r = (0, 1)
    while e > 0:
        if e & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        e >>= 1
    return r


def _on_curve(pt):
    x, y = pt
    return (-x * x + y * y - 1 - D * x * x * y * y) % P == 0


def _decode_point(s):
    n = int.from_bytes(s, "little")
    y = n & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((n >> 255) & 1):
        x = P - x
    pt = (x, y)
    if not _on_curve(pt):
        raise ValueError("public key is not a curve point")
    return pt


def ed25519_verify(signature, message, public_key):
    if len(signature) != 64 or len(public_key) != 32:
        return False
    try:
        R = _decode_point(signature[:32])
        A = _decode_point(public_key)
    except ValueError:
        return False
    S = int.from_bytes(signature[32:], "little")
    if S >= L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little")
    return _mul(_B, S) == _add(R, _mul(A, h % L))


# ------------------------------------------------------- C2SP signed-note parsing
def parse_note(text):
    """A signed note is: body, blank line, then one '— <name> <base64>' line per signature.
    The signed message is the body including its trailing newline."""
    sep = "\n\n— "
    i = text.index(sep)
    body = text[: i + 1]
    sigs = []
    for line in text[i + 2 :].splitlines():
        if line.startswith("— "):
            name, b64 = line[2:].split(" ", 1)
            sigs.append((name, base64.b64decode(b64)))
    return body, sigs


def b64lines(path):
    return [base64.b64decode(x) for x in path.read_text().split() if x]


def main():
    # 1. the anchor is over OUR committed bytes
    leaf_bytes = (FIX / "leaf.6312.json").read_bytes().rstrip(b"\n")
    leaf = json.loads(leaf_bytes)
    env_sha = hashlib.sha256((ROOT / ENVELOPE_REL).read_bytes()).hexdigest()
    check(
        "anchored leaf binds this repo's committed envelope",
        leaf["claim"]["request_hash"] == "sha256:" + env_sha,
        f"sha256({ENVELOPE_REL}) = {env_sha}",
    )
    check(
        "leaf request_uri names that same file",
        leaf["claim"]["request_uri"] == ENVELOPE_REL,
        leaf["claim"]["request_uri"],
    )
    check("leaf carries the narrow claim type", leaf["claimType"] == "erc8004-envelope-anchor/v1")
    print(f"       leaf scope: {leaf['claim']['scope']}")

    # 2. leaf digest as published
    leaf_sha = hashlib.sha256(leaf_bytes).hexdigest()
    expected = json.loads((FIX / "expected.json").read_text())
    check("committed leaf digest matches the published one", leaf_sha == expected["leaf_sha256"], leaf_sha)
    check("leaf is RFC 8785 canonical length", len(leaf_bytes) == expected["leaf_bytes"], f"{len(leaf_bytes)} bytes")

    # 3. inclusion proof folds to the published root
    proof = b64lines(FIX / "inclusion.6312.6322.txt")
    root = root_from_inclusion(h_leaf(leaf_bytes), LEAF_INDEX, PROOF_SIZE, proof)
    root_b64 = base64.b64encode(root).decode()
    check(
        f"inclusion proof folds leaf {LEAF_INDEX} to the root at size {PROOF_SIZE}",
        root_b64 == expected["root_at_6322"],
        root_b64,
    )

    # 4. the live checkpoint is signed by the log's published key
    body, sigs = parse_note((FIX / "checkpoint.6355.txt").read_text())
    lines = body.splitlines()
    origin, signed_size, signed_root_b64 = lines[0], int(lines[1]), lines[2]
    vkey = [
        l.split(":", 1)[1].strip()
        for l in (FIX / "log-root.txt").read_text().splitlines()
        if l.startswith("vkey")
    ][0]
    _, keyhash_hex, vkey_b64 = vkey.split("+")
    raw = base64.b64decode(vkey_b64)
    check("published vkey declares Ed25519", raw[0] == 1)
    pub = raw[1:]
    verified = any(
        s[:4].hex() == keyhash_hex and ed25519_verify(s[4:68], body.encode(), pub)
        for name, s in sigs
        if name == origin
    )
    check(
        f"checkpoint (size {signed_size}) is signed by the log's published vkey",
        verified,
        f"origin={origin} keyhash={keyhash_hex}",
    )
    witnesses = sorted({n for n, _ in sigs if n != origin})
    check(
        "checkpoint is cosigned by independent witnesses",
        len(witnesses) >= 4,
        f"{len(witnesses)} distinct: {', '.join(witnesses)}",
    )
    print("       (witness cosignatures are recorded, not verified here — each witness's own")
    print("        key would have to be fetched from that witness; the log's signature is)")

    # 5. nothing was rewritten under our leaf between 6322 and the signed head
    good, why = consistent(
        PROOF_SIZE,
        signed_size,
        b64lines(FIX / "consistency.6322.6355.txt"),
        base64.b64decode(expected["root_at_6322"]),
        base64.b64decode(signed_root_b64),
    )
    check(f"tree at size {PROOF_SIZE} is an unmodified prefix of the signed size-{signed_size} tree", good, why)

    print()
    if ok:
        print("all anchor checks passed — these envelope bytes existed in a witnessed order.")
        print("Authority and validity are NOT claimed here; run run_erc8004.py for those.")
        return 0
    print("FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
