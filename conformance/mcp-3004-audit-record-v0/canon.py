# SPDX-License-Identifier: MIT OR Apache-2.0
"""Independent second-language reproduction of the SEP-3004 canonical form.

This is a from-the-spec-text reimplementation of the `gif-audit/2`
canonicalization described in the Tamper-Evident Audit Record Contract
(modelcontextprotocol#3004) — NOT a port of the reference TypeScript. The point
of writing it separately is that the construction's own claim ("independent
reproduction is the point") is then checkable here: `run_mcp3004.py` asserts this
module and the vendored reference verifier agree byte-for-byte on every fixture,
and that both reproduce the SEP's two published known-answer digests.

Rules implemented (SEP §2.3, canon version `gif-audit/2`):
  * Object keys are serialized as-is and sorted. Keys are a controlled ASCII
    registry vocabulary, so JS's UTF-16 code-unit `Array.sort()` and Python's
    code-point `sorted()` cannot diverge here; a non-ASCII key would need the
    spec to pin a collation, and this module deliberately refuses one (see
    `_sort_keys`) rather than silently guessing.
  * String VALUES are normalized: reject control characters, NFC, trim U+0020
    only (not the full whitespace class), then a length cap of 8192 measured in
    UTF-16 code units (JS `String.length`), not Python code points.
  * `null` encodes distinguishably from `""`.
  * Preimage = the 7 protected core fields + `extensions`. `event_hash` is the
    output and is excluded; `anchor_witness` (§2.8, reserved) is excluded in v1.
  * H = SHA-256 over the UTF-8 canonical form.
"""

import hashlib
import json
import re
import unicodedata

MAX_FIELD_LEN = 8192

CORE_PROTECTED = (
    "event_id",
    "occurred_at",
    "principal_id",
    "event_type",
    "tool_name",
    "outcome",
    "previous_hash",
)

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _utf16_len(s: str) -> int:
    """JS `String.length` — UTF-16 code units, so astral characters count 2."""
    return len(s.encode("utf-16-le")) // 2


def normalize_string(s: str) -> str:
    if _CONTROL.search(s):
        raise ValueError("control character in protected string field")
    n = unicodedata.normalize("NFC", s)
    n = re.sub(r"^ +| +$", "", n)  # U+0020 only, matching PG btrim parity
    if _utf16_len(n) > MAX_FIELD_LEN:
        raise ValueError("protected string field exceeds length cap")
    return n


def _json_string(s: str) -> str:
    """`JSON.stringify` for a string: minimal escapes, non-ASCII emitted raw."""
    return json.dumps(s, ensure_ascii=False)


def _sort_keys(keys):
    for k in keys:
        if not k.isascii():
            raise ValueError(
                f"non-ASCII object key {k!r}: the contract scopes keys to an ASCII "
                "registry vocabulary and does not pin a collation for anything else"
            )
    return sorted(keys)


def canonicalize(value) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _json_string(normalize_string(value))
    if isinstance(value, (int, float)):
        # Supported for forward-safety; excluded by the /2 no-bare-numbers convention.
        raise ValueError("bare number: canon version gif-audit/2 forbids it")
    if isinstance(value, list):
        return "[" + ",".join(canonicalize(v) for v in value) + "]"
    if isinstance(value, dict):
        keys = _sort_keys(value.keys())
        return "{" + ",".join(_json_string(k) + ":" + canonicalize(value[k]) for k in keys) + "}"
    raise ValueError(f"uncanonicalizable value of type {type(value).__name__}")


def canonical_body(record: dict) -> dict:
    body = {f: record[f] for f in CORE_PROTECTED}
    body["extensions"] = record["extensions"]
    return body


def canonical_preimage(record: dict) -> str:
    return canonicalize(canonical_body(record))


def compute_event_hash(record: dict) -> str:
    return hashlib.sha256(canonical_preimage(record).encode("utf-8")).hexdigest()
