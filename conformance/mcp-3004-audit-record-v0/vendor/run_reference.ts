// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Runs the SEP-3004 REFERENCE verifier — vendored here byte-for-byte, digest
// pinned in SHA256SUMS — over the fixtures in ../fixtures. Nothing in
// audit-record-contract.ts is patched. The only thing this driver does that the
// upstream file does not is add ONE entry to the extension registry:
//
//     PROFILES['authority-evidence'] = { required: [...], optional: [...] }
//
// That is the whole proposed change, and R1/R2 below make it visible: the same
// record is rejected before the line and accepted after it. If the contract's
// central architectural claim — "new emitter types add an extension, not a new
// chain" — holds, then that one line is all a new evidence type should ever
// cost. This driver is the check on that claim.
//
// Run: node --experimental-strip-types vendor/run_reference.ts   (Node >= 22.6)

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  PROFILES,
  computeEventHash,
  validateExtensions,
  verifyRecordHash,
  verifyChainSegment,
  type AuditRecord,
} from './audit-record-contract.ts';

const HERE = dirname(fileURLToPath(import.meta.url));
const FIX = join(HERE, '..', 'fixtures');

const read = (name: string) => JSON.parse(readFileSync(join(FIX, name), 'utf8'));

const segment: AuditRecord[] = read('segment.json');
const triple: AuditRecord = read('three-extension-kat.json');

// The SEP's own published known-answer fixtures, transcribed from the public
// preimage. They anchor this vendored copy: if these two digests do not come
// out, the vendored verifier is not the one the SEP describes and every other
// result in this directory is void.
const KAT_CG = 'd494769c1ae442ea88dd190068747abf63c0568a3b856f85791b1a50a99d48b4';
const KAT_2X = 'f733fed9cc757165f810b778e4baba1f51a45504988e937707aaab4361b2f064';

const katCore = {
  event_id: '99999999-9999-9999-9999-999999999999',
  occurred_at: '2026-06-06T12:00:00.000Z',
  principal_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  event_type: 'tool_call',
  tool_name: 'export',
  outcome: 'deferred',
  previous_hash: null,
  event_hash: '',
};
const cgBody = {
  flagged: false,
  invoked_by_principal_id: null,
  purpose_declared: 'reconcile June invoices',
  session_id: '55555555-5555-5555-5555-555555555555',
};
const rsBody = {
  drift_status: 'confirmed',
  evidence_hash: 'sha256:b2c547e2c8f17eafc72ef5c2d4d7b6b4d0f7437ab52bae573a9af14ff5e2d9be',
  policy_id: 'example.org/runtime-drift@3',
  quarantine_decision: 'quarantine',
  severity: 'high',
};

const results: Array<[string, boolean, string]> = [];
const check = (id: string, ok: boolean, detail: string) => results.push([id, ok, detail]);

// ---------------------------------------------------------------------------
// R0 — the vendored verifier is the one the SEP describes.
// ---------------------------------------------------------------------------
const katCg = computeEventHash({ ...katCore, extensions: { 'caller-governance': cgBody } } as AuditRecord);
const kat2x = computeEventHash({
  ...katCore,
  extensions: { 'caller-governance': cgBody, 'runtime-security': rsBody },
} as AuditRecord);
check('R0-kat-anchor', katCg === KAT_CG && kat2x === KAT_2X,
  katCg === KAT_CG && kat2x === KAT_2X
    ? 'vendored verifier reproduces both published known-answer digests'
    : `KAT mismatch: cg=${katCg} 2x=${kat2x}`);

// ---------------------------------------------------------------------------
// R1 — BEFORE registration, the reference verifier rejects the extension.
// ---------------------------------------------------------------------------
const before = validateExtensions(segment[0]);
check('R1-unregistered-rejected', !before.ok && before.failures.some(f => f.includes('authority-evidence')),
  before.ok ? 'UNEXPECTED: accepted an unregistered type' : before.failures.join('; '));

// ---------------------------------------------------------------------------
// The proposed registration — one entry, no other change.
// ---------------------------------------------------------------------------
(PROFILES as Record<string, { required: readonly string[]; optional: readonly string[] }>)['authority-evidence'] = {
  required: ['evidence_profile', 'evidence_digest', 'authority_verdict', 'verdict_digest'],
  optional: ['evidence_uri', 'act_signed_at', 'signature_alg'],
};

// ---------------------------------------------------------------------------
// R2 — AFTER registration, every fixture validates.
// ---------------------------------------------------------------------------
const afterFailures = [...segment, triple]
  .map(r => validateExtensions(r))
  .flatMap(r => r.failures);
check('R2-registered-accepted', afterFailures.length === 0,
  afterFailures.length === 0 ? 'all fixtures validate under the extended registry' : afterFailures.join('; '));

// ---------------------------------------------------------------------------
// R3 — cross-language agreement: the reference verifier recomputes exactly the
// event_hash that the independent Python canonicalizer wrote into the fixture.
// ---------------------------------------------------------------------------
const mismatches = [...segment, triple]
  .filter(r => computeEventHash(r) !== r.event_hash)
  .map(r => `${r.event_id}: ts=${computeEventHash(r)} py=${r.event_hash}`);
check('R3-cross-language', mismatches.length === 0,
  mismatches.length === 0
    ? `TypeScript and Python agree on all ${segment.length + 1} records`
    : mismatches.join('; '));

// ---------------------------------------------------------------------------
// R4 — the two-record segment verifies as a chain (hashes + threading).
// ---------------------------------------------------------------------------
const chain = verifyChainSegment(segment);
check('R4-chain-verifies', chain.ok,
  chain.ok ? 'both records verify and thread — including the NOT-AUTHORIZED one' : chain.failures.join('; '));

// ---------------------------------------------------------------------------
// R5 — an authority-evidence field is integrity-protected by the SAME chain:
// flipping the verdict from not_authorized to consistent breaks the digest.
// ---------------------------------------------------------------------------
const forged = JSON.parse(JSON.stringify(segment[1])) as AuditRecord;
forged.extensions['authority-evidence'].authority_verdict = 'consistent';
const forgedCheck = verifyRecordHash(forged);
check('R5-extension-tamper-detected', !forgedCheck.ok,
  forgedCheck.ok ? 'UNEXPECTED: forged verdict still verified' : 'rewriting authority_verdict breaks event_hash');

// ---------------------------------------------------------------------------
// R6 — the three-extension record verifies: caller-governance, runtime-security
// and authority-evidence side by side under ONE digest.
// ---------------------------------------------------------------------------
const tripleCheck = verifyRecordHash(triple);
const tripleTypes = Object.keys(triple.extensions).sort().join(', ');
check('R6-three-extension', tripleCheck.ok && Object.keys(triple.extensions).length === 3,
  tripleCheck.ok ? `one digest over: ${tripleTypes}` : tripleCheck.failures.join('; '));

// ---------------------------------------------------------------------------
// R7 — THE GAP. Both records are chain-valid. Every protected core field is
// identical except event_id, occurred_at and the chain link. One act was
// authorized; the other was made after the mandate was revoked. SEP-3004
// verification cannot tell them apart — only the evidence can.
// ---------------------------------------------------------------------------
const [a, b] = segment;
const coreDiff = ['principal_id', 'event_type', 'tool_name', 'outcome']
  .filter(f => (a as Record<string, unknown>)[f] !== (b as Record<string, unknown>)[f]);
const verdictA = a.extensions['authority-evidence'].authority_verdict;
const verdictB = b.extensions['authority-evidence'].authority_verdict;
check('R7-the-gap',
  chain.ok && coreDiff.length === 0 && verdictA === 'consistent' && verdictB === 'not_authorized',
  coreDiff.length === 0
    ? `identical principal/type/tool/outcome; both chain-valid; verdicts differ: ${verdictA} vs ${verdictB}`
    : `core fields differ, weakening the demonstration: ${coreDiff.join(',')}`);

// ---------------------------------------------------------------------------
for (const [id, ok, detail] of results) {
  console.log(`  ${ok ? '✓' : '✗'} ${id} — ${detail}`);
}
const failed = results.filter(([, ok]) => !ok).length;
console.log(`\n${results.length} reference checks — ${results.length - failed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
