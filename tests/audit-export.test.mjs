import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AUDIT_CSV_COLUMNS,
  csvCellSafe,
  csvRowSafe,
  buildCorpusCsv,
  buildAuditJson,
  verifyAuditJson,
} from '../js/audit-export.mjs';
import { runCapGateBenchmark } from '../js/benchmark.mjs';
import { ADVERSARIAL_CORPUS } from '../js/corpus.mjs';
import { sha256Hex, canonicalJson } from '../js/hash.mjs';

/* csvCellSafe --------------------------------------------------------------- */

test('csv: = formula is prefixed', () => {
  assert.ok(/^"?'=/.test(csvCellSafe('=1+1')));
  assert.ok(/^"?'=/.test(csvCellSafe('=cmd|"/etc/passwd"!A1')));
});

test('csv: + and - leading chars are prefixed', () => {
  assert.ok(/^"?'\+/.test(csvCellSafe('+SUM(A1)')));
  assert.ok(/^"?'-/.test(csvCellSafe('-rf /')));
  assert.ok(/^"?'-/.test(csvCellSafe('-1')));
});

test('csv: @ references are prefixed', () => {
  assert.ok(/^"?'@/.test(csvCellSafe('@SUM(A1)')));
});

test('csv: leading whitespace before formula chars is prefixed', () => {
  assert.ok(/^"?'/.test(csvCellSafe('\t=1+1')));
  assert.ok(/^"?'/.test(csvCellSafe('  =x')));
});

test('csv: ordinary text passes through unchanged', () => {
  assert.equal(csvCellSafe('hello'), 'hello');
  assert.equal(csvCellSafe('cmd-1'), 'cmd-1');
  assert.equal(csvCellSafe('x = y'), 'x = y');
});

test('csv: interior formula chars are not prefixed', () => {
  assert.equal(csvCellSafe('a=b'), 'a=b');
  assert.equal(csvCellSafe('a-b-c'), 'a-b-c');
});

test('csv: embedded quotes are doubled and wrapped', () => {
  assert.equal(csvCellSafe('say "hi"'), '"say ""hi"""');
});

test('csv: commas wrap the cell', () => {
  assert.equal(csvCellSafe('a,b'), '"a,b"');
});

test('csv: newlines wrap the cell', () => {
  assert.equal(csvCellSafe('a\nb'), '"a\nb"');
});

test('csv: formula-prefixed cell with comma is quoted whole', () => {
  const out = csvCellSafe('=1,2');
  assert.ok(out.startsWith('"\''));
});

test('csv: null and numbers serialize safely', () => {
  assert.equal(csvCellSafe(null), '');
  assert.equal(csvCellSafe(42), '42');
});

/* csvRowSafe / buildCorpusCsv -------------------------------------------------- */

test('csv: row joins cells with commas', () => {
  assert.equal(csvRowSafe(['a', 'b', 'c']), 'a,b,c');
});

test('csv: corpus export has a header and one row per case', () => {
  const bench = runCapGateBenchmark(ADVERSARIAL_CORPUS);
  const csv = buildCorpusCsv(bench);
  const lines = csv.trim().split(/\r?\n/);
  assert.equal(lines[0], AUDIT_CSV_COLUMNS.join(','));
  assert.equal(lines.length - 1, ADVERSARIAL_CORPUS.length);
});

test('csv: attacker-shaped titles cannot inject formulas', () => {
  const rows = [{ id: 'x', category: 'c', title: '=HYPERLINK("evil")', expectedBlocked: true,
    naiveBlocked: false, flatBlocked: false, decision: 'DENY', capBlocked: true, riskScore: 90, findingRules: [] }];
  const csv = buildCorpusCsv(rows);
  const dataLine = csv.trim().split(/\r?\n/)[1];
  assert.ok(dataLine.includes("'=HYPERLINK"));
  assert.ok(!/^,=/.test(dataLine));
});

test('csv: accepts the rows array directly', () => {
  const bench = runCapGateBenchmark(ADVERSARIAL_CORPUS);
  const csv = buildCorpusCsv(bench.rows);
  assert.equal(csv.trim().split(/\r?\n/).length - 1, ADVERSARIAL_CORPUS.length);
});

/* buildAuditJson / verifyAuditJson ---------------------------------------------- */

test('audit: document carries a SHA-256 fingerprint', () => {
  const bench = runCapGateBenchmark(ADVERSARIAL_CORPUS);
  const doc = buildAuditJson({ policy: { a: 1 }, benchmark: bench });
  assert.equal(doc.integrity.algorithm, 'SHA-256');
  assert.match(doc.integrity.canonicalSha256, /^[0-9a-f]{64}$/);
});

test('audit: fingerprint covers the canonical payload', () => {
  const doc = buildAuditJson({ policy: { a: 1 }, benchmark: null });
  const { integrity, ...payload } = doc;
  assert.equal(integrity.canonicalSha256, sha256Hex(canonicalJson(payload)));
});

test('audit: verify accepts a fresh document', () => {
  const bench = runCapGateBenchmark(ADVERSARIAL_CORPUS);
  const doc = buildAuditJson({ policy: { a: 1 }, benchmark: bench });
  assert.equal(verifyAuditJson(JSON.parse(JSON.stringify(doc))).status, 'VALID');
});

test('audit: verify catches a tampered field', () => {
  const doc = buildAuditJson({ policy: { a: 1 }, benchmark: null });
  doc.policy = { a: 2 };
  assert.equal(verifyAuditJson(doc).status, 'TAMPERED');
});

test('audit: verify catches a tampered fingerprint value', () => {
  const doc = buildAuditJson({ policy: { a: 1 }, benchmark: null });
  doc.integrity.canonicalSha256 = 'f'.repeat(64);
  assert.equal(verifyAuditJson(doc).status, 'TAMPERED');
});

test('audit: verify rejects malformed documents', () => {
  assert.equal(verifyAuditJson(null).status, 'MALFORMED');
  assert.equal(verifyAuditJson([]).status, 'MALFORMED');
  assert.equal(verifyAuditJson({}).status, 'MALFORMED');
  assert.equal(verifyAuditJson({ integrity: 'x' }).status, 'MALFORMED');
});

test('audit: verify rejects an unknown algorithm', () => {
  const doc = buildAuditJson({ policy: null });
  doc.integrity.algorithm = 'MD5';
  assert.equal(verifyAuditJson(doc).status, 'MALFORMED');
});

test('audit: benchmark rows are included without the heavy capgate payload', () => {
  const bench = runCapGateBenchmark(ADVERSARIAL_CORPUS);
  const doc = buildAuditJson({ benchmark: bench });
  assert.equal(doc.benchmark.rows.length, ADVERSARIAL_CORPUS.length);
  assert.ok(!('capgate' in doc.benchmark.rows[0]));
});

test('audit: extra fields outside integrity are fingerprinted', () => {
  const doc = buildAuditJson({ policy: { a: 1 }, generatedAt: '2026-01-01T00:00:00Z' });
  doc.extra = 'smuggled';
  assert.equal(verifyAuditJson(doc).status, 'TAMPERED');
});
