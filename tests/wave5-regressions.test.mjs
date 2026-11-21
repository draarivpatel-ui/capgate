import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../js/hash.mjs';
import { buildReceipt, verifyReceipt } from '../js/receipt.mjs';
import { buildAuditJson, verifyAuditJson, buildCorpusCsv, csvCellSafe } from '../js/audit-export.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/* ------------------------------------------------------------------ */
/* Adversarial wave 5: UI/export layer defects found by hostile audit  */
/* ------------------------------------------------------------------ */

test('hidden attribute beats .btn display rule: [hidden]{display:none} exists', () => {
  const css = read('styles.css');
  assert.match(css, /\[hidden\]\s*\{[^}]*display:\s*none\s*!important/);
});

test('btn-apply-safe starts hidden and .btn[hidden] computes display:none', () => {
  const html = read('index.html');
  const btn = html.match(/<button[^>]*id="btn-apply-safe"[^>]*>/);
  assert.ok(btn, 'apply-safe button exists');
  assert.ok(/\bhidden\b/.test(btn[0]), 'starts with hidden attribute');
  assert.match(read('styles.css'), /display:\s*inline-flex/, '.btn uses inline-flex (regression guard)');
});

test('canonicalJson throws a controlled error on hostile deep nesting', () => {
  let deep = { a: 1 };
  for (let i = 0; i < 4000; i++) deep = { a: deep };
  assert.throws(() => canonicalJson(deep), /too deeply/);
});

test('verifyReceipt returns MALFORMED (not a crash) on deeply nested receipts', () => {
  let deep = { a: 1 };
  for (let i = 0; i < 4000; i++) deep = { a: deep };
  const fake = {
    tool: 'CapGate', version: '1.1.0', policy: deep,
    digest: { algorithm: 'a', canonicalJson: 'b', signature: 'c' },
  };
  const res = verifyReceipt(fake);
  assert.equal(res.status, 'MALFORMED');
  assert.match(res.detail, /nested/);
});

test('verifyAuditJson returns MALFORMED (not a crash) on deeply nested docs', () => {
  let deep = { a: 1 };
  for (let i = 0; i < 4000; i++) deep = { a: deep };
  const fake = {
    tool: 'CapGate', policy: deep,
    integrity: { algorithm: 'SHA-256', canonicalEncoding: 'capgate/canonical-json-v1', canonicalSha256: 'x' },
  };
  const res = verifyAuditJson(fake);
  assert.equal(res.status, 'MALFORMED');
});

test('verifyAuditJson reports TAMPERED for smuggled keys inside integrity', () => {
  const doc = buildAuditJson({ policy: { x: 1 }, benchmark: null, toolCall: null, evaluation: null });
  assert.equal(verifyAuditJson(doc).status, 'VALID');
  doc.integrity.smuggled = 'payload';
  const res = verifyAuditJson(doc);
  assert.equal(res.status, 'TAMPERED');
  assert.match(res.detail, /smuggled/);
});

test('verifyAuditJson still validates and catches payload edits', () => {
  const doc = buildAuditJson({ policy: { a: 1 }, toolCall: { tool: 'x' } });
  assert.equal(verifyAuditJson(doc).status, 'VALID');
  doc.policy.a = 2;
  assert.equal(verifyAuditJson(doc).status, 'TAMPERED');
});

test('csvCellSafe prefixes formula cells behind every whitespace/format char', () => {
  const leads = ['\t', ' ', '\v', '\f', '\r', '\n', '\u0085', '\u00A0', '\u1680', '\u180E', '\u200B', '\u200C', '\u200D', '\u2028', '\u2029', '\u202F', '\u205F', '\u2060', '\u3000', '\uFEFF'];
  for (const lead of leads) {
    const out = csvCellSafe(`${lead}=cmd`);
    assert.ok(out.startsWith("'") || out.startsWith('"\''), `unescaped formula lead ${JSON.stringify(lead)}`);
  }
  for (const ch of ['=', '+', '-', '@']) {
    const out = csvCellSafe(`${ch}1`);
    assert.ok(out.startsWith("'") || out.startsWith("\"'"), `formula char ${ch}`);
  }
});

test('csvCellSafe leaves ordinary cells untouched', () => {
  assert.equal(csvCellSafe('hello'), 'hello');
  assert.equal(csvCellSafe('a-b'), 'a-b');
  assert.equal(csvCellSafe('  spaced  '), '  spaced  ');
});

test('buildCorpusCsv survives malformed rows without throwing', () => {
  assert.doesNotThrow(() => buildCorpusCsv([null]));
  assert.doesNotThrow(() => buildCorpusCsv([undefined, { findingRules: 'abc' }, { id: 1 }]));
  const csv = buildCorpusCsv([{ id: 'x', findingRules: ['A', 'B'] }]);
  assert.match(csv, /x/);
  assert.match(csv, /A B/);
});

test('canonicalJson matches JSON.stringify for toJSON, function and undefined edges', () => {
  assert.equal(canonicalJson({ d: new Date(0) }), '{"d":"1970-01-01T00:00:00.000Z"}');
  assert.equal(canonicalJson({ a: 1, f: () => {} }), '{"a":1}');
  assert.equal(canonicalJson([undefined]), '[null]');
  assert.equal(canonicalJson({ s: Symbol('x'), a: 2 }), '{"a":2}');
});

test('canonicalJson keeps the undefined-vs-null distinction JSON.stringify has', () => {
  assert.notEqual(canonicalJson({ a: undefined }), canonicalJson({ a: null }));
  assert.equal(canonicalJson({ a: undefined }), '{}');
});

test('receipts still build and verify after the canonicalJson changes', () => {
  const receipt = buildReceipt({ policy: { a: 1 }, toolCall: { tool: 't' }, evaluation: { decision: 'ALLOW' }, benchmark: { rows: 1 } });
  const res = verifyReceipt(JSON.parse(JSON.stringify(receipt)));
  assert.equal(res.status, 'VALID');
});

test('app.js wraps the verify call so a thrown verifier never dies silently', () => {
  const app = read('js/app.js');
  const seg = app.slice(app.indexOf('runVerifyReceipt'));
  assert.match(seg, /try\s*\{[\s\S]{0,200}verifyReceipt\(parsed\)[\s\S]{0,200}\}\s*catch/);
});

test('family chips filter the unfiltered proof set (proofIdsAll)', () => {
  const app = read('js/app.js');
  assert.ok(app.includes('state.proofIdsAll = proofIds.slice()'), 'renderBenchmark stores the full set');
  assert.ok(app.includes('state.proofIdsAll.filter'), 'chip handler filters the full set');
  const handler = app.slice(app.indexOf("addEventListener('click', () => {", app.indexOf('family-chip')));
  const famAssign = handler.indexOf('state.proofFamily = fam');
  const guard = handler.indexOf('if (!ids.length) return');
  assert.ok(guard !== -1 && guard < famAssign, 'empty filter must not mark the chip active');
});

test('both-baselines fallback row renders BLOCK, not a hardcoded ALLOW', () => {
  const app = read('js/app.js');
  assert.match(app, /name:\s*'Both baselines',\s*verdict:\s*'BLOCK'/);
  assert.match(app, /d\.verdict\s*\|\|\s*'ALLOW'/);
});

test('kbd toggle accessible name is its visible label (WCAG 2.5.3)', () => {
  const html = read('index.html');
  const btn = html.match(/<button[^>]*id="btn-kbd-toggle"[^>]*>/);
  assert.ok(btn, 'keys toggle exists');
  assert.ok(!/aria-label=/.test(btn[0]), 'no aria-label overriding the visible text');
  assert.ok(/aria-pressed="true"/.test(btn[0]), 'keeps its pressed state');
});

test('attack-live region is debounced behind an sr-only mirror', () => {
  const html = read('index.html');
  const liveEl = html.match(/<div[^>]*id="attack-live"[^>]*>/);
  assert.ok(liveEl, 'attack-live element exists');
  assert.ok(!/aria-live/.test(liveEl[0]), 'visual verdict div is not itself a live region');
  assert.match(html, /id="attack-live-sr" class="sr-only" aria-live="polite"/);
  const app = read('js/app.js');
  assert.match(app, /setTimeout\([\s\S]{0,120}?,\s*700\s*\)/, 'debounced announcement');
  assert.match(read('styles.css'), /\.sr-only\s*\{/);
});

test('blob URL is revoked asynchronously after click', () => {
  const app = read('js/app.js');
  assert.match(app, /setTimeout\(\(\)\s*=>\s*URL\.revokeObjectURL/);
});

test('policy depth input cannot put NaN into state.policy', () => {
  const app = read('js/app.js');
  assert.match(app, /Number\.isFinite\(depthNum\)\s*\?\s*Math\.max\(0,\s*Math\.min\(6,\s*depthNum\)\)\s*:\s*2/);
});

test('focus survives list rebuilds: corpus items and family chips restore focus', () => {
  const app = read('js/app.js');
  assert.match(app, /corpusList\.contains\(document\.activeElement\)/);
  assert.match(app, /familyChips\.contains\(document\.activeElement\)/);
  assert.ok(app.includes('document.activeElement.dataset.caseId'));
  assert.ok(app.includes('document.activeElement.dataset.family'));
});
