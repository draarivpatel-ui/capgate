/**
 * Audit exports for the CapGate playground: a formula-safe CSV of the corpus
 * rows and a SHA-256 fingerprinted JSON document. Both are deterministic,
 * dependency-free, and identical in Node and the browser.
 */

import { canonicalJson, sha256Hex } from './hash.mjs';
import { TOOL_VERSION } from './receipt.mjs';

export const AUDIT_CSV_COLUMNS = Object.freeze([
  'id', 'category', 'title', 'expected', 'naiveBlocked', 'flatBlocked',
  'capgateDecision', 'capgateBlocked', 'riskScore', 'findingRules',
]);

/**
 * Spreadsheet formula injection guard: a cell whose text starts with
 * `=`, `+`, `-`, `@`, or whitespace before one of those is executed as a
 * formula by Excel, Sheets, and Numbers. Prefixing with `'` renders it as
 * literal text. The cell is then CSV-quoted when it can break a record.
 */
export function csvCellSafe(value) {
  let s = String(value ?? '');
  // \s already covers tab/space/CR/LF/VT/FF plus NBSP and the Unicode space
  // separators; the added code points are the remaining format characters a
  // spreadsheet may skip before a formula (= + - @).
  if (/^[\s\u0085\u180E\u200B\u200C\u200D\u2060\uFEFF]*[=+\-@]/.test(s)) {
    s = `'${s}`;
  }
  if (/[",\r\n]/.test(s) || s.startsWith("'")) {
    s = `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/** One CSV line from an array of raw cell values. */
export function csvRowSafe(cells) {
  return cells.map(csvCellSafe).join(',');
}

/**
 * Formula-safe CSV export of the benchmark rows. Corpus titles and commands
 * are attacker-shaped text (`=`, `-c ...`, `+cmd`), so every cell passes
 * through csvCellSafe before joining.
 */
export function buildCorpusCsv(benchOrRows) {
  const rows = Array.isArray(benchOrRows) ? benchOrRows : (benchOrRows?.rows || []);
  const lines = [AUDIT_CSV_COLUMNS.join(',')];
  for (const r of rows) {
    const row = r && typeof r === 'object' ? r : {};
    lines.push(csvRowSafe([
      row.id,
      row.category,
      row.title,
      row.expectedBlocked ? 'unsafe' : 'benign',
      row.naiveBlocked ? 'blocked' : 'allowed',
      row.flatBlocked ? 'blocked' : 'allowed',
      row.decision,
      row.capBlocked ? 'blocked' : 'allowed',
      row.riskScore,
      (Array.isArray(row.findingRules) ? row.findingRules : []).join(' '),
    ]));
  }
  return `${lines.join('\r\n')}\r\n`;
}

/** Deterministic summary of the benchmark for the audit document. */
function summarizeBenchmark(benchmark) {
  if (!benchmark || typeof benchmark !== 'object') return null;
  const { rows, ...rest } = benchmark;
  return {
    ...rest,
    rows: (rows || []).map((r) => {
      const { capgate, ...row } = r;
      return row;
    }),
  };
}

/**
 * Build the fingerprinted JSON audit document. `integrity.canonicalSha256`
 * is the SHA-256 of the canonical form of every field except `integrity`
 * itself, so a verifier can strip it, re-serialize, re-hash, and compare.
 */
export function buildAuditJson({ policy, benchmark, toolCall, evaluation, generatedAt } = {}) {
  const payload = {
    tool: 'CapGate',
    kind: 'capgate-audit',
    version: TOOL_VERSION,
    generatedAt: generatedAt ?? null,
    policy: policy ?? null,
    inspectedToolCall: toolCall ?? null,
    evaluation: evaluation ?? null,
    benchmark: summarizeBenchmark(benchmark),
  };
  return {
    ...payload,
    integrity: {
      algorithm: 'SHA-256',
      canonicalEncoding: 'capgate/canonical-json-v1',
      canonicalSha256: sha256Hex(canonicalJson(payload)),
    },
  };
}

/**
 * Re-verify a parsed audit document's fingerprint. Returns
 * { status: 'VALID' | 'TAMPERED' | 'MALFORMED' }.
 */
const AUDIT_INTEGRITY_KEYS = new Set(['algorithm', 'canonicalEncoding', 'canonicalSha256']);

export function verifyAuditJson(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return { status: 'MALFORMED', detail: 'Audit document is not an object.' };
  }
  const integrity = doc.integrity;
  if (!integrity || typeof integrity !== 'object' || Array.isArray(integrity)) {
    return { status: 'MALFORMED', detail: 'Audit document has no integrity object.' };
  }
  // The integrity object must carry exactly the fingerprint triple: extra keys
  // are unprotected data smuggled into a "verified" document.
  const extra = Object.keys(integrity).filter((k) => !AUDIT_INTEGRITY_KEYS.has(k));
  if (extra.length) {
    return { status: 'TAMPERED', detail: `Unexpected integrity field(s): ${extra.join(', ')}.` };
  }
  if (integrity.algorithm !== 'SHA-256' || integrity.canonicalEncoding !== 'capgate/canonical-json-v1') {
    return { status: 'MALFORMED', detail: 'Unsupported integrity algorithm or encoding.' };
  }
  const payload = { ...doc };
  delete payload.integrity;
  let expected;
  try {
    expected = sha256Hex(canonicalJson(payload));
  } catch {
    return { status: 'MALFORMED', detail: 'Audit document is too deeply nested to verify.' };
  }
  if (integrity.canonicalSha256 !== expected) {
    return { status: 'TAMPERED', detail: 'Canonical payload differs from the recorded fingerprint.' };
  }
  return { status: 'VALID', detail: 'Canonical payload matches the SHA-256 fingerprint.' };
}
