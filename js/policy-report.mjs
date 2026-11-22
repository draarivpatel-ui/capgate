/**
 * Checksummed policy-audit reports for the attack-chain lab, in JSON, CSV and
 * Markdown, plus URL-hash bookmarking for lab presets.
 *
 * The integrity digest is an UNKEYED SHA-256 over the canonical payload: it is
 * tamper evidence (any edit changes the digest), not a signature, and the
 * report says so in its own fields. CSV cells pass through the same
 * formula-injection guard as the corpus export, so chain titles that start
 * with = + - @ can never execute as a spreadsheet formula.
 */

import { canonicalJson, sha256Hex } from './hash.mjs';
import { TOOL_VERSION } from './receipt.mjs';
import { csvCellSafe, csvRowSafe } from './audit-export.mjs';
import { ATTACK_CHAIN_MAP, POLICY_PRESET_MAP } from './attack-lab.mjs';

export const REPORT_KIND = 'capgate-policy-audit';
export const REPORT_INTEGRITY_NOTE = 'integrity.canonicalSha256 is an unkeyed SHA-256 digest over the canonical payload: tamper evidence, not a signature. Anyone can mint a fresh digest, so it detects edits but cannot prove authorship.';

/**
 * Build the fingerprinted JSON report for one lab run. `lab` is the object
 * returned by runAttackLab; only deterministic, serializable fields are kept.
 */
export function buildPolicyReportJson({ preset, lab, compareTo = null, generatedAt = null } = {}) {
  const payload = {
    tool: 'CapGate',
    kind: REPORT_KIND,
    version: TOOL_VERSION,
    generatedAt: generatedAt ?? null,
    policy: preset ? { id: preset.id, name: preset.name, config: preset.policy } : null,
    compareTo,
    summary: lab ? {
      blockedChains: lab.blockedCount,
      totalChains: lab.totalChains,
      residualSurface: lab.residualSurface,
      tightnessScore: lab.tightness.score,
      tightnessMax: lab.tightness.maxScore,
      tightnessDimensions: lab.tightness.dimensions.map((d) => ({ id: d.id, name: d.name, earned: d.earned, max: d.max })),
    } : null,
    chains: (lab?.results || []).map((r) => ({
      id: r.chainId,
      title: r.title,
      blocked: r.blocked,
      haltIndex: r.haltIndex,
      haltKind: r.haltKind,
      haltRule: r.haltRule,
      budget: r.budget,
      steps: r.steps.map((s) => ({
        index: s.index,
        label: s.label,
        sink: s.sink,
        tool: s.tool,
        status: s.status,
        decision: s.decision,
        ruleIds: s.ruleIds,
        riskScore: s.riskScore,
      })),
    })),
    integrityNote: REPORT_INTEGRITY_NOTE,
  };
  return {
    ...payload,
    integrity: {
      algorithm: 'SHA-256',
      canonicalEncoding: 'capgate/canonical-json-v1',
      canonicalSha256: sha256Hex(canonicalJson(payload)),
      keyed: false,
    },
  };
}

const REPORT_INTEGRITY_KEYS = new Set(['algorithm', 'canonicalEncoding', 'canonicalSha256', 'keyed']);

/**
 * Re-verify a parsed policy report. Strip `integrity`, re-serialize the
 * canonical payload, re-hash, compare. Returns VALID, TAMPERED or MALFORMED.
 */
export function verifyPolicyReport(doc) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) {
    return { status: 'MALFORMED', detail: 'Report is not an object.' };
  }
  const integrity = doc.integrity;
  if (!integrity || typeof integrity !== 'object' || Array.isArray(integrity)) {
    return { status: 'MALFORMED', detail: 'Report has no integrity object.' };
  }
  const extra = Object.keys(integrity).filter((k) => !REPORT_INTEGRITY_KEYS.has(k));
  if (extra.length) {
    return { status: 'TAMPERED', detail: `Unexpected integrity field(s): ${extra.join(', ')}.` };
  }
  if (integrity.algorithm !== 'SHA-256' || integrity.canonicalEncoding !== 'capgate/canonical-json-v1' || integrity.keyed !== false) {
    return { status: 'MALFORMED', detail: 'Unsupported integrity algorithm, encoding, or keyed flag.' };
  }
  if (doc.kind !== REPORT_KIND || doc.tool !== 'CapGate') {
    return { status: 'MALFORMED', detail: 'Document is not a CapGate policy audit report.' };
  }
  const payload = { ...doc };
  delete payload.integrity;
  let expected;
  try {
    expected = sha256Hex(canonicalJson(payload));
  } catch {
    return { status: 'MALFORMED', detail: 'Report is too deeply nested to verify.' };
  }
  if (integrity.canonicalSha256 !== expected) {
    return { status: 'TAMPERED', detail: 'Canonical payload differs from the recorded fingerprint.' };
  }
  return { status: 'VALID', detail: 'Canonical payload matches the unkeyed SHA-256 fingerprint.' };
}

export const REPORT_CSV_COLUMNS = Object.freeze([
  'chain', 'chainTitle', 'chainBlocked', 'haltKind', 'step', 'stepLabel', 'sink', 'tool', 'status', 'decision', 'rules',
]);

/** Formula-safe CSV: one row per chain step, one summary row per chain. */
export function buildPolicyReportCsv(lab, preset = null) {
  const lines = [REPORT_CSV_COLUMNS.join(',')];
  for (const r of lab?.results || []) {
    for (const s of r.steps) {
      lines.push(csvRowSafe([
        r.chainId, r.title, r.blocked ? 'blocked' : 'completed', r.haltKind || '',
        s.index + 1, s.label, s.sink || '', s.tool || '', s.status, s.decision || '',
        (s.ruleIds || []).join(' '),
      ]));
    }
  }
  if (preset) {
    lines.push(csvRowSafe(['policy', preset.name, `${lab.blockedCount}/${lab.totalChains} blocked`, '', '', `residual surface ${lab.residualSurface}, tightness ${lab.tightness.score}/${lab.tightness.maxScore}`, '', '', '', '', '']));
  }
  return `${lines.join('\r\n')}\r\n`;
}

function mdCell(value) {
  return String(value ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/** Markdown report: summary plus one table row per chain. */
export function buildPolicyReportMarkdown({ preset, lab, generatedAt = null } = {}) {
  const lines = [
    '# CapGate policy audit report',
    '',
    `Tool: CapGate ${TOOL_VERSION}`,
    `Generated: ${generatedAt ?? 'offline deterministic export'}`,
    `Policy: ${preset ? `${preset.name} (${preset.id})` : 'custom'}`,
    '',
    `Blocked chains: ${lab.blockedCount}/${lab.totalChains}`,
    `Residual attack surface: ${lab.residualSurface}/100`,
    `Least-privilege tightness: ${lab.tightness.score}/${lab.tightness.maxScore}`,
    '',
    '| Chain | Blocked | Halted at | Halt kind | First rule |',
    '| --- | --- | --- | --- | --- |',
  ];
  for (const r of lab.results) {
    lines.push(`| ${mdCell(r.title)} | ${r.blocked ? 'yes' : 'no (completed)'} | ${r.haltIndex >= 0 ? `step ${r.haltIndex + 1}` : '-'} | ${mdCell(r.haltKind || '-')} | ${mdCell(r.haltRule || '-')} |`);
  }
  lines.push('', REPORT_INTEGRITY_NOTE, '');
  return `${lines.join('\n')}\n`;
}

/* URL-hash bookmarking ---------------------------------------------------- */

const HASH_PREFIX = 'cap=';

/**
 * Encode a lab selection into a compact hash: `#cap=<preset>`,
 * `#cap=<preset>.<chain>` or `#cap=<preset>.<chain>.vs.<presetB>`.
 */
export function encodeLabHash({ preset, chain, compareTo } = {}) {
  if (!preset || !POLICY_PRESET_MAP[preset]) return '';
  let hash = `${HASH_PREFIX}${preset}`;
  if (chain && ATTACK_CHAIN_MAP[chain]) hash += `.${chain}`;
  if (compareTo && POLICY_PRESET_MAP[compareTo]) hash += `.vs.${compareTo}`;
  return `#${hash}`;
}

/**
 * Decode a `#cap=` hash back into a validated selection. Malformed hashes
 * fail closed: they return null rather than a partial or guessed state.
 */
export function decodeLabHash(hash) {
  const raw = String(hash ?? '').trim().replace(/^#/, '');
  if (!raw) return null;
  if (!raw.startsWith(HASH_PREFIX)) return null;
  const body = raw.slice(HASH_PREFIX.length);
  if (!body) return null;
  const segs = body.split('.');
  const vsIdx = segs.indexOf('vs');
  const main = vsIdx >= 0 ? segs.slice(0, vsIdx) : segs;
  const compare = vsIdx >= 0 ? segs.slice(vsIdx + 1) : [];
  if (vsIdx >= 0 && (segs.lastIndexOf('vs') !== vsIdx || compare.length !== 1)) return null;
  if (main.length < 1 || main.length > 2) return null;
  const [preset, chain] = main;
  if (!POLICY_PRESET_MAP[preset]) return null;
  if (chain !== undefined && !ATTACK_CHAIN_MAP[chain]) return null;
  if (compare.length === 1 && !POLICY_PRESET_MAP[compare[0]]) return null;
  return { preset, chain: chain ?? null, compareTo: compare[0] ?? null };
}
