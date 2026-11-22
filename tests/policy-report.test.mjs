import test from 'node:test';
import assert from 'node:assert/strict';
import {
  buildPolicyReportJson,
  verifyPolicyReport,
  buildPolicyReportCsv,
  buildPolicyReportMarkdown,
  encodeLabHash,
  decodeLabHash,
  REPORT_KIND,
  REPORT_INTEGRITY_NOTE,
  REPORT_CSV_COLUMNS,
} from '../js/policy-report.mjs';
import { runAttackLab, POLICY_PRESET_MAP, ATTACK_CHAINS } from '../js/attack-lab.mjs';
import { sha256Hex, canonicalJson } from '../js/hash.mjs';
import { csvCellSafe } from '../js/audit-export.mjs';

const lab = runAttackLab(POLICY_PRESET_MAP.scoped.policy);
const preset = POLICY_PRESET_MAP.scoped;
const doc = buildPolicyReportJson({ preset, lab, generatedAt: '2026-11-22T00:00:00.000Z' });

/* JSON report ------------------------------------------------------------------ */

test('json: report carries the audit kind, tool, version and policy', () => {
  assert.equal(doc.kind, REPORT_KIND);
  assert.equal(doc.tool, 'CapGate');
  assert.equal(doc.policy.id, 'scoped');
  assert.equal(doc.policy.name, preset.name);
});

test('json: policy config is embedded in the report', () => {
  assert.equal(doc.policy.config.workspaceRoot, '/workspace/app');
  assert.deepEqual(doc.policy.config.grantedTools, ['fs_read', 'http_fetch']);
});

test('json: summary carries the four headline metrics', () => {
  assert.equal(doc.summary.blockedChains, 6);
  assert.equal(doc.summary.totalChains, 6);
  assert.ok(Number.isFinite(doc.summary.residualSurface));
  assert.ok(Number.isFinite(doc.summary.tightnessScore));
  assert.equal(doc.summary.tightnessMax, 100);
});

test('json: summary embeds the 13 tightness dimensions', () => {
  assert.equal(doc.summary.tightnessDimensions.length, 13);
});

test('json: one entry per chain with per-step detail', () => {
  assert.equal(doc.chains.length, 6);
  for (const c of doc.chains) {
    assert.ok(c.id && c.title);
    assert.ok(Array.isArray(c.steps));
    for (const s of c.steps) {
      assert.ok(['allowed', 'denied', 'held', 'budget', 'skipped'].includes(s.status));
    }
  }
});

test('json: integrity block is an unkeyed SHA-256 triple plus the flag', () => {
  assert.equal(doc.integrity.algorithm, 'SHA-256');
  assert.equal(doc.integrity.canonicalEncoding, 'capgate/canonical-json-v1');
  assert.equal(doc.integrity.keyed, false);
  assert.match(doc.integrity.canonicalSha256, /^[0-9a-f]{64}$/);
});

test('json: the report honestly labels the digest as tamper evidence', () => {
  assert.match(doc.integrityNote, /unkeyed/i);
  assert.match(doc.integrityNote, /not a signature/i);
});

test('json: deterministic - two builds of the same lab give the same digest', () => {
  const a = buildPolicyReportJson({ preset, lab, generatedAt: '2026-11-22T00:00:00.000Z' });
  const b = buildPolicyReportJson({ preset, lab, generatedAt: '2026-11-22T00:00:00.000Z' });
  assert.equal(a.integrity.canonicalSha256, b.integrity.canonicalSha256);
});

test('json: generatedAt is covered by the digest', () => {
  const a = buildPolicyReportJson({ preset, lab, generatedAt: 'A' });
  const b = buildPolicyReportJson({ preset, lab, generatedAt: 'B' });
  assert.notEqual(a.integrity.canonicalSha256, b.integrity.canonicalSha256);
});

/* verify ------------------------------------------------------------------------- */

test('verify: a freshly built report verifies VALID', () => {
  const r = verifyPolicyReport(doc);
  assert.equal(r.status, 'VALID');
});

const TAMPERS = [
  ['summary.blockedChains', (d) => { d.summary.blockedChains = 0; }],
  ['chains[0].haltRule', (d) => { d.chains[0].haltRule = 'CAP-X'; }],
  ['chains[0].steps[0].status', (d) => { d.chains[0].steps[0].status = 'skipped'; }],
  ['policy.id', (d) => { d.policy.id = 'unrestricted'; }],
  ['version', (d) => { d.version = '0.0.0'; }],
  ['extra top-level key', (d) => { d.injected = true; }],
];
for (const [label, mutate] of TAMPERS) {
  test(`verify: editing ${label} reports TAMPERED`, () => {
    const edited = JSON.parse(JSON.stringify(doc));
    mutate(edited);
    assert.equal(verifyPolicyReport(edited).status, 'TAMPERED');
  });
}

test('verify: smuggled integrity subkey reports TAMPERED', () => {
  const edited = JSON.parse(JSON.stringify(doc));
  edited.integrity.extra = 1;
  assert.equal(verifyPolicyReport(edited).status, 'TAMPERED');
});

test('verify: recomputed digest by an attacker still fails the recorded one', () => {
  const edited = JSON.parse(JSON.stringify(doc));
  edited.summary.blockedChains = 99;
  // Attacker who does NOT recompute: stale digest catches it. One who does
  // recompute produces a self-consistent doc - which is why the report calls
  // itself tamper evidence, not authenticity. Both paths are covered; here the
  // stale digest must fail.
  assert.equal(verifyPolicyReport(edited).status, 'TAMPERED');
  const recomputed = JSON.parse(JSON.stringify(doc));
  recomputed.integrity.canonicalSha256 = sha256Hex(canonicalJson((({ integrity, ...rest }) => rest)(recomputed)));
  assert.equal(verifyPolicyReport(recomputed).status, 'VALID');
});

const MALFORMED = [
  ['null', null],
  ['array', [1, 2]],
  ['string', 'x'],
  ['no integrity', { kind: REPORT_KIND }],
  ['wrong kind', { ...doc, kind: 'other' }],
  ['wrong tool', { ...doc, tool: 'NotCapGate' }],
  ['wrong algorithm', { ...doc, integrity: { ...doc.integrity, algorithm: 'MD5' } }],
  ['keyed flag flipped', { ...doc, integrity: { ...doc.integrity, keyed: true } }],
];
for (const [label, value] of MALFORMED) {
  test(`verify: ${label} reports MALFORMED`, () => {
    assert.equal(verifyPolicyReport(value).status, 'MALFORMED');
  });
}

/* CSV report --------------------------------------------------------------------- */

const csv = buildPolicyReportCsv(lab, preset);

test('csv: header row is the pinned column list', () => {
  assert.equal(csv.split('\r\n')[0], REPORT_CSV_COLUMNS.join(','));
});

test('csv: one row per chain step plus the policy summary row', () => {
  const stepCount = lab.results.reduce((n, r) => n + r.steps.length, 0);
  const lines = csv.trim().split('\r\n');
  assert.equal(lines.length, 1 + stepCount + 1);
});

test('csv: CRLF line endings throughout', () => {
  assert.ok(!/[^\r]\n/.test(csv));
  assert.ok(csv.endsWith('\r\n'));
});

test('csv: no line can open a spreadsheet formula', () => {
  for (const line of csv.split('\r\n')) {
    assert.ok(!/^[=+\-@\t ]/.test(line), line.slice(0, 40));
  }
});

test('csv: a cell starting with = is prefixed and quoted', () => {
  // Chain titles and labels flow through csvCellSafe inside the report builder:
  // prefix a `'` to disarm the formula, then quote because the `'` itself can
  // be re-interpreted when it leads the raw field.
  assert.equal(csvCellSafe('=cmd'), `"'=cmd"`);
  assert.equal(csvCellSafe('+2+2'), `"'+2+2"`);
  assert.equal(csvCellSafe('@SUM(A1)'), `"'@SUM(A1)"`);
  assert.equal(csvCellSafe('-10+5'), `"'-10+5"`);
  assert.equal(csvCellSafe('  =x'), `"'  =x"`); // whitespace before = is disarmed too
});

test('csv: cell text containing a quote escapes it doubled', () => {
  assert.equal(csvCellSafe('say "hi"'), '"say ""hi"""');
});

test('csv: summary row carries preset name and metrics', () => {
  const last = csv.trim().split('\r\n').pop();
  assert.ok(last.includes('Least-Privilege Scoped Token'));
  assert.ok(last.includes('6/6 blocked'));
});

/* Markdown report ------------------------------------------------------------------ */

const md = buildPolicyReportMarkdown({ preset, lab, generatedAt: '2026-11-22' });

test('md: report opens with a level-1 heading and summary lines', () => {
  assert.match(md, /^# CapGate policy audit report/);
  assert.match(md, /Blocked chains: 6\/6/);
  assert.match(md, /Residual attack surface: \d+\/100/);
  assert.match(md, /Least-privilege tightness: \d+\/100/);
});

test('md: one table row per chain with escaped pipes', () => {
  const rows = md.split('\n').filter((l) => l.startsWith('| ') && !l.includes('---'));
  assert.equal(rows.length, 7); // header + 6 chains
});

test('md: chain titles with pipe characters are escaped, not broken', () => {
  const weird = JSON.parse(JSON.stringify(lab));
  weird.results[0].title = 'a | b';
  const out = buildPolicyReportMarkdown({ preset, lab: weird });
  assert.ok(out.includes('a \\| b'));
});

test('md: report carries the unkeyed-digest honesty note', () => {
  assert.ok(md.includes(REPORT_INTEGRITY_NOTE));
});

/* URL hash ------------------------------------------------------------------------- */

test('hash: preset-only encodes as #cap=<preset>', () => {
  assert.equal(encodeLabHash({ preset: 'scoped' }), '#cap=scoped');
});

test('hash: preset plus chain encodes both segments', () => {
  assert.equal(encodeLabHash({ preset: 'scoped', chain: 'inject-exfil' }), '#cap=scoped.inject-exfil');
});

test('hash: preset plus chain plus compare encodes the vs clause', () => {
  assert.equal(encodeLabHash({ preset: 'scoped', chain: 'deputy', compareTo: 'hitl' }), '#cap=scoped.deputy.vs.hitl');
});

test('hash: unknown preset encodes empty (fail closed)', () => {
  assert.equal(encodeLabHash({ preset: 'nope' }), '');
  assert.equal(encodeLabHash({ preset: '' }), '');
});

test('hash: unknown chain is dropped rather than encoded', () => {
  assert.equal(encodeLabHash({ preset: 'scoped', chain: 'nope' }), '#cap=scoped');
});

test('hash: round-trips every preset id', () => {
  for (const id of ['unrestricted', 'readonly', 'scoped', 'hitl', 'zerotrust']) {
    const d = decodeLabHash(encodeLabHash({ preset: id }));
    assert.equal(d.preset, id);
  }
});

test('hash: round-trips every chain id as the chain segment', () => {
  for (const c of ATTACK_CHAINS) {
    const d = decodeLabHash(encodeLabHash({ preset: 'scoped', chain: c.id, compareTo: 'hitl' }));
    assert.equal(d.chain, c.id);
    assert.equal(d.compareTo, 'hitl');
  }
});

test('hash: a bare cap= string without the # decodes too', () => {
  const d = decodeLabHash('cap=scoped.privesc');
  assert.equal(d.preset, 'scoped');
  assert.equal(d.chain, 'privesc');
});

const BAD_HASHES = [
  ['empty', ''],
  ['just #', '#'],
  ['wrong prefix', '#other=scoped'],
  ['no preset', '#cap='],
  ['unknown preset', '#cap=evil'],
  ['unknown chain', '#cap=scoped.evil'],
  ['unknown compare', '#cap=scoped.vs.evil'],
  ['empty compare', '#cap=scoped.vs.'],
  ['double vs', '#cap=scoped.vs.vs'],
  ['three segments', '#cap=scoped.privesc.extra'],
  ['js injection', '#cap=javascript:alert(1)'],
  ['null', null],
];
for (const [label, h] of BAD_HASHES) {
  test(`hash: malformed ${label} fails closed to null`, () => {
    assert.equal(decodeLabHash(h), null);
  });
}

test('hash: decoded selection feeds back into a valid encode', () => {
  const d = decodeLabHash('#cap=zerotrust.metaenv.vs.unrestricted');
  assert.equal(d.preset, 'zerotrust');
  assert.equal(d.chain, 'metaenv');
  assert.equal(d.compareTo, 'unrestricted');
  assert.equal(encodeLabHash(d), '#cap=zerotrust.metaenv.vs.unrestricted');
});
