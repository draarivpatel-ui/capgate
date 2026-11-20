import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_POLICY,
  evaluateToolCall,
  hasTraversalSegment,
  normalizeForInspection,
  isSensitivePath,
  buildSarifReport,
} from '../js/capability-gate.mjs';
import { runCapGateBenchmark } from '../js/benchmark.mjs';

const sh = (command) => ({ tool: 'shell_exec', args: { command } });
const ev = (call, policy = DEFAULT_POLICY) => evaluateToolCall(call, policy);
const rules = (result) => result.findings.map((f) => f.ruleId);

test('overlong UTF-8, NUL, fullwidth and double-encoded traversal are all blocked', () => {
  const paths = [
    '/workspace/app/..%c0%afetc/passwd',
    '/workspace/app/%c0%ae%c0%ae/etc/passwd',
    '/workspace/app/..%ef%bc%8fetc/passwd',
    '/workspace/app/..%00/etc/passwd',
    '/workspace/app/....//etc/passwd',
    '/workspace/app/..;/etc/passwd',
    '/workspace/app/%252e%252e/etc/shadow',
    '/workspace/app/..%e0%80%afetc/passwd',
  ];
  for (const p of paths) {
    assert.equal(hasTraversalSegment(p), true, p);
    assert.equal(ev({ tool: 'fs_read', args: { path: p } }).decision, 'DENY', p);
  }
  assert.equal(hasTraversalSegment('/workspace/app/src/main.js'), false);
  assert.equal(hasTraversalSegment('/workspace/app/file..name.js'), false);
});

test('backslash-escaped dots in fs_read paths are blocked, plain backslash separators still work', () => {
  assert.equal(hasTraversalSegment('/workspace/app/.\\./.\\./secret.txt'), true);
  assert.equal(ev({ tool: 'fs_read', args: { path: '/workspace/app/.\\./.\\./secret.txt' } }).decision, 'DENY');
  assert.equal(hasTraversalSegment('..\\..\\secret'), true);
  assert.equal(normalizeForInspection('..\\..\\secret'), '../secret');
});

test('sensitive path matcher sees encoded secret files', () => {
  assert.equal(isSensitivePath('/workspace/app/%2essh/id_ed25519'), true);
  assert.equal(isSensitivePath('/workspace/app/.ssh%2fid_ed25519'), true);
  assert.equal(isSensitivePath('/workspace/app/.%65nv'), true);
  assert.equal(isSensitivePath('/workspace/app/src/main.js'), false);
});

test('deny-by-default blocks unknown and missing tools and escalates empty required args', () => {
  assert.equal(ev({ tool: 'mystery_tool', args: { x: '1' } }).decision, 'DENY');
  assert.ok(rules(ev({ tool: 'mystery_tool', args: {} })).includes('CAP-POLICY-00'));
  assert.equal(ev({ tool: '', args: {} }).decision, 'DENY');
  assert.equal(ev(sh('')).decision, 'ESCALATE');
  assert.equal(ev({ tool: 'env_read', args: { name: '' } }).decision, 'ESCALATE');
  assert.ok(rules(ev(sh(''))).includes('CAP-POLICY-01'));
});

test('inline interpreter and package-script execution is blocked or escalated', () => {
  const inline = [
    'python3 -c "import os; os.system(0)"',
    'node -e "require(1)"',
    'node --eval "require(1)"',
    'python3 --command "print(1)"',
    'ruby -e "system(1)"',
    'deno eval "console.log(1)"',
  ];
  for (const c of inline) {
    const r = ev(sh(c));
    assert.equal(r.blocked, true, c);
    assert.ok(rules(r).includes('CAP-CMD-03'), c);
  }
  assert.equal(ev(sh('npm run clean')).decision, 'ESCALATE');
  assert.ok(rules(ev(sh('npx suspicious-pkg'))).includes('CAP-CMD-04'));
  assert.equal(ev(sh('npm test')).decision, 'ALLOW');
  assert.equal(ev(sh('npm start')).decision, 'ALLOW');
});

test('inline payloads hiding blocked commands are caught recursively', () => {
  const r = ev(sh(`python3 -c "import os; os.system('rm -rf /workspace/app')"`));
  assert.equal(r.decision, 'DENY');
  assert.ok(rules(r).includes('CAP-CMD-03'));
  const passed = ev(sh('python3 -c "print(1)"'), { ...DEFAULT_POLICY, allowInlineCode: true });
  assert.equal(passed.decision, 'ALLOW');
});

test('git pager, alias, config-env and -c overrides are blocked', () => {
  const cases = [
    'git config core.pager sh',
    'git config --global core.editor vim',
    'git -c core.pager=sh log',
    'git -c=core.pager=sh log',
    'git -c alias.x=sh status',
    'git --config-env=core.pager=X log',
    'git config diff.external /bin/sh',
  ];
  for (const c of cases) {
    const r = ev(sh(c));
    assert.equal(r.decision, 'DENY', c);
    assert.ok(rules(r).includes('CAP-GIT-01'), c);
  }
  assert.equal(ev(sh('git push --dry-run origin main')).decision, 'ALLOW');
});

test('secret expansion and secret assignments cannot hide behind braces or wrappers', () => {
  for (const c of ['echo ${API_KEY}', 'echo "$API_KEY"', 'env -i API_KEY=abc ls']) {
    const r = ev(sh(c));
    assert.equal(r.decision, 'DENY', c);
    assert.ok(rules(r).includes('CAP-SECRET-02'), c);
  }
  assert.equal(ev(sh('echo $HOME')).decision, 'ALLOW');
  assert.equal(ev({ tool: 'env_read', args: { name: 'API%5FKEY' } }).decision, 'ALLOW');
  assert.equal(ev({ tool: 'env_read', args: { name: 'auth_token' } }).decision, 'DENY');
});

test('version strings are unified across package, benchmark, SARIF and receipt', async () => {
  const pkg = JSON.parse(await (await import('node:fs/promises')).readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const bench = runCapGateBenchmark();
  const sarif = buildSarifReport(bench.rows);
  assert.equal(pkg.version, '1.1.0');
  assert.equal(bench.version, '1.1.0');
  assert.equal(sarif.runs[0].tool.driver.version, '1.1.0');
});
