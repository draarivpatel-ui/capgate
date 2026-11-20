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

/* ---------- Wave 2 hardening: fresh cross-model bypass classes ---------- */

test('Windows drive-letter and UNC paths are outside the workspace and hive paths are sensitive', () => {
  for (const p of ['C:\\Windows\\System32\\config\\SAM', 'C:\\Windows\\Repair\\SAM', '//?/UNC/share/secret']) {
    assert.equal(ev({ tool: 'fs_read', args: { path: p } }).decision, 'DENY', p);
  }
  assert.ok(rules(ev({ tool: 'fs_read', args: { path: 'C:\\Windows\\System32\\config\\SAM' } })).includes('CAP-SECRET-01'));
  assert.equal(ev({ tool: 'fs_read', args: { path: '/workspace/app/src/main.js' } }).decision, 'ALLOW');
});

test('space, NBSP and dot-padded traversal segments are blocked', () => {
  for (const p of ['/workspace/app/..%20/etc/passwd', '/workspace/app/..%c2%a0/etc/passwd', '/workspace/app/.. ./x', '/workspace/app/.../etc/passwd']) {
    assert.equal(hasTraversalSegment(p), true, p);
    assert.equal(ev({ tool: 'fs_read', args: { path: p } }).decision, 'DENY', p);
  }
  assert.equal(hasTraversalSegment('/workspace/app/v2.0-beta/x'), false);
});

test('git hook scripts and shell startup files are sensitive paths', () => {
  for (const p of [
    '/workspace/app/.git/hooks/pre-commit',
    '/workspace/app/.git/hooks/post-merge',
    '/workspace/app/.zshenv',
    '/workspace/app/.bashrc',
    '/root/.bash_profile',
  ]) {
    assert.ok(rules(ev({ tool: 'fs_write', args: { path: p } })).includes('CAP-SECRET-01'), p);
  }
});

test('bare wrapper invocations are never silent allows', () => {
  assert.ok(rules(ev(sh('env'))).includes('CAP-SECRET-02'));
  assert.equal(ev(sh('env')).decision, 'DENY');
  assert.equal(ev(sh('env | grep -i key')).decision, 'DENY');
  assert.equal(ev(sh('sudo')).decision, 'DENY');
  assert.ok(rules(ev(sh('sudo'))).includes('CAP-CMD-01'));
  assert.equal(ev(sh('ls | xargs')).decision, 'ESCALATE');
});

test('npm lifecycle subcommands that run dependency code escalate', () => {
  for (const c of ['npm install left-pad', 'npm i evil-pkg', 'npm ci', 'npm create vite@latest', 'npm exec malicious', 'npm update']) {
    const r = ev(sh(c));
    assert.ok(rules(r).includes('CAP-CMD-04'), c);
    assert.notEqual(r.decision, 'ALLOW', c);
  }
  assert.equal(ev(sh('npm test')).decision, 'ALLOW');
  assert.equal(ev(sh('npm start')).decision, 'ALLOW');
});

test('interpreter module imports and stdin program text are held for review', () => {
  assert.ok(rules(ev(sh('python3 -m evilpkg'))).includes('CAP-CMD-06'));
  assert.equal(ev(sh('python3 -m pytest -q')).decision, 'ESCALATE');
  for (const c of [
    "python3 - <<EOF\nimport os\nos.system('rm -rf /workspace/app')\nEOF",
    "python3 <<EOF\nimport subprocess; subprocess.run(['rm','-rf','/workspace/app'])\nEOF",
    "node <<EOF\nrequire('child_process').execSync('rm -rf /workspace/app')\nEOF",
    "perl <<EOF\nsystem('rm -rf /workspace/app')\nEOF",
  ]) {
    assert.equal(ev(sh(c)).decision, 'DENY', c);
    assert.ok(rules(ev(sh(c))).some((r) => ['CAP-CMD-05', 'CAP-CMD-01'].includes(r)), c);
  }
  assert.ok(rules(ev(sh('sh < /workspace/app/p.sh'))).includes('CAP-CMD-05'));
  assert.equal(ev(sh('sh < /dev/null')).decision, 'ALLOW');
  assert.equal(ev(sh('cat < /dev/null')).decision, 'ALLOW');
});

test('SSRF host lookalikes, zone ids and rebinding services are blocked', () => {
  const net = { ...DEFAULT_POLICY, allowNetwork: true };
  const urls = [
    'http://169。254。169。254/latest/meta-data/',
    'http://１６９．２５４．１６９．２５４/latest/meta-data/',
    'http:169.254.169.254/latest/meta-data/',
    'http://169%2e254%2e169%2e254/',
    'http://169.254.169.254\u0000/',
    'http://[::1%25eth0]:8080/',
    'http://127.0.0.1.nip.io/secret',
    'http://10-0-0-5.sslip.io/admin',
    'http://localtest.me/admin',
    'http://lvh.me/admin',
    'http://instance-data/computeMetadata/v1/',
  ];
  for (const u of urls) {
    assert.equal(ev({ tool: 'http_fetch', args: { url: u } }, net).decision, 'DENY', u);
  }
  assert.equal(ev({ tool: 'http_fetch', args: { url: 'https://api.github.com/repos/x/y' } }, net).decision, 'ALLOW');
});

test('extended secret environment names (PAT, JWT, KEY suffix) are blocked without new false positives', () => {
  for (const name of ['GITHUB_PAT', 'JWT', 'SSH_KEY', 'STRIPE_KEY', 'DB_PASS', 'DEPLOY_CREDS', 'SIGNING_KEY']) {
    assert.equal(ev({ tool: 'env_read', args: { name } }).decision, 'DENY', name);
  }
  assert.ok(rules(ev(sh('echo $GITHUB_PAT'))).includes('CAP-SECRET-02'));
  assert.equal(ev({ tool: 'env_read', args: { name: 'NODE_ENV' } }).decision, 'ALLOW');
  assert.equal(ev({ tool: 'env_read', args: { name: 'DEPLOY_PATTERN' } }).decision, 'ALLOW');
  assert.equal(ev({ tool: 'env_read', args: { name: 'PATH_INFO' } }).decision, 'ALLOW');
});

test('git hook-executing subcommands escalate and core.hooksPath is blocked', () => {
  for (const c of ['git commit -m x', 'git merge feature', 'git rebase main', 'git pull origin main', 'git am patch.diff']) {
    assert.ok(rules(ev(sh(c))).includes('CAP-GIT-02'), c);
    assert.notEqual(ev(sh(c)).decision, 'ALLOW', c);
  }
  assert.ok(rules(ev(sh('git config core.hooksPath .githooks'))).includes('CAP-GIT-01'));
  assert.ok(rules(ev(sh('git config core.hooksPath /tmp/evil'))).includes('CAP-PATH-02'));
});

test('malformed policy shapes degrade to safe defaults instead of disabling rules', () => {
  assert.equal(ev(sh('rm -rf /tmp/x'), { ...DEFAULT_POLICY, blockedCommands: 'rm' }).decision, 'DENY');
  assert.equal(ev(sh('rm -rf /tmp/x'), { ...DEFAULT_POLICY, allowedCommands: null }).decision, 'DENY');
  assert.equal(ev(sh("bash -c 'bash -c \"rm -rf /tmp/x\"'"), { ...DEFAULT_POLICY, maxShellNestingDepth: 'x' }).decision, 'DENY');
});

test('xargs brace replacement tokenizes as one word and slash-less special-scheme URLs are inspected', () => {
  const r = ev(sh("printf 'a' | xargs -I{} sh -c 'rm -rf /workspace/app'"));
  assert.equal(r.decision, 'DENY');
  assert.ok(rules(r).includes('CAP-CMD-01'));
  const net = { ...DEFAULT_POLICY, allowNetwork: true };
  assert.equal(ev({ tool: 'http_fetch', args: { url: 'http:169.254.169.254/latest/meta-data/' } }, net).decision, 'DENY');
});
