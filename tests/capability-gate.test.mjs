import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_POLICY,
  evaluateToolCall,
  isPrivateOrInternalHost,
  hasTraversalSegment,
  buildSarifReport,
} from '../js/capability-gate.mjs';
import { runCapGateBenchmark } from '../js/benchmark.mjs';

test('IP normalizer detects decimal, hex, octal, IPv4, and IPv6-mapped internal hosts', () => {
  assert.equal(isPrivateOrInternalHost('127.0.0.1'), true);
  assert.equal(isPrivateOrInternalHost('2130706433'), true);
  assert.equal(isPrivateOrInternalHost('0x7f000001'), true);
  assert.equal(isPrivateOrInternalHost('0xa9fea9fe'), true);
  assert.equal(isPrivateOrInternalHost('0177.0.0.1'), true);
  assert.equal(isPrivateOrInternalHost('[::ffff:127.0.0.1]'), true);
  assert.equal(isPrivateOrInternalHost('[::1]'), true);
  assert.equal(isPrivateOrInternalHost('127.1'), true);
  assert.equal(isPrivateOrInternalHost('::ffff:7f000001'), true);
  assert.equal(isPrivateOrInternalHost('0:0:0:0:0:ffff:127.0.0.1'), true);
  assert.equal(isPrivateOrInternalHost('localhost.'), true);
  assert.equal(isPrivateOrInternalHost('user@127.0.0.1'), true);
  assert.equal(isPrivateOrInternalHost('10.20.30.40'), true);
  assert.equal(isPrivateOrInternalHost('api.github.com'), false);
  assert.equal(isPrivateOrInternalHost('fcc-news.com'), false);
  assert.equal(isPrivateOrInternalHost('93.184.216.34'), false);
});

test('path traversal detector catches raw, backslash, double-encoded, and shell-escaped parent segments', () => {
  assert.equal(hasTraversalSegment('/workspace/app/../etc/passwd'), true);
  assert.equal(hasTraversalSegment('/workspace/app/%2e%2e/secret'), true);
  assert.equal(hasTraversalSegment('/workspace/app/%252e%252e/secret'), true);
  assert.equal(hasTraversalSegment('..\\..\\secret'), true);
  assert.equal(hasTraversalSegment('/workspace/app/src/main.js'), false);
  assert.equal(hasTraversalSegment('/workspace/app/file..name.js'), false);
  const ev = evaluateToolCall({ tool: 'shell_exec', args: { command: 'head -n 5 .\\./.\\./secret.txt' } }, DEFAULT_POLICY);
  assert.equal(ev.blocked, true);
});

test('capability firewall blocks env -S, bash --norc, echo redirects/secret leaks, and bracketed IPv6 SSRF', () => {
  assert.equal(evaluateToolCall({ tool: 'shell_exec', args: { command: "env -S 'rm -rf /workspace/app'" } }, DEFAULT_POLICY).blocked, true);
  assert.equal(evaluateToolCall({ tool: 'shell_exec', args: { command: "bash --norc -c 'rm -rf /workspace/app'" } }, DEFAULT_POLICY).blocked, true);
  assert.equal(evaluateToolCall({ tool: 'shell_exec', args: { command: 'echo hi > /etc/cron.d/x' } }, DEFAULT_POLICY).blocked, true);
  assert.equal(evaluateToolCall({ tool: 'shell_exec', args: { command: 'echo "$API_KEY" > /tmp/leak' } }, DEFAULT_POLICY).blocked, true);
  assert.equal(evaluateToolCall({ tool: 'http_fetch', args: { url: 'http://[::1]/' } }, DEFAULT_POLICY).blocked, true);
  assert.equal(evaluateToolCall({ tool: 'http_fetch', args: { url: 'http://[::ffff:127.0.0.1]:3000/internal' } }, DEFAULT_POLICY).blocked, true);
  assert.equal(evaluateToolCall({ tool: 'shell_exec', args: { command: 'git -C repo send-pack origin main' } }, DEFAULT_POLICY).blocked, true);
  assert.equal(evaluateToolCall({ tool: 'shell_exec', args: { command: 'git push --dry-run origin main' } }, DEFAULT_POLICY).blocked, false);

  const pipedEcho = evaluateToolCall({ tool: 'shell_exec', args: { command: "echo 'rm -rf /workspace/app' | bash" } }, DEFAULT_POLICY);
  assert.equal(pipedEcho.blocked, true);
  assert.ok(pipedEcho.findings.some((f) => f.ruleId === 'CAP-CMD-01'));

  const pipedFile = evaluateToolCall({ tool: 'shell_exec', args: { command: 'cat /workspace/app/install.sh | bash' } }, DEFAULT_POLICY);
  assert.equal(pipedFile.blocked, true);

  const ansiSudo = evaluateToolCall({ tool: 'shell_exec', args: { command: "bash -c $'sudo id'" } }, DEFAULT_POLICY);
  assert.equal(ansiSudo.blocked, true);
  assert.ok(ansiSudo.findings.some((f) => f.ruleId === 'CAP-CMD-01'));
});

test('36-case adversarial corpus achieves F1=1.0 and FPR=0.0, beating naive and flat baselines', () => {
  const report = runCapGateBenchmark();
  assert.equal(report.corpusCount, 36);
  assert.equal(report.detectors.capgate.precision, 1);
  assert.equal(report.detectors.capgate.recall, 1);
  assert.equal(report.detectors.capgate.f1, 1);
  assert.equal(report.detectors.capgate.fpr, 0);
  assert.ok(report.detectors.capgate.f1 > report.detectors.naiveRegex.f1);
  assert.ok(report.detectors.capgate.f1 > report.detectors.flatGate.f1);
});

test('SARIF 2.1.0 report includes driver.rules, ruleIndex, ruleIds, and valid schema version', () => {
  const report = runCapGateBenchmark();
  const sarif = buildSarifReport(report.rows);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, 'CapGate');
  assert.ok(Array.isArray(sarif.runs[0].tool.driver.rules) && sarif.runs[0].tool.driver.rules.length > 0);
  assert.ok(sarif.runs[0].results.length >= 24);
  for (const res of sarif.runs[0].results) {
    assert.match(res.ruleId, /^CAP-/);
    assert.equal(sarif.runs[0].tool.driver.rules[res.ruleIndex]?.id, res.ruleId);
  }
});

test('policy toggle allowNetwork permits allowlisted domain and blocks unknown external domain unless allowNetwork is true', () => {
  const denied = evaluateToolCall({ tool: 'http_fetch', args: { url: 'https://example.org/data' } }, DEFAULT_POLICY);
  assert.equal(denied.blocked, true);

  const permitted = evaluateToolCall(
    { tool: 'http_fetch', args: { url: 'https://example.org/data' } },
    { ...DEFAULT_POLICY, allowNetwork: true }
  );
  assert.equal(permitted.blocked, false);

  const ssrfStillBlocked = evaluateToolCall(
    { tool: 'http_fetch', args: { url: 'http://0x7f000001/admin' } },
    { ...DEFAULT_POLICY, allowNetwork: true, blockPrivateIps: true }
  );
  assert.equal(ssrfStillBlocked.blocked, true);
});

test('SSRF check covers every IPv6 spelling and targets written without an http(s) scheme', () => {
  for (const host of ['::0001', '[::0001]', '::', '0::', '::0', '::1%lo0', '64:ff9b::7f00:1', '::ffff:a00:1', 'fe80::1', 'fd00::1']) {
    assert.equal(isPrivateOrInternalHost(host), true, host);
  }
  for (const host of ['2606:4700:4700::1111', '::ffff:5db8:d822', '64:ff9b::5db8:d822', 'feed.example.com', 'fc.example.com']) {
    assert.equal(isPrivateOrInternalHost(host), false, host);
  }

  const policy = { ...DEFAULT_POLICY, allowNetwork: true };
  const fetchDecision = (url) => evaluateToolCall({ tool: 'http_fetch', args: { url } }, policy).decision;
  for (const url of ['169.254.169.254/latest/meta-data', '//169.254.169.254/x', 'ftp://127.0.0.1/', 'gopher://127.0.0.1:6379/_x', 'http://[::0001]/']) {
    assert.equal(fetchDecision(url), 'DENY', url);
  }
  assert.equal(fetchDecision('https://example.com/'), 'ALLOW');
  assert.equal(fetchDecision('example.com/docs'), 'ALLOW');

  const shellDecision = (command) => evaluateToolCall({ tool: 'shell_exec', args: { command } }, policy).decision;
  for (const command of ['curl 127.0.0.1:8080', 'curl localhost:3000', 'wget 10.0.0.5/secret', 'curl [::1]:8080', 'curl db.internal/x', 'curl -s ftp://10.0.0.5/x']) {
    assert.equal(shellDecision(command), 'DENY', command);
  }
  assert.equal(shellDecision('curl https://example.com'), 'ALLOW');
  assert.equal(shellDecision('curl -o out.txt example.com/file'), 'ALLOW');
});
