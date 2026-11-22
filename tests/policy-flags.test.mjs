import test from 'node:test';
import assert from 'node:assert/strict';
import {
  DEFAULT_POLICY,
  GRANTABLE_TOOLS,
  evaluateToolCall,
} from '../js/capability-gate.mjs';

const benignRead = { tool: 'fs_read', args: { path: '/workspace/app/src/index.js' } };
const benignWrite = { tool: 'fs_write', args: { path: '/workspace/app/out/result.txt' } };
const traversalRead = { tool: 'fs_read', args: { path: '/workspace/app/../../etc/hostname' } };
const envRead = { tool: 'fs_read', args: { path: '/workspace/app/.env' } };
const lsCall = { tool: 'shell_exec', args: { command: 'ls /workspace/app' } };
const fetchCall = { tool: 'http_fetch', args: { url: 'https://api.github.com/x' } };
const envVarCall = { tool: 'env_read', args: { name: 'NODE_ENV' } };

/* grantedTools ----------------------------------------------------------- */

for (const tool of GRANTABLE_TOOLS) {
  test(`grants: ${tool} denied with CAP-POLICY-02 when not in grantedTools`, () => {
    const policy = { ...DEFAULT_POLICY, grantedTools: GRANTABLE_TOOLS.filter((t) => t !== tool) };
    const call = { fs_read: benignRead, fs_write: benignWrite, http_fetch: fetchCall, env_read: envVarCall, shell_exec: lsCall }[tool];
    const ev = evaluateToolCall(call, policy);
    assert.equal(ev.blocked, true);
    assert.equal(ev.decision, 'DENY');
    assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-POLICY-02'));
  });
}

test('grants: an explicitly granted tool still evaluates content rules', () => {
  const policy = { ...DEFAULT_POLICY, grantedTools: ['fs_read'] };
  const ok = evaluateToolCall(benignRead, policy);
  assert.equal(ok.decision, 'ALLOW');
  const bad = evaluateToolCall(envRead, policy);
  assert.equal(bad.blocked, true);
  assert.ok(bad.findings.some((f) => f.ruleId === 'CAP-SECRET-01'));
});

test('grants: empty grant list denies every tool call', () => {
  const policy = { ...DEFAULT_POLICY, grantedTools: [] };
  for (const call of [benignRead, benignWrite, fetchCall, envVarCall, lsCall]) {
    const ev = evaluateToolCall(call, policy);
    assert.equal(ev.blocked, true, `${call.tool} should be denied`);
    assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-POLICY-02'));
  }
});

test('grants: single-tool grant as a string is sanitized to an array', () => {
  const ev = evaluateToolCall(benignRead, { ...DEFAULT_POLICY, grantedTools: 'fs_read' });
  assert.equal(ev.decision, 'ALLOW');
  const denied = evaluateToolCall(benignWrite, { ...DEFAULT_POLICY, grantedTools: 'fs_read' });
  assert.equal(denied.blocked, true);
});

test('grants: malformed grantedTools falls back to all tools granted', () => {
  const ev = evaluateToolCall(benignRead, { ...DEFAULT_POLICY, grantedTools: 42 });
  assert.equal(ev.decision, 'ALLOW');
});

test('grants: unknown grant names in the list grant nothing extra', () => {
  const policy = { ...DEFAULT_POLICY, grantedTools: ['fs_read', 'teleport'] };
  const denied = evaluateToolCall(lsCall, policy);
  assert.ok(denied.findings.some((f) => f.ruleId === 'CAP-POLICY-02'));
});

test('grants: default policy grants all five tools', () => {
  for (const call of [benignRead, benignWrite, fetchCall, envVarCall]) {
    const ev = evaluateToolCall(call, DEFAULT_POLICY);
    assert.ok(!ev.findings.some((f) => f.ruleId === 'CAP-POLICY-02'));
  }
});

/* allowFsWrite ----------------------------------------------------------- */

test('writes: allowFsWrite=false denies fs_write inside the workspace', () => {
  const ev = evaluateToolCall(benignWrite, { ...DEFAULT_POLICY, allowFsWrite: false });
  assert.equal(ev.decision, 'DENY');
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-POLICY-03'));
});

test('writes: allowFsWrite=false leaves fs_read alone', () => {
  const ev = evaluateToolCall(benignRead, { ...DEFAULT_POLICY, allowFsWrite: false });
  assert.equal(ev.decision, 'ALLOW');
});

test('writes: allowFsWrite=true is the default and allows workspace writes', () => {
  const ev = evaluateToolCall(benignWrite, DEFAULT_POLICY);
  assert.equal(ev.decision, 'ALLOW');
});

test('writes: allowFsWrite=false stacks with outside-workspace findings', () => {
  const ev = evaluateToolCall({ tool: 'fs_write', args: { path: '/etc/x' } }, { ...DEFAULT_POLICY, allowFsWrite: false });
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-POLICY-03'));
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-PATH-02'));
});

/* enforceWorkspaceBoundary ------------------------------------------------ */

test('boundary: off drops CAP-PATH findings for fs_read traversal', () => {
  const p = { ...DEFAULT_POLICY, enforceWorkspaceBoundary: false };
  const ev = evaluateToolCall({ tool: 'fs_read', args: { path: '/workspace/app/../../etc/hostname' } }, p);
  assert.ok(!ev.findings.some((f) => /^CAP-PATH-/.test(f.ruleId)), 'path findings should be filtered');
});

test('boundary: off keeps CAP-SECRET-01 findings intact', () => {
  const p = { ...DEFAULT_POLICY, enforceWorkspaceBoundary: false };
  const ev = evaluateToolCall(envRead, p);
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-SECRET-01'));
  assert.equal(ev.blocked, true);
});

test('boundary: on is the default and traversal stays blocked', () => {
  const ev = evaluateToolCall(traversalRead, DEFAULT_POLICY);
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-PATH-01'));
});

test('boundary: off also filters traversal findings inside shell args', () => {
  const p = { ...DEFAULT_POLICY, enforceWorkspaceBoundary: false, workspaceRoot: '/' };
  const ev = evaluateToolCall({ tool: 'shell_exec', args: { command: 'cat ../../etc/hostname' } }, p);
  assert.ok(!ev.findings.some((f) => /^CAP-PATH-/.test(f.ruleId)));
});

test('boundary: off plus sensitive guard off gives a clean allow', () => {
  const p = { ...DEFAULT_POLICY, enforceWorkspaceBoundary: false, blockSensitivePaths: false, workspaceRoot: '/' };
  const ev = evaluateToolCall(envRead, p);
  assert.equal(ev.decision, 'ALLOW');
  assert.equal(ev.findingCount, 0);
});

/* blockSensitivePaths ----------------------------------------------------- */

test('sensitive: off drops CAP-SECRET-01 for direct secret reads', () => {
  const p = { ...DEFAULT_POLICY, blockSensitivePaths: false };
  const ev = evaluateToolCall(envRead, p);
  assert.ok(!ev.findings.some((f) => f.ruleId === 'CAP-SECRET-01'));
});

test('sensitive: off does not drop secret-env CAP-SECRET-02 findings', () => {
  const p = { ...DEFAULT_POLICY, blockSensitivePaths: false };
  const ev = evaluateToolCall({ tool: 'env_read', args: { name: 'AWS_SECRET_ACCESS_KEY' } }, p);
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-SECRET-02'));
});

test('sensitive: on is the default and .env reads stay denied', () => {
  const ev = evaluateToolCall(envRead, DEFAULT_POLICY);
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-SECRET-01'));
  assert.equal(ev.decision, 'DENY');
});

test('sensitive: off filters sensitive shell path args but keeps boundary', () => {
  const p = { ...DEFAULT_POLICY, blockSensitivePaths: false };
  const ev = evaluateToolCall({ tool: 'shell_exec', args: { command: 'cat /etc/passwd' } }, p);
  assert.ok(!ev.findings.some((f) => f.ruleId === 'CAP-SECRET-01'));
  assert.ok(ev.findings.some((f) => /^CAP-PATH-/.test(f.ruleId)), 'boundary still catches /etc');
});

/* requireHumanApproval ---------------------------------------------------- */

test('approval: benign call escalates to HELD instead of running', () => {
  const ev = evaluateToolCall(benignRead, { ...DEFAULT_POLICY, requireHumanApproval: true });
  assert.equal(ev.decision, 'ESCALATE');
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-POLICY-04' && f.severity === 'medium'));
  assert.equal(ev.blocked, true);
});

test('approval: denied call stays DENY, not ESCALATE, under the gate', () => {
  const ev = evaluateToolCall(envRead, { ...DEFAULT_POLICY, requireHumanApproval: true });
  assert.equal(ev.decision, 'DENY');
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-SECRET-01'));
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-POLICY-04'));
});

test('approval: does not re-hold an unrecognised tool call', () => {
  const ev = evaluateToolCall({ tool: 'kernel_exec', args: {} }, { ...DEFAULT_POLICY, requireHumanApproval: true });
  assert.equal(ev.decision, 'DENY');
  assert.ok(!ev.findings.some((f) => f.ruleId === 'CAP-POLICY-04'));
});

test('approval: false is the default and benign calls stay ALLOW', () => {
  const ev = evaluateToolCall(benignRead, DEFAULT_POLICY);
  assert.equal(ev.decision, 'ALLOW');
});

test('approval: every known tool is held, including env_read', () => {
  const p = { ...DEFAULT_POLICY, requireHumanApproval: true };
  for (const call of [benignRead, benignWrite, fetchCall, envVarCall, lsCall]) {
    const ev = evaluateToolCall(call, p);
    assert.ok(ev.decision !== 'ALLOW', `${call.tool} should not auto-run`);
  }
});

/* combined and edge cases -------------------------------------------------- */

test('combined: ungranted tool + write-off stacks both policy findings', () => {
  const p = { ...DEFAULT_POLICY, grantedTools: ['fs_read'], allowFsWrite: false };
  const ev = evaluateToolCall(benignWrite, p);
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-POLICY-02'));
  assert.ok(ev.findings.some((f) => f.ruleId === 'CAP-POLICY-03'));
});

test('combined: finding count and risk score derive from governed findings', () => {
  const p = { ...DEFAULT_POLICY, blockSensitivePaths: false };
  const ev = evaluateToolCall(envRead, p);
  assert.equal(ev.findingCount, ev.findings.length);
  assert.ok(ev.riskScore <= 100);
});

test('combined: governed filter cannot revive findings, only drop them', () => {
  const base = evaluateToolCall(envRead, DEFAULT_POLICY);
  const loose = evaluateToolCall(envRead, { ...DEFAULT_POLICY, blockSensitivePaths: false });
  assert.ok(loose.findings.length <= base.findings.length);
  assert.equal(loose.decision, 'ALLOW');
});

test('combined: new policy keys do not leak into DEFAULT_POLICY shape checks', () => {
  assert.ok(Array.isArray(DEFAULT_POLICY.grantedTools));
  assert.equal(DEFAULT_POLICY.allowFsWrite, true);
  assert.equal(DEFAULT_POLICY.enforceWorkspaceBoundary, true);
  assert.equal(DEFAULT_POLICY.blockSensitivePaths, true);
  assert.equal(DEFAULT_POLICY.requireHumanApproval, false);
});
