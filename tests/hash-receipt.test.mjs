import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { sha256Hex, hmacSha256Hex, canonicalJson } from '../js/hash.mjs';
import { buildReceipt, verifyReceipt, TOOL_VERSION } from '../js/receipt.mjs';
import { DEFAULT_POLICY, evaluateToolCall } from '../js/capability-gate.mjs';

test('dependency-free SHA-256 matches Node crypto on known and unicode vectors', () => {
  const vectors = ['', 'abc', 'hello world', 'a'.repeat(1000), 'unicode: é中文 😀', JSON.stringify({ b: 2, a: 1 })];
  for (const s of vectors) {
    assert.equal(sha256Hex(s), createHash('sha256').update(s, 'utf8').digest('hex'));
  }
});

test('dependency-free HMAC-SHA256 matches Node crypto including long keys', () => {
  for (const [key, msg] of [['key', 'hello'], ['a'.repeat(100), 'message'], ['unicodeé', 'payload中']]) {
    assert.equal(hmacSha256Hex(key, msg), createHmac('sha256', key).update(msg, 'utf8').digest('hex'));
  }
});

test('canonicalJson sorts object keys recursively and preserves arrays', () => {
  assert.equal(canonicalJson({ b: 1, a: [{ z: 2, y: 1 }], c: null }), canonicalJson({ a: [{ y: 1, z: 2 }], b: 1, c: null }));
  assert.notEqual(canonicalJson({ b: 1, a: 2 }), JSON.stringify({ b: 1, a: 2 }));
  assert.equal(canonicalJson([3, 1, 2]), '[3,1,2]');
});

test('receipt verifies as VALID after JSON round trip', () => {
  const receipt = makeReceipt();
  assert.equal(verifyReceipt(receipt).status, 'VALID');
  assert.equal(verifyReceipt(JSON.parse(JSON.stringify(receipt))).status, 'VALID');
});

test('receipt detects tampering of policy, tool call, evaluation, benchmark and digest', () => {
  const base = makeReceipt();
  const mutations = [
    (r) => { r.policy.workspaceRoot = '/etc'; },
    (r) => { r.inspectedToolCall.args.command = 'echo hi'; },
    (r) => { r.evaluation.riskScore = 0; },
    (r) => { r.benchmark.corpusCount = 99; },
    (r) => { r.digest.signature = 'deadbeef'; },
    (r) => { r.digest.canonicalJson = 'deadbeef'; },
    (r) => { r.version = '0.0.0'; },
  ];
  for (const mutate of mutations) {
    const r = structuredClone(base);
    mutate(r);
    const result = verifyReceipt(r);
    assert.equal(result.status, 'TAMPERED', JSON.stringify(r));
    assert.ok(result.changedFields.length > 0);
  }
});

test('receipt rejects malformed input', () => {
  assert.equal(verifyReceipt(null).status, 'MALFORMED');
  assert.equal(verifyReceipt({ foo: 1 }).status, 'MALFORMED');
  assert.equal(verifyReceipt([]).status, 'MALFORMED');
  assert.equal(verifyReceipt({ digest: {}, tool: 'x' }).status, 'MALFORMED');
});

test('receipt reports unexpected extra fields as tampered context', () => {
  const r = makeReceipt();
  r.injected = 'x';
  const result = verifyReceipt(r);
  assert.equal(result.status, 'TAMPERED');
  assert.match(result.detail, /injected/);
});

function makeReceipt() {
  const toolCall = { tool: 'shell_exec', args: { command: 'bash -c "rm -rf /workspace/app"' } };
  const ev = evaluateToolCall(toolCall, DEFAULT_POLICY);
  return buildReceipt({
    policy: DEFAULT_POLICY,
    toolCall,
    evaluation: ev,
    benchmark: { version: TOOL_VERSION, corpusCount: 36, detectors: { capgate: { f1: 1 } } },
  });
}
