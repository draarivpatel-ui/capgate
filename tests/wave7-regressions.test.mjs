import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson } from '../js/hash.mjs';
import {
  DEFAULT_POLICY,
  evaluateToolCall,
  hostCandidatesFromArg,
} from '../js/capability-gate.mjs';
import { policyTightness } from '../js/attack-lab.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const NET = { ...DEFAULT_POLICY, allowNetwork: true };
const sh = (command) => ({ tool: 'shell_exec', args: { command } });

test('wave7: canonicalJson mirrors JSON.stringify when toJSON returns an object-skipped value', () => {
  assert.equal(canonicalJson({ a: { toJSON: () => undefined } }), '{}');
  assert.equal(canonicalJson({ a: { toJSON: () => () => 1 } }), '{}');
  assert.equal(canonicalJson({ a: { toJSON: () => Symbol('x') } }), '{}');
  assert.equal(canonicalJson({ a: { toJSON: () => undefined }, b: 1 }), '{"b":1}');
  assert.equal(canonicalJson([{ toJSON: () => undefined }]), '[null]');
});

test('wave7: shell host extraction sees bare IPv6 literals', () => {
  assert.deepEqual(hostCandidatesFromArg('fe80::1'), ['fe80::1']);
  assert.deepEqual(hostCandidatesFromArg('user@fe80::1'), ['fe80::1']);
  assert.deepEqual(hostCandidatesFromArg('@fe80::1'), ['fe80::1']);
  assert.deepEqual(hostCandidatesFromArg('user@[fe80::1%eth0]'), ['[fe80::1%eth0]']);
  assert.deepEqual(hostCandidatesFromArg('[fe80::1%25eth0]'), ['[fe80::1%25eth0]']);
});

test('wave7: ssh and dig cannot bypass private-IP blocking with bare IPv6', () => {
  for (const command of [
    'ssh user@fe80::1',
    'ssh fe80::1',
    'ssh user@[fe80::1%eth0]',
    'dig @fe80::1 example.com',
  ]) {
    const result = evaluateToolCall(sh(command), NET);
    assert.equal(result.decision, 'DENY', `${command} -> ${result.decision}`);
    assert.ok(result.findings.some((f) => f.ruleId === 'CAP-SSRF-01'), `${command} missing CAP-SSRF-01`);
  }
});

test('wave7: an empty command allowlist is scored as maximally narrow, not zero', () => {
  const policy = { ...DEFAULT_POLICY, allowedCommands: [] };
  const dim = policyTightness(policy).dimensions.find((d) => d.id === 'cmdallowlist');
  assert.equal(dim.earned, dim.max);
});

test('wave7: clickable attack-chain cards are keyboard operable and expose pressed state', () => {
  const labJs = fs.readFileSync(path.join(ROOT, 'js/lab.js'), 'utf8');
  assert.match(labJs, /card\.tabIndex\s*=\s*0/);
  assert.match(labJs, /setAttribute\('role',\s*'button'\)/);
  assert.match(labJs, /setAttribute\('aria-pressed'/);
  assert.match(labJs, /addEventListener\('keydown'/);
  assert.match(labJs, /ev\.key\s*===\s*'Enter'/);
  assert.match(labJs, /ev\.key\s*===\s*' '/);
});

