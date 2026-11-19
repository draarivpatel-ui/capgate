import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_POLICY, evaluateToolCall, evaluateNaiveRegex, evaluateFlatGate } from '../js/capability-gate.mjs';
import { ADVERSARIAL_CORPUS } from '../js/corpus.mjs';
import { runCapGateBenchmark } from '../js/benchmark.mjs';
import {
  gaugeArc,
  buildDecisionTrace,
  buildVerdicts,
  buildDetectorCards,
  buildFamilyMatrix,
  proofCases,
} from '../js/viewmodel.mjs';

const byId = (id) => ADVERSARIAL_CORPUS.find((c) => c.id === id);
const bench = runCapGateBenchmark(ADVERSARIAL_CORPUS, DEFAULT_POLICY);

test('gaugeArc clamps the score, draws no fill at zero, and grows with the score', () => {
  assert.equal(gaugeArc(-5).value, 0);
  assert.equal(gaugeArc(250).value, 100);
  assert.equal(gaugeArc(0).fill, '');
  assert.match(gaugeArc(60).fill, /^M [\d.]+ [\d.]+ A 48 48 0 [01] 1 [\d.]+ [\d.]+$/);
  assert.equal(gaugeArc(100).fill, gaugeArc(100).track);
  assert.equal(gaugeArc('not a number').value, 0);
});

test('decision trace follows the unwrapped layers and pins each rule to the layer that tripped it', () => {
  const item = byId('wrap-03-xargs-sh-c');
  const ev = evaluateToolCall(item.toolCall, DEFAULT_POLICY);
  const nodes = buildDecisionTrace(item.toolCall, ev);
  assert.deepEqual(nodes.map((n) => n.kind), ['input', 'layer', 'layer', 'layer', 'decision']);
  const rm = nodes.find((n) => n.label === 'rm');
  assert.equal(rm.depth, 1);
  assert.equal(rm.rule, 'CAP-CMD-01');
  assert.equal(rm.severity, 'critical');
  assert.equal(rm.trail, 'sh > -c > rm');
  assert.equal(nodes.at(-1).label, 'DENY');
  assert.equal(nodes.at(-1).blocked, true);
});

test('non-shell findings appear as rule nodes and benign calls end in ALLOW', () => {
  const ssrf = byId('ssrf-02-hex-metadata');
  const nodes = buildDecisionTrace(ssrf.toolCall, evaluateToolCall(ssrf.toolCall, DEFAULT_POLICY));
  assert.deepEqual(nodes.map((n) => n.kind), ['input', 'rule', 'decision']);
  assert.equal(nodes[1].rule, 'CAP-SSRF-01');
  const benign = byId('benign-01-npm-test');
  const ok = buildDecisionTrace(benign.toolCall, evaluateToolCall(benign.toolCall, DEFAULT_POLICY));
  assert.equal(ok.at(-1).label, 'ALLOW');
  assert.equal(ok.at(-1).blocked, false);
  assert.equal(ok.filter((n) => n.rule).length, 0);
});

test('every corpus case yields a trace whose decision matches the engine', () => {
  for (const item of ADVERSARIAL_CORPUS) {
    const ev = evaluateToolCall(item.toolCall, DEFAULT_POLICY);
    const nodes = buildDecisionTrace(item.toolCall, ev);
    assert.equal(nodes[0].kind, 'input');
    assert.equal(nodes.at(-1).blocked, ev.blocked, item.id);
    const ruleCount = nodes.filter((n) => n.rule).length;
    assert.equal(ruleCount, ev.findings.length, `${item.id} shows every finding once`);
  }
});

test('verdicts mark the baselines wrong on a hidden wrapper attack', () => {
  const item = byId('wrap-02-timeout-nohup-pkill');
  const calls = {
    naive: evaluateNaiveRegex(item.toolCall),
    flat: evaluateFlatGate(item.toolCall, DEFAULT_POLICY),
    capgate: evaluateToolCall(item.toolCall, DEFAULT_POLICY),
  };
  const v = buildVerdicts(calls, true);
  assert.deepEqual(v.map((x) => [x.key, x.verdict, x.correct]), [
    ['naiveRegex', 'ALLOW', false],
    ['flatGate', 'ALLOW', false],
    ['capgate', 'BLOCK', true],
  ]);
});

test('proof cases are exactly the attacks CapGate blocks and both baselines miss', () => {
  const ids = proofCases(bench);
  assert.equal(ids.length, 13);
  for (const id of ids) {
    const row = bench.rows.find((r) => r.id === id);
    assert.ok(row.expectedBlocked && row.capBlocked && !row.naiveBlocked && !row.flatBlocked, id);
  }
});

test('detector cards and family matrix carry the benchmark numbers unchanged', () => {
  const cards = buildDetectorCards(bench);
  assert.deepEqual(cards.map((c) => c.key), ['capgate', 'flatGate', 'naiveRegex']);
  assert.equal(cards[0].caught, '24 of 24 attacks blocked');
  assert.equal(cards[2].metrics.find((m) => m.name === 'Recall').value, 0.4167);
  assert.deepEqual(cards[2].confusion, { tp: 10, fp: 2, tn: 10, fn: 14 });
  const matrix = buildFamilyMatrix(bench);
  assert.equal(matrix.length, 7);
  assert.equal(matrix.reduce((n, r) => n + r.total, 0), 36);
  for (const row of matrix) assert.equal(row.cells[0].share, 1, row.family);
});
