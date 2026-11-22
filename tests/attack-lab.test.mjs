import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ATTACK_CHAINS,
  ATTACK_CHAIN_MAP,
  POLICY_PRESETS,
  POLICY_PRESET_MAP,
  SINKS,
  STEP_RANK,
  runAttackChain,
  runAttackLab,
  residualSurfaceScore,
  policyTightness,
  diffPolicyLabs,
  checkMonotonicTightening,
  TIGHTENING_TRANSFORMS,
} from '../js/attack-lab.mjs';
import { DEFAULT_POLICY, GRANTABLE_TOOLS } from '../js/capability-gate.mjs';

const labs = Object.fromEntries(POLICY_PRESETS.map((p) => [p.id, runAttackLab(p.policy)]));

/* registry integrity ------------------------------------------------------- */

test('registry: exactly five presets with unique ids and names', () => {
  assert.equal(POLICY_PRESETS.length, 5);
  const ids = POLICY_PRESETS.map((p) => p.id);
  assert.equal(new Set(ids).size, 5);
  for (const p of POLICY_PRESETS) {
    assert.ok(p.name.length > 3);
    assert.ok(POLICY_PRESET_MAP[p.id] === p);
  }
});

test('registry: every preset policy grants a subset of the five tools', () => {
  for (const p of POLICY_PRESETS) {
    assert.ok(Array.isArray(p.policy.grantedTools));
    for (const t of p.policy.grantedTools) assert.ok(GRANTABLE_TOOLS.includes(t));
  }
});

test('registry: exactly six chains with unique ids and real steps', () => {
  assert.equal(ATTACK_CHAINS.length, 6);
  const ids = ATTACK_CHAINS.map((c) => c.id);
  assert.equal(new Set(ids).size, 6);
  for (const c of ATTACK_CHAINS) {
    assert.ok(ATTACK_CHAIN_MAP[c.id] === c);
    assert.ok(c.title.length > 10);
    assert.ok(c.family.length > 3);
    assert.ok(c.steps.length >= 2);
  }
});

test('registry: every chain step names a known sink, tool, label and call', () => {
  for (const c of ATTACK_CHAINS) {
    for (const s of c.steps) {
      assert.ok(SINKS.includes(s.sink), `${c.id} step sink ${s.sink}`);
      assert.ok(GRANTABLE_TOOLS.includes(s.toolCall.tool));
      assert.ok(s.label.length > 5);
      assert.ok(s.toolCall.args && Object.keys(s.toolCall.args).length > 0);
    }
  }
});

test('registry: expected chain ids exist for the six required attacks', () => {
  for (const id of ['inject-exfil', 'privesc', 'escape', 'deputy', 'forkbomb', 'metaenv']) {
    assert.ok(ATTACK_CHAIN_MAP[id], `missing chain ${id}`);
  }
});

/* per-preset blocked counts ------------------------------------------------- */

test('unrestricted: all six chains complete (0/6 blocked)', () => {
  const lab = labs.unrestricted;
  assert.equal(lab.blockedCount, 0);
  assert.equal(lab.totalChains, 6);
  for (const r of lab.results) {
    assert.equal(r.blocked, false, r.chainId);
    assert.equal(r.haltIndex, -1);
    assert.ok(r.steps.every((s) => s.status === 'allowed'));
  }
});

test('readonly: all six chains blocked (6/6)', () => {
  assert.equal(labs.readonly.blockedCount, 6);
});

test('scoped: all six chains blocked (6/6)', () => {
  assert.equal(labs.scoped.blockedCount, 6);
});

test('hitl: all six chains halted (6/6)', () => {
  assert.equal(labs.hitl.blockedCount, 6);
});

test('zerotrust: all six chains blocked (6/6)', () => {
  assert.equal(labs.zerotrust.blockedCount, 6);
});

/* per-chain, per-preset blocked matrix (30 tests) --------------------------- */

const EXPECTED_HALT = {
  unrestricted: { 'inject-exfil': -1, privesc: -1, escape: -1, deputy: -1, forkbomb: -1, metaenv: -1 },
  readonly: { 'inject-exfil': 0, privesc: 1, escape: 0, deputy: 0, forkbomb: 0, metaenv: 0 },
  scoped: { 'inject-exfil': 1, privesc: 1, escape: 0, deputy: 0, forkbomb: 0, metaenv: 0 },
  hitl: { 'inject-exfil': 0, privesc: 0, escape: 0, deputy: 0, forkbomb: 0, metaenv: 0 },
  zerotrust: { 'inject-exfil': 0, privesc: 1, escape: 0, deputy: 0, forkbomb: 5, metaenv: 0 },
};

for (const preset of POLICY_PRESETS) {
  for (const chain of ATTACK_CHAINS) {
    const want = EXPECTED_HALT[preset.id][chain.id];
    test(`matrix: ${preset.id} x ${chain.id} haltIndex=${want}`, () => {
      const res = labs[preset.id].results.find((r) => r.chainId === chain.id);
      assert.equal(res.haltIndex, want);
      assert.equal(res.blocked, want >= 0);
    });
  }
}

/* step-level statuses ------------------------------------------------------- */

test('steps: unrestricted marks every step of every chain allowed', () => {
  for (const r of labs.unrestricted.results) {
    for (const s of r.steps) {
      assert.equal(s.status, 'allowed');
      assert.equal(s.decision, 'ALLOW');
    }
  }
});

test('steps: scoped lets the injected allowlisted fetch through then denies the secret read', () => {
  const r = labs.scoped.results.find((x) => x.chainId === 'inject-exfil');
  assert.equal(r.steps[0].status, 'allowed');
  assert.equal(r.steps[0].decision, 'ALLOW');
  assert.equal(r.steps[1].status, 'denied');
  assert.ok(r.steps[1].ruleIds.includes('CAP-SECRET-01'));
  assert.equal(r.steps[2].status, 'skipped');
});

test('steps: readonly denies chain-1 at the egress step', () => {
  const r = labs.readonly.results.find((x) => x.chainId === 'inject-exfil');
  assert.equal(r.steps[0].status, 'denied');
  assert.ok(r.steps[0].ruleIds.includes('CAP-NET-01'));
});

test('steps: zerotrust fork bomb shows five allows, a budget halt, then skips', () => {
  const r = labs.zerotrust.results.find((x) => x.chainId === 'forkbomb');
  assert.equal(r.haltKind, 'budget');
  for (let i = 0; i < 5; i += 1) assert.equal(r.steps[i].status, 'allowed');
  assert.equal(r.steps[5].status, 'budget');
  assert.ok(r.steps[5].ruleIds.includes('LAB-BUDGET-01'));
  for (let i = 6; i < r.steps.length; i += 1) assert.equal(r.steps[i].status, 'skipped');
});

test('steps: hitl holds every chain at step 0 when the call is otherwise clean', () => {
  for (const id of ['inject-exfil', 'privesc', 'forkbomb']) {
    const r = labs.hitl.results.find((x) => x.chainId === id);
    assert.equal(r.steps[0].status, 'held', id);
    assert.ok(r.steps[0].ruleIds.includes('CAP-POLICY-04'));
  }
});

test('steps: hitl still denies outright-dangerous first steps', () => {
  const r = labs.hitl.results.find((x) => x.chainId === 'escape');
  assert.equal(r.steps[0].status, 'denied');
  assert.ok(r.steps[0].ruleIds.includes('CAP-PATH-01'));
});

test('steps: zerotrust privesc reads the file then hits the write grant', () => {
  const r = labs.zerotrust.results.find((x) => x.chainId === 'privesc');
  assert.equal(r.steps[0].status, 'allowed');
  assert.equal(r.steps[1].status, 'denied');
  assert.ok(r.steps[1].ruleIds.includes('CAP-POLICY-02'));
});

test('steps: scoped forkbomb stops at step 0 because shell_exec is not granted', () => {
  const r = labs.scoped.results.find((x) => x.chainId === 'forkbomb');
  assert.equal(r.steps[0].status, 'denied');
  assert.ok(r.steps[0].ruleIds.includes('CAP-POLICY-02'));
});

test('steps: metaenv secret-env exfil is denied under zerotrust at step 0', () => {
  const r = labs.zerotrust.results.find((x) => x.chainId === 'metaenv');
  assert.equal(r.steps[0].status, 'denied');
  assert.ok(r.steps[0].ruleIds.length > 0);
});

test('steps: skipped steps carry no decision or findings', () => {
  const r = labs.scoped.results.find((x) => x.chainId === 'inject-exfil');
  const skipped = r.steps.filter((s) => s.status === 'skipped');
  for (const s of skipped) {
    assert.equal(s.decision, null);
    assert.deepEqual(s.ruleIds, []);
  }
});

/* metrics -------------------------------------------------------------------- */

test('metrics: residual surface is 100 under unrestricted', () => {
  assert.equal(labs.unrestricted.residualSurface, 100);
});

test('metrics: residual surface is much lower under every hardened preset', () => {
  for (const id of ['readonly', 'scoped', 'hitl', 'zerotrust']) {
    assert.ok(labs[id].residualSurface < 40, `${id} residual ${labs[id].residualSurface}`);
  }
});

test('metrics: hitl has the lowest residual surface (held at step 0)', () => {
  assert.equal(labs.hitl.residualSurface, 0);
});

test('metrics: tightness is near zero under unrestricted and high elsewhere', () => {
  assert.ok(labs.unrestricted.tightness.score < 15);
  for (const id of ['readonly', 'scoped', 'hitl', 'zerotrust']) {
    assert.ok(labs[id].tightness.score >= 55, `${id} tightness ${labs[id].tightness.score}`);
  }
});

test('metrics: tightness ordering places unrestricted strictly lowest', () => {
  for (const id of ['readonly', 'scoped', 'hitl', 'zerotrust']) {
    assert.ok(labs[id].tightness.score > labs.unrestricted.tightness.score);
  }
});

test('metrics: tightness dimensions cover 13 guard axes summing to the score', () => {
  const t = policyTightness(POLICY_PRESET_MAP.zerotrust.policy);
  assert.equal(t.dimensions.length, 13);
  assert.equal(t.dimensions.reduce((s, d) => s + d.earned, 0), t.score);
  assert.equal(t.maxScore, 100);
  for (const d of t.dimensions) assert.ok(d.earned <= d.max);
});

test('metrics: residualSurfaceScore handles an empty results list', () => {
  assert.equal(residualSurfaceScore([], []), 0);
});

test('metrics: tightness degrades gracefully on a sparse policy object', () => {
  const t = policyTightness({});
  assert.ok(t.score >= 0 && t.score <= 100);
});

/* runAttackChain mechanics ----------------------------------------------------- */

test('mechanics: empty chain completes with no halt', () => {
  const r = runAttackChain({ id: 'x', title: 'x', steps: [] }, DEFAULT_POLICY);
  assert.equal(r.blocked, false);
  assert.equal(r.haltIndex, -1);
  assert.deepEqual(r.steps, []);
});

test('mechanics: missing policy falls back to the default policy', () => {
  const r = runAttackChain(ATTACK_CHAIN_MAP.escape);
  assert.equal(r.blocked, true);
  assert.equal(r.steps[0].status, 'denied');
});

test('mechanics: maxChainSteps of 0 means no budget', () => {
  const r = runAttackChain(ATTACK_CHAIN_MAP.forkbomb, { ...DEFAULT_POLICY, maxChainSteps: 0 });
  assert.notEqual(r.haltKind, 'budget');
});

test('mechanics: budget of 1 halts the second step of any granted chain', () => {
  const p = { ...POLICY_PRESET_MAP.unrestricted.policy, maxChainSteps: 1 };
  const r = runAttackChain(ATTACK_CHAIN_MAP.forkbomb, p);
  assert.equal(r.steps[0].status, 'allowed');
  assert.equal(r.steps[1].status, 'budget');
  assert.equal(r.haltIndex, 1);
});

test('mechanics: chain result preserves id, title and family', () => {
  const r = runAttackChain(ATTACK_CHAIN_MAP.deputy, POLICY_PRESET_MAP.scoped.policy);
  assert.equal(r.chainId, 'deputy');
  assert.equal(r.title, ATTACK_CHAIN_MAP.deputy.title);
  assert.equal(r.family, ATTACK_CHAIN_MAP.deputy.family);
});

test('mechanics: haltRule is the first rule id of the halting step', () => {
  const r = labs.scoped.results.find((x) => x.chainId === 'inject-exfil');
  assert.equal(r.haltRule, 'CAP-SECRET-01');
});

/* policy diff ------------------------------------------------------------------ */

test('diff: rows cover every chain in order', () => {
  const d = diffPolicyLabs(labs.unrestricted, labs.scoped);
  assert.equal(d.rows.length, 6);
  assert.deepEqual(d.rows.map((r) => r.chainId), ATTACK_CHAINS.map((c) => c.id));
});

test('diff: unrestricted vs scoped reports six tightened chains', () => {
  const d = diffPolicyLabs(labs.unrestricted, labs.scoped);
  assert.equal(d.tightened, 6);
  assert.equal(d.loosened, 0);
});

test('diff: scoped vs unrestricted reports six loosened chains', () => {
  const d = diffPolicyLabs(labs.scoped, labs.unrestricted);
  assert.equal(d.loosened, 6);
  assert.equal(d.tightened, 0);
});

test('diff: identical policies report six unchanged chains', () => {
  const d = diffPolicyLabs(labs.scoped, labs.scoped);
  assert.equal(d.tightened, 0);
  assert.equal(d.loosened, 0);
  for (const r of d.rows) assert.equal(r.chainDelta, 'same');
});

test('diff: scoped vs zerotrust differs on the fork-bomb mechanism', () => {
  const d = diffPolicyLabs(labs.scoped, labs.zerotrust);
  const row = d.rows.find((r) => r.chainId === 'forkbomb');
  assert.equal(row.aHalt, 0);
  assert.equal(row.bHalt, 5);
  assert.equal(row.bHaltKind, 'budget');
  const step5 = row.steps[5];
  assert.equal(step5.aStatus, 'skipped');
  assert.equal(step5.bStatus, 'budget');
});

test('diff: step deltas classify correctly between presets', () => {
  const d = diffPolicyLabs(labs.unrestricted, labs.hitl);
  const row = d.rows.find((r) => r.chainId === 'inject-exfil');
  assert.equal(row.steps[0].delta, 'tightened');
  assert.equal(row.steps[0].aStatus, 'allowed');
  assert.ok(['held', 'denied'].includes(row.steps[0].bStatus));
});

test('diff: step rank map covers every status', () => {
  for (const s of ['allowed', 'denied', 'held', 'budget', 'skipped']) {
    assert.ok(Number.isFinite(STEP_RANK[s]));
  }
});

/* monotonicity ------------------------------------------------------------------ */

for (const t of TIGHTENING_TRANSFORMS) {
  test(`monotonic: ${t.id} never opens a blocked chain on the default policy`, () => {
    const r = checkMonotonicTightening(DEFAULT_POLICY, t);
    assert.equal(r.monotonic, true, JSON.stringify(r.violations));
  });
}

for (const t of TIGHTENING_TRANSFORMS) {
  test(`monotonic: ${t.id} is monotonic on the unrestricted baseline`, () => {
    const r = checkMonotonicTightening(POLICY_PRESET_MAP.unrestricted.policy, t);
    assert.equal(r.monotonic, true, JSON.stringify(r.violations));
  });
}

for (const t of TIGHTENING_TRANSFORMS) {
  test(`monotonic: ${t.id} is monotonic on the zero-trust sandbox`, () => {
    const r = checkMonotonicTightening(POLICY_PRESET_MAP.zerotrust.policy, t);
    assert.equal(r.monotonic, true, JSON.stringify(r.violations));
  });
}

test('monotonic: transforms registry has unique ids and names', () => {
  const ids = TIGHTENING_TRANSFORMS.map((t) => t.id);
  assert.equal(new Set(ids).size, ids.length);
  assert.ok(ids.length >= 10);
  for (const t of TIGHTENING_TRANSFORMS) assert.ok(t.name.length > 5);
});

test('monotonic: checkMonotonicTightening returns the tightened policy', () => {
  const r = checkMonotonicTightening(POLICY_PRESET_MAP.unrestricted.policy, TIGHTENING_TRANSFORMS[0]);
  assert.equal(r.tightened.enforceWorkspaceBoundary, true);
});
