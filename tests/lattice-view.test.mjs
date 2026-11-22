import test from 'node:test';
import assert from 'node:assert/strict';
import {
  LATTICE_NODES,
  LATTICE_EDGES,
  LATTICE_VIEWBOX,
  buildLatticeModel,
  classifyEdge,
  latticeStatusCounts,
} from '../js/lattice-view.mjs';
import { runAttackChain, ATTACK_CHAIN_MAP, POLICY_PRESETS, POLICY_PRESET_MAP } from '../js/attack-lab.mjs';
import { DEFAULT_POLICY, GRANTABLE_TOOLS } from '../js/capability-gate.mjs';

/* geometry ------------------------------------------------------------------ */

test('geometry: ten nodes across three columns with unique ids', () => {
  assert.equal(LATTICE_NODES.length, 10);
  assert.equal(new Set(LATTICE_NODES.map((n) => n.id)).size, 10);
  assert.equal(LATTICE_NODES.filter((n) => n.kind === 'agent').length, 1);
  assert.equal(LATTICE_NODES.filter((n) => n.kind === 'tool').length, 5);
  assert.equal(LATTICE_NODES.filter((n) => n.kind === 'sink').length, 4);
});

test('geometry: every node sits inside the viewBox', () => {
  for (const n of LATTICE_NODES) {
    assert.ok(n.cx >= 0 && n.cx <= LATTICE_VIEWBOX.width, n.id);
    assert.ok(n.cy >= 0 && n.cy <= LATTICE_VIEWBOX.height, n.id);
  }
});

test('geometry: all five grantable tools have a lattice node', () => {
  const toolNodes = LATTICE_NODES.filter((n) => n.kind === 'tool').map((n) => n.id);
  for (const t of GRANTABLE_TOOLS) assert.ok(toolNodes.includes(t), t);
});

test('geometry: fifteen edges with unique ids', () => {
  assert.equal(LATTICE_EDGES.length, 15);
  assert.equal(new Set(LATTICE_EDGES.map((e) => e.id)).size, 15);
});

test('geometry: edge endpoints reference existing nodes', () => {
  const ids = new Set(LATTICE_NODES.map((n) => n.id));
  for (const e of LATTICE_EDGES) {
    assert.ok(ids.has(e.from), e.id);
    assert.ok(ids.has(e.to), e.id);
  }
});

test('geometry: built edge paths are cubic beziers between node columns', () => {
  const m = buildLatticeModel(DEFAULT_POLICY);
  for (const e of m.edges) {
    assert.match(e.d, /^M [\d.]+ [\d.]+ C [\d.]+ [\d.]+, [\d.]+ [\d.]+, [\d.]+ [\d.]+$/);
    assert.ok(e.x2 > e.x1, e.id);
  }
});

/* classification -------------------------------------------------------------- */

test('classify: unrestricted opens all fifteen edges', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.unrestricted.policy);
  assert.equal(m.edges.filter((e) => e.status === 'open').length, 15);
});

test('classify: zerotrust grants only fs_read and shell_exec agent edges', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.zerotrust.policy);
  const grants = m.edges.filter((e) => e.kind === 'grant');
  assert.equal(grants.filter((e) => e.status === 'open').length, 2);
  for (const id of ['agent->fs_read', 'agent->shell_exec']) {
    assert.equal(grants.find((e) => e.id === id).status, 'open');
  }
  for (const id of ['agent->fs_write', 'agent->http_fetch', 'agent->env_read']) {
    assert.equal(grants.find((e) => e.id === id).status, 'blocked');
  }
});

test('classify: zerotrust blocks every secrets edge', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.zerotrust.policy);
  for (const e of m.edges.filter((x) => x.to === 'secrets')) {
    assert.equal(e.status, 'blocked', e.id);
  }
});

test('classify: zerotrust blocks network edges but opens shell_exec exec surface', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.zerotrust.policy);
  for (const e of m.edges.filter((x) => x.to === 'network')) {
    assert.equal(e.status, 'blocked', e.id);
  }
  assert.equal(m.edges.find((e) => e.id === 'shell_exec->shell').status, 'open');
  assert.equal(m.edges.find((e) => e.id === 'shell_exec->filesystem').status, 'open');
});

test('classify: readonly opens its three granted tool edges only', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.readonly.policy);
  const grants = m.edges.filter((e) => e.kind === 'grant');
  const open = grants.filter((e) => e.status === 'open').map((e) => e.id);
  assert.deepEqual(open.sort(), ['agent->env_read', 'agent->fs_read', 'agent->http_fetch'].sort());
});

test('classify: readonly blocks egress on the http_fetch network edge', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.readonly.policy);
  assert.equal(m.edges.find((e) => e.id === 'http_fetch->network').status, 'blocked');
});

test('classify: scoped marks the allowlisted http_fetch edge as held, not open', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.scoped.policy);
  assert.equal(m.edges.find((e) => e.id === 'http_fetch->network').status, 'held');
});

test('classify: scoped keeps secrets edges blocked', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.scoped.policy);
  for (const e of m.edges.filter((x) => x.to === 'secrets')) {
    assert.equal(e.status, 'blocked', e.id);
  }
});

test('classify: hitl turns every open edge held', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.hitl.policy);
  assert.equal(m.edges.filter((e) => e.status === 'open').length, 0);
  assert.ok(m.edges.filter((e) => e.status === 'held').length > 0);
});

test('classify: approval gate converts open grant edges to held', () => {
  const grant = LATTICE_EDGES.find((e) => e.id === 'agent->fs_read');
  assert.equal(classifyEdge(grant, DEFAULT_POLICY), 'open');
  assert.equal(classifyEdge(grant, { ...DEFAULT_POLICY, requireHumanApproval: true }), 'held');
});

test('classify: blocked edges stay blocked under the approval gate', () => {
  const secrets = LATTICE_EDGES.find((e) => e.id === 'env_read->secrets');
  assert.equal(classifyEdge(secrets, { ...DEFAULT_POLICY, requireHumanApproval: true }), 'blocked');
});

test('classify: env_read->secrets opens only when allowEnvSecrets is on', () => {
  const e = LATTICE_EDGES.find((x) => x.id === 'env_read->secrets');
  assert.equal(classifyEdge(e, DEFAULT_POLICY), 'blocked');
  assert.equal(classifyEdge(e, { ...DEFAULT_POLICY, allowEnvSecrets: true }), 'open');
});

test('classify: fs_write->filesystem closes when write capability is removed', () => {
  const e = LATTICE_EDGES.find((x) => x.id === 'fs_write->filesystem');
  assert.equal(classifyEdge(e, DEFAULT_POLICY), 'open');
  assert.equal(classifyEdge(e, { ...DEFAULT_POLICY, allowFsWrite: false }), 'blocked');
});

test('classify: fs_read->secrets opens only when the sensitive guard is off', () => {
  const e = LATTICE_EDGES.find((x) => x.id === 'fs_read->secrets');
  assert.equal(classifyEdge(e, DEFAULT_POLICY), 'blocked');
  assert.equal(classifyEdge(e, { ...DEFAULT_POLICY, blockSensitivePaths: false }), 'open');
});

test('classify: shell_exec->network needs both egress and a network utility', () => {
  const e = LATTICE_EDGES.find((x) => x.id === 'shell_exec->network');
  assert.equal(classifyEdge(e, DEFAULT_POLICY), 'held'); // allowlisted domains exist
  assert.equal(classifyEdge(e, { ...DEFAULT_POLICY, allowedDomains: [] }), 'blocked');
  assert.equal(classifyEdge(e, { ...DEFAULT_POLICY, allowNetwork: true }), 'open');
  assert.equal(classifyEdge(e, { ...DEFAULT_POLICY, allowNetwork: true, networkCommands: [] }), 'blocked');
});

test('classify: every edge status is one of open, held, blocked', () => {
  for (const p of POLICY_PRESETS) {
    const m = buildLatticeModel(p.policy);
    for (const e of m.edges) {
      assert.ok(['open', 'held', 'blocked'].includes(e.status), `${p.id} ${e.id}`);
    }
  }
});

test('classify: every reach edge carries a reason string', () => {
  const m = buildLatticeModel(DEFAULT_POLICY);
  for (const e of m.edges.filter((x) => x.kind === 'reach')) {
    assert.ok(e.reason.length > 10, e.id);
  }
});

/* chain overlay ------------------------------------------------------------------ */

test('overlay: unrestricted + inject-exfil traverses the whole attack path', () => {
  const res = runAttackChain(ATTACK_CHAIN_MAP['inject-exfil'], POLICY_PRESET_MAP.unrestricted.policy);
  const m = buildLatticeModel(POLICY_PRESET_MAP.unrestricted.policy, res);
  assert.equal(m.edges.find((e) => e.id === 'agent->http_fetch').chain, 'traversed');
  assert.equal(m.edges.find((e) => e.id === 'http_fetch->network').chain, 'traversed');
  assert.equal(m.edges.find((e) => e.id === 'fs_read->secrets').chain, 'traversed');
  assert.equal(m.edges.find((e) => e.id === 'shell_exec->network').chain, 'traversed');
});

test('overlay: scoped + inject-exfil halts at the fs_read secrets edge', () => {
  const res = runAttackChain(ATTACK_CHAIN_MAP['inject-exfil'], POLICY_PRESET_MAP.scoped.policy);
  const m = buildLatticeModel(POLICY_PRESET_MAP.scoped.policy, res);
  assert.equal(m.edges.find((e) => e.id === 'agent->http_fetch').chain, 'traversed');
  assert.equal(m.edges.find((e) => e.id === 'http_fetch->network').chain, 'traversed');
  assert.equal(m.edges.find((e) => e.id === 'fs_read->secrets').chain, 'halted');
  assert.equal(m.edges.find((e) => e.id === 'agent->fs_read').chain, 'traversed');
  assert.equal(m.edges.find((e) => e.id === 'shell_exec->network').chain, 'pending');
});

test('overlay: zerotrust + inject-exfil halts at the ungranted http_fetch grant', () => {
  const res = runAttackChain(ATTACK_CHAIN_MAP['inject-exfil'], POLICY_PRESET_MAP.zerotrust.policy);
  const m = buildLatticeModel(POLICY_PRESET_MAP.zerotrust.policy, res);
  assert.equal(m.edges.find((e) => e.id === 'agent->http_fetch').chain, 'halted');
  assert.equal(m.edges.find((e) => e.id === 'http_fetch->network').chain, 'pending');
});

test('overlay: zerotrust + forkbomb marks the grant edge halted at the budget step', () => {
  const res = runAttackChain(ATTACK_CHAIN_MAP.forkbomb, POLICY_PRESET_MAP.zerotrust.policy);
  const m = buildLatticeModel(POLICY_PRESET_MAP.zerotrust.policy, res);
  const grant = m.edges.find((e) => e.id === 'agent->shell_exec');
  assert.equal(grant.chain, 'halted');
  assert.equal(grant.chainStep, 5);
});

test('overlay: hitl + privesc holds the reach edge after the attempted call', () => {
  const res = runAttackChain(ATTACK_CHAIN_MAP.privesc, POLICY_PRESET_MAP.hitl.policy);
  const m = buildLatticeModel(POLICY_PRESET_MAP.hitl.policy, res);
  assert.equal(m.edges.find((e) => e.id === 'agent->fs_read').chain, 'traversed');
  assert.equal(m.edges.find((e) => e.id === 'fs_read->filesystem').chain, 'halted');
});

test('overlay: no chain result leaves all chain marks null', () => {
  const m = buildLatticeModel(DEFAULT_POLICY, null);
  assert.ok(m.edges.every((e) => e.chain === null));
  assert.ok(m.edges.every((e) => e.chainStep === -1));
});

test('counts: unrestricted counts fifteen open edges', () => {
  const c = latticeStatusCounts(buildLatticeModel(POLICY_PRESET_MAP.unrestricted.policy));
  assert.equal(c.open, 15);
  assert.equal(c.held, 0);
  assert.equal(c.blocked, 0);
});

test('counts: counts cover all edges and only valid keys', () => {
  const m = buildLatticeModel(POLICY_PRESET_MAP.zerotrust.policy);
  const c = latticeStatusCounts(m);
  assert.equal(c.open + c.held + c.blocked, m.edges.length);
});
