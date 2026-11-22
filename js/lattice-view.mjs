/**
 * Capability-lattice model for the attack-path SVG visualizer.
 *
 * The lattice has three columns: the agent, the five tools it may be granted,
 * and the four sensitive sinks a tool can reach. Every edge is classified by
 * the real policy object: 'open' (a path the agent can actually use),
 * 'held' (reachable only after human approval), or 'blocked' (closed by a
 * guard or a missing grant). An optional chain result overlays the path a
 * chosen attack chain took: traversed, halted, or pending edges.
 *
 * Pure geometry and classification, no DOM: the same model is unit tested in
 * Node and drawn with createElementNS in the page.
 */

import { DEFAULT_POLICY, GRANTABLE_TOOLS } from './capability-gate.mjs';

export const LATTICE_VIEWBOX = Object.freeze({ width: 780, height: 430 });

export const LATTICE_NODES = Object.freeze([
  { id: 'agent', label: 'Agent', kind: 'agent', cx: 78, cy: 215 },
  { id: 'fs_read', label: 'fs_read', kind: 'tool', cx: 390, cy: 60 },
  { id: 'fs_write', label: 'fs_write', kind: 'tool', cx: 390, cy: 130 },
  { id: 'http_fetch', label: 'http_fetch', kind: 'tool', cx: 390, cy: 200 },
  { id: 'env_read', label: 'env_read', kind: 'tool', cx: 390, cy: 270 },
  { id: 'shell_exec', label: 'shell_exec', kind: 'tool', cx: 390, cy: 350 },
  { id: 'filesystem', label: 'Filesystem', kind: 'sink', cx: 700, cy: 80 },
  { id: 'network', label: 'Network', kind: 'sink', cx: 700, cy: 175 },
  { id: 'secrets', label: 'Secrets', kind: 'sink', cx: 700, cy: 270 },
  { id: 'shell', label: 'Shell exec', kind: 'sink', cx: 700, cy: 370 },
]);

const NODE_W = 132;
const NODE_H = 40;

/** Tool-to-sink grant edges. `reach` is the rule that decides the base status. */
export const LATTICE_EDGES = Object.freeze([
  { id: 'agent->fs_read', from: 'agent', to: 'fs_read', kind: 'grant', tool: 'fs_read' },
  { id: 'agent->fs_write', from: 'agent', to: 'fs_write', kind: 'grant', tool: 'fs_write' },
  { id: 'agent->http_fetch', from: 'agent', to: 'http_fetch', kind: 'grant', tool: 'http_fetch' },
  { id: 'agent->env_read', from: 'agent', to: 'env_read', kind: 'grant', tool: 'env_read' },
  { id: 'agent->shell_exec', from: 'agent', to: 'shell_exec', kind: 'grant', tool: 'shell_exec' },
  { id: 'fs_read->filesystem', from: 'fs_read', to: 'filesystem', kind: 'reach', tool: 'fs_read', sink: 'filesystem' },
  { id: 'fs_read->secrets', from: 'fs_read', to: 'secrets', kind: 'reach', tool: 'fs_read', sink: 'secrets' },
  { id: 'fs_write->filesystem', from: 'fs_write', to: 'filesystem', kind: 'reach', tool: 'fs_write', sink: 'filesystem' },
  { id: 'fs_write->secrets', from: 'fs_write', to: 'secrets', kind: 'reach', tool: 'fs_write', sink: 'secrets' },
  { id: 'http_fetch->network', from: 'http_fetch', to: 'network', kind: 'reach', tool: 'http_fetch', sink: 'network' },
  { id: 'env_read->secrets', from: 'env_read', to: 'secrets', kind: 'reach', tool: 'env_read', sink: 'secrets' },
  { id: 'shell_exec->filesystem', from: 'shell_exec', to: 'filesystem', kind: 'reach', tool: 'shell_exec', sink: 'filesystem' },
  { id: 'shell_exec->network', from: 'shell_exec', to: 'network', kind: 'reach', tool: 'shell_exec', sink: 'network' },
  { id: 'shell_exec->secrets', from: 'shell_exec', to: 'secrets', kind: 'reach', tool: 'shell_exec', sink: 'secrets' },
  { id: 'shell_exec->shell', from: 'shell_exec', to: 'shell', kind: 'reach', tool: 'shell_exec', sink: 'shell' },
]);

function egressStatus(policy) {
  const domains = Array.isArray(policy.allowedDomains) ? policy.allowedDomains.length : 0;
  if (policy.allowNetwork === true) return 'open';
  return domains > 0 ? 'held' : 'blocked';
}

/**
 * Base status of one edge under a policy, before the approval overlay.
 * 'open' means a call could traverse it; 'held' means it works only in a
 * narrowed way (domain allowlist); 'blocked' means a guard or missing grant
 * closes it.
 */
function baseEdgeStatus(edge, policy) {
  const granted = new Set(Array.isArray(policy.grantedTools) ? policy.grantedTools : GRANTABLE_TOOLS);
  if (edge.kind === 'grant') {
    return granted.has(edge.tool) ? 'open' : 'blocked';
  }
  if (!granted.has(edge.tool)) return 'blocked';
  switch (`${edge.tool}->${edge.sink}`) {
    case 'fs_read->filesystem':
      return policy.enforceWorkspaceBoundary === false ? 'open' : 'open';
    case 'fs_read->secrets':
      return policy.blockSensitivePaths === false ? 'open' : 'blocked';
    case 'fs_write->filesystem':
      return policy.allowFsWrite === false ? 'blocked' : 'open';
    case 'fs_write->secrets':
      return policy.allowFsWrite !== false && policy.blockSensitivePaths === false ? 'open' : 'blocked';
    case 'http_fetch->network':
      return egressStatus(policy);
    case 'env_read->secrets':
      return policy.allowEnvSecrets === true ? 'open' : 'blocked';
    case 'shell_exec->filesystem':
      return (Array.isArray(policy.allowedCommands) && policy.allowedCommands.length > 0) ? 'open' : 'blocked';
    case 'shell_exec->network': {
      const net = Array.isArray(policy.networkCommands) && policy.networkCommands.length > 0;
      if (!net) return 'blocked';
      return egressStatus(policy);
    }
    case 'shell_exec->secrets':
      return (policy.blockSensitivePaths === false || policy.allowEnvSecrets === true) ? 'open' : 'blocked';
    case 'shell_exec->shell':
      return (Array.isArray(policy.allowedCommands) && policy.allowedCommands.length > 0) ? 'open' : 'blocked';
    default:
      return 'blocked';
  }
}

const EDGE_REASON = {
  'fs_read->filesystem': 'fs_read touches workspace files',
  'fs_read->secrets': 'fs_read reaches credential files when the sensitive-path guard is off',
  'fs_write->filesystem': 'fs_write plants files when write capability is granted',
  'fs_write->secrets': 'fs_write reaches credential files when write and the sensitive guard allow it',
  'http_fetch->network': 'http_fetch reaches the network within the egress policy',
  'env_read->secrets': 'env_read exposes secret variables when allowEnvSecrets is on',
  'shell_exec->filesystem': 'shell_exec touches files through allowlisted commands',
  'shell_exec->network': 'shell_exec reaches the network through network utilities',
  'shell_exec->secrets': 'shell_exec reaches secrets through readers or env expansion',
  'shell_exec->shell': 'shell_exec runs commands from the allowlist',
};

/** Final edge status: approval gate turns any open edge into a held edge. */
export function classifyEdge(edge, policy = DEFAULT_POLICY) {
  const base = baseEdgeStatus(edge, policy);
  if (base === 'open' && policy.requireHumanApproval === true) return 'held';
  return base;
}

function nodeById(id) {
  return LATTICE_NODES.find((n) => n.id === id);
}

/**
 * Build the drawable model: node boxes plus cubic edge paths with a status and
 * an optional chain overlay class.
 */
export function buildLatticeModel(policy = DEFAULT_POLICY, chainResult = null) {
  const nodes = LATTICE_NODES.map((n) => ({ ...n, w: NODE_W, h: NODE_H }));
  const edges = LATTICE_EDGES.map((e) => {
    const a = nodeById(e.from);
    const b = nodeById(e.to);
    const x1 = a.cx + NODE_W / 2;
    const y1 = a.cy;
    const x2 = b.cx - NODE_W / 2;
    const y2 = b.cy;
    const mx = (x1 + x2) / 2;
    return {
      ...e,
      x1, y1, x2, y2,
      c1x: mx, c1y: y1, c2x: mx, c2y: y2,
      d: `M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`,
      status: classifyEdge(e, policy),
      reason: EDGE_REASON[e.id] || (e.kind === 'grant' ? `grant of ${e.tool}` : ''),
      chain: null,
      chainStep: -1,
    };
  });

  if (chainResult && Array.isArray(chainResult.steps)) {
    for (const step of chainResult.steps) {
      if (!step || !step.tool) continue;
      const grantEdge = edges.find((e) => e.id === `agent->${step.tool}`);
      const reachEdge = edges.find((e) => e.id === `${step.tool}->${step.sink}`);
      const set = (edge, mark) => {
        if (!edge || edge.chain === 'halted') return;
        if (edge.chain === 'traversed' && mark !== 'halted') return;
        edge.chain = mark;
        edge.chainStep = step.index;
      };
      if (step.status === 'allowed') {
        set(grantEdge, 'traversed');
        set(reachEdge, 'traversed');
      } else if (step.status === 'skipped') {
        set(grantEdge, 'pending');
        set(reachEdge, 'pending');
      } else if (step.status === 'budget') {
        // The chain budget cut the call before dispatch: the agent-to-tool edge
        // is where it stopped.
        set(grantEdge, 'halted');
        set(reachEdge, 'pending');
      } else {
        // denied or held: the call was attempted. It halted at the grant edge
        // when the tool was never granted, else at the reach edge.
        if (grantEdge && grantEdge.status === 'blocked') {
          set(grantEdge, 'halted');
          set(reachEdge, 'pending');
        } else {
          set(grantEdge, 'traversed');
          set(reachEdge, 'halted');
        }
      }
    }
  }
  return { viewBox: LATTICE_VIEWBOX, nodes, edges };
}

/** Count edges by status for the lattice legend and tests. */
export function latticeStatusCounts(model) {
  const counts = { open: 0, held: 0, blocked: 0 };
  for (const e of model.edges) counts[e.status] += 1;
  return counts;
}
