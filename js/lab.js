import {
  ATTACK_CHAINS,
  POLICY_PRESETS,
  POLICY_PRESET_MAP,
  runAttackLab,
  diffPolicyLabs,
} from './attack-lab.mjs';
import { buildLatticeModel, latticeStatusCounts } from './lattice-view.mjs';
import {
  buildPolicyReportJson,
  verifyPolicyReport,
  buildPolicyReportCsv,
  buildPolicyReportMarkdown,
  encodeLabHash,
  decodeLabHash,
} from './policy-report.mjs';
import { runSelfTests } from './self-tests.mjs';

const SVG_NS = 'http://www.w3.org/2000/svg';

const state = {
  presetId: 'scoped',
  chainId: 'inject-exfil',
  compareId: 'zerotrust',
  lab: null,
  compareLab: null,
};

const els = {
  policyCards: document.getElementById('lab-policy-cards'),
  metricBlocked: document.getElementById('lab-metric-blocked'),
  metricBlockedSub: document.getElementById('lab-metric-blocked-sub'),
  metricResidual: document.getElementById('lab-metric-residual'),
  metricTight: document.getElementById('lab-metric-tight'),
  metricTightSub: document.getElementById('lab-metric-tight-sub'),
  chainGrid: document.getElementById('lab-chain-grid'),
  compareSelect: document.getElementById('lab-compare-select'),
  chainSelect: document.getElementById('lab-chain-select'),
  diffMatrix: document.getElementById('lab-diff-matrix'),
  lattice: document.getElementById('lab-lattice'),
  legend: document.getElementById('lab-legend'),
  btnReportJson: document.getElementById('lab-btn-report-json'),
  btnReportCsv: document.getElementById('lab-btn-report-csv'),
  btnReportMd: document.getElementById('lab-btn-report-md'),
  btnCopyLink: document.getElementById('lab-btn-copy-link'),
  btnSelftests: document.getElementById('lab-btn-selftests'),
  selftestStatus: document.getElementById('lab-selftest-status'),
  selftestList: document.getElementById('lab-selftest-list'),
  verifyInput: document.getElementById('lab-verify-input'),
  btnVerifyReport: document.getElementById('lab-btn-verify-report'),
  verifyResult: document.getElementById('lab-verify-result'),
};

/** Small element builder. Text always goes through textContent, never parsed as markup. */
function h(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}

function svg(tag, attrs) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  return el;
}

const STATUS_LABEL = {
  allowed: 'ALLOW', denied: 'DENY', held: 'HELD', budget: 'BUDGET', skipped: 'skip',
};
const HALT_LABEL = { denied: 'denied by the engine', held: 'held for approval', budget: 'call budget exhausted' };

function preset() {
  return POLICY_PRESET_MAP[state.presetId] || POLICY_PRESETS[0];
}

function currentChainResult() {
  return state.lab?.results.find((r) => r.chainId === state.chainId) || state.lab?.results[0] || null;
}

function writeHash() {
  const hash = encodeLabHash({ preset: state.presetId, chain: state.chainId, compareTo: state.compareId });
  if (hash && window.location.hash !== hash) {
    history.replaceState(null, '', hash);
  }
}

function renderPolicyCards() {
  els.policyCards.textContent = '';
  for (const p of POLICY_PRESETS) {
    const btn = h('button', `lab-pcard${p.id === state.presetId ? ' active' : ''}`);
    btn.type = 'button';
    btn.dataset.preset = p.id;
    btn.setAttribute('aria-pressed', String(p.id === state.presetId));
    btn.append(h('strong', 'lab-pcard-name', p.name), h('span', 'lab-pcard-sum', p.summary));
    btn.addEventListener('click', () => {
      if (state.presetId === p.id) return;
      state.presetId = p.id;
      evaluateLab();
      writeHash();
    });
    els.policyCards.appendChild(btn);
  }
}

function renderMetrics() {
  const lab = state.lab;
  els.metricBlocked.textContent = `${lab.blockedCount}/${lab.totalChains}`;
  // data-state carries the danger palette: 'allow' renders green (safe),
  // 'deny' red (dangerous), 'escalate' amber. For the lab, every chain
  // halted is the safe outcome.
  els.metricBlocked.dataset.state = lab.blockedCount === lab.totalChains ? 'allow' : lab.blockedCount === 0 ? 'deny' : 'escalate';
  els.metricBlockedSub.textContent = lab.blockedCount === lab.totalChains
    ? 'every chain halted before completing'
    : lab.blockedCount === 0
      ? 'every chain ran to completion'
      : `${lab.totalChains - lab.blockedCount} chain${lab.totalChains - lab.blockedCount === 1 ? '' : 's'} completed`;
  els.metricResidual.textContent = `${lab.residualSurface}/100`;
  els.metricResidual.dataset.state = lab.residualSurface >= 60 ? 'deny' : lab.residualSurface <= 15 ? 'allow' : 'escalate';
  els.metricTight.textContent = `${lab.tightness.score}/${lab.tightness.maxScore}`;
  els.metricTight.dataset.state = lab.tightness.score >= 60 ? 'allow' : lab.tightness.score < 20 ? 'deny' : 'escalate';
  els.metricTightSub.textContent = `${lab.tightness.dimensions.filter((d) => d.earned > 0).length} of ${lab.tightness.dimensions.length} guard dimensions engaged`;
}

function renderChains() {
  els.chainGrid.textContent = '';
  for (const res of state.lab.results) {
    const card = h('article', `lab-chain${res.chainId === state.chainId ? ' active' : ''}`);
    card.dataset.chain = res.chainId;
    const head = h('div', 'lab-chain-head');
    head.append(
      h('h3', 'lab-chain-title', res.title),
      h('span', `chip mono lab-chain-badge ${res.blocked ? 'badge-blocked' : 'badge-open'}`, res.blocked ? 'BLOCKED' : 'COMPLETED'),
    );
    const detail = res.blocked
      ? `halted at step ${res.haltIndex + 1} of ${res.steps.length}: ${HALT_LABEL[res.haltKind] || res.haltKind} (${res.haltRule || res.haltKind})`
      : `all ${res.steps.length} steps ran; the attack chain completed`;
    const steps = h('ol', 'lab-steps');
    for (const s of res.steps) {
      const li = h('li', 'lab-step');
      li.dataset.status = s.status;
      const top = h('span', 'lab-step-top');
      top.append(
        h('span', `lab-step-chip status-${s.status}`, STATUS_LABEL[s.status] || s.status),
        h('span', 'lab-step-label', s.label),
      );
      const meta = [
        s.tool ? `tool ${s.tool}` : null,
        s.sink ? `sink ${s.sink}` : null,
        s.decision ? `decision ${s.decision}` : null,
        s.ruleIds.length ? s.ruleIds.join(', ') : null,
      ].filter(Boolean).join(' | ');
      li.append(top, h('span', 'lab-step-meta mono', meta));
      steps.appendChild(li);
    }
    card.append(head, h('p', 'lab-chain-narr', res.blocked ? detail : `OPEN: ${detail}`), steps);
    card.addEventListener('click', () => {
      state.chainId = res.chainId;
      renderLattice();
      renderChainSelection();
      writeHash();
    });
    els.chainGrid.appendChild(card);
  }
}

function renderChainSelection() {
  for (const card of els.chainGrid.children) {
    card.classList.toggle('active', card.dataset.chain === state.chainId);
  }
  if (els.chainSelect.value !== state.chainId) els.chainSelect.value = state.chainId;
}

function renderDiffMatrix() {
  els.diffMatrix.textContent = '';
  const comparePreset = POLICY_PRESET_MAP[state.compareId];
  if (!comparePreset || comparePreset.id === state.presetId) {
    els.diffMatrix.appendChild(h('p', 'muted', 'Pick a different policy to diff against.'));
    return;
  }
  const diff = diffPolicyLabs(state.lab, state.compareLab);
  const headRow = h('div', 'lab-diff-row lab-diff-head');
  headRow.setAttribute('role', 'row');
  for (const [txt, cls] of [['Chain', 'lab-diff-chain'], [preset().name, 'lab-diff-col'], [comparePreset.name, 'lab-diff-col'], ['Per-step A on top, B below', 'lab-diff-steps']]) {
    const c = h('span', cls, txt);
    c.setAttribute('role', 'columnheader');
    headRow.appendChild(c);
  }
  els.diffMatrix.appendChild(headRow);
  for (const row of diff.rows) {
    const r = h('div', 'lab-diff-row');
    r.setAttribute('role', 'row');
    const name = h('span', 'lab-diff-chain', row.title);
    name.setAttribute('role', 'rowheader');
    const aCell = h('span', 'lab-diff-col');
    aCell.append(
      h('strong', `diff-outcome ${row.aBlocked ? 'blocked' : 'open'}`, row.aBlocked ? `BLOCKED @ step ${row.aHalt + 1}` : 'COMPLETED'),
      h('span', 'diff-outcome-sub', row.aBlocked ? (row.aHaltKind || '') : 'attack succeeded'),
    );
    const bCell = h('span', 'lab-diff-col');
    bCell.append(
      h('strong', `diff-outcome ${row.bBlocked ? 'blocked' : 'open'}`, row.bBlocked ? `BLOCKED @ step ${row.bHalt + 1}` : 'COMPLETED'),
      h('span', 'diff-outcome-sub', row.bBlocked ? (row.bHaltKind || '') : 'attack succeeded'),
    );
    const stepsCell = h('span', 'lab-diff-steps');
    for (const s of row.steps) {
      const pair = h('span', `diff-step delta-${s.delta}`);
      pair.title = `step ${s.index + 1}: ${s.label} | ${state.presetId}: ${s.aStatus} | ${state.compareId}: ${s.bStatus}`;
      const halfA = h('span', 'diff-step-half');
      halfA.dataset.status = s.aStatus;
      const halfB = h('span', 'diff-step-half');
      halfB.dataset.status = s.bStatus;
      pair.append(halfA, halfB);
      stepsCell.appendChild(pair);
    }
    if (row.chainDelta !== 'same') {
      stepsCell.appendChild(h('span', `chip mono lab-chain-badge badge-${row.chainDelta === 'tightened' ? 'blocked' : 'open'}`, row.chainDelta.toUpperCase()));
    }
    r.append(name, aCell, bCell, stepsCell);
    els.diffMatrix.appendChild(r);
  }
}

function renderLattice() {
  const chainRes = currentChainResult();
  const model = buildLatticeModel(preset().policy, chainRes);
  els.lattice.textContent = '';
  for (const e of model.edges) {
    const path = svg('path', {
      d: e.d,
      class: `lat-edge edge-${e.status}${e.chain ? ` chain-${e.chain}` : ''}`,
      'fill': 'none',
      'data-edge': e.id,
      'data-status': e.status,
      'data-chain': e.chain || 'none',
    });
    const title = svg('title');
    title.textContent = `${e.id}: ${e.status}${e.chain ? ` (chain: ${e.chain}, step ${e.chainStep + 1})` : ''} - ${e.reason}`;
    path.appendChild(title);
    els.lattice.appendChild(path);
    if (e.chain === 'halted') {
      const mx = (e.x1 + e.x2) / 2;
      const my = (e.y1 + e.y2) / 2;
      const marker = svg('g', { class: 'lat-halt', transform: `translate(${mx} ${my})` });
      marker.appendChild(svg('circle', { r: 9, class: 'lat-halt-dot' }));
      const x = svg('text', { 'text-anchor': 'middle', dy: '0.32em', class: 'lat-halt-x' });
      x.textContent = 'x';
      marker.appendChild(x);
      els.lattice.appendChild(marker);
    }
  }
  for (const n of model.nodes) {
    const g = svg('g', { class: `lat-node kind-${n.kind}` });
    g.appendChild(svg('rect', {
      x: n.cx - n.w / 2, y: n.cy - n.h / 2, width: n.w, height: n.h, rx: 10,
      class: 'lat-node-box',
    }));
    const t = svg('text', { x: n.cx, y: n.cy, 'text-anchor': 'middle', dy: '0.32em', class: 'lat-node-label' });
    t.textContent = n.label;
    g.appendChild(t);
    els.lattice.appendChild(g);
  }
  const counts = latticeStatusCounts(model);
  els.legend.textContent = '';
  const items = [
    ['edge-open', `open path (${counts.open})`],
    ['edge-blocked', `guarded edge (${counts.blocked})`],
    ['edge-held', `allowlisted or approval-held (${counts.held})`],
    ['chain-traversed', 'chain traversed'],
    ['chain-halted', 'chain halted'],
    ['chain-pending', 'chain unreached'],
  ];
  for (const [cls, label] of items) {
    const item = h('span', 'lab-legend-item');
    item.append(h('span', `lab-legend-line lat-edge ${cls}`), h('span', null, label));
    els.legend.appendChild(item);
  }
}

function populateSelects() {
  els.compareSelect.textContent = '';
  for (const p of POLICY_PRESETS) {
    const opt = document.createElement('option');
    opt.value = p.id;
    opt.textContent = p.name;
    els.compareSelect.appendChild(opt);
  }
  els.chainSelect.textContent = '';
  for (const c of ATTACK_CHAINS) {
    const opt = document.createElement('option');
    opt.value = c.id;
    opt.textContent = c.title;
    els.chainSelect.appendChild(opt);
  }
  els.compareSelect.value = state.compareId;
  els.chainSelect.value = state.chainId;
}

function evaluateLab() {
  state.lab = runAttackLab(preset().policy);
  const cmp = POLICY_PRESET_MAP[state.compareId];
  state.compareLab = cmp && cmp.id !== state.presetId ? runAttackLab(cmp.policy) : null;
  renderPolicyCards();
  renderMetrics();
  renderChains();
  renderDiffMatrix();
  renderLattice();
}

function applyHash() {
  const decoded = decodeLabHash(window.location.hash);
  if (!decoded) return false;
  state.presetId = decoded.preset;
  if (decoded.chain) state.chainId = decoded.chain;
  if (decoded.compareTo) state.compareId = decoded.compareTo;
  return true;
}

function triggerDownload(filename, text, mime) {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

function exportReportJson() {
  if (!state.lab) return;
  const doc = buildPolicyReportJson({
    preset: preset(),
    lab: state.lab,
    compareTo: state.compareId,
    generatedAt: new Date().toISOString(),
  });
  triggerDownload('capgate-policy-audit.json', JSON.stringify(doc, null, 2), 'application/json');
}

function exportReportCsv() {
  if (!state.lab) return;
  triggerDownload('capgate-policy-audit.csv', buildPolicyReportCsv(state.lab, preset()), 'text/csv');
}

function exportReportMd() {
  if (!state.lab) return;
  const md = buildPolicyReportMarkdown({ preset: preset(), lab: state.lab, generatedAt: new Date().toISOString() });
  triggerDownload('capgate-policy-audit.md', md, 'text/markdown');
}

async function copyLink() {
  writeHash();
  const url = window.location.href;
  let done = false;
  try {
    await navigator.clipboard.writeText(url);
    done = true;
  } catch {
    done = false;
  }
  els.btnCopyLink.textContent = done ? 'Link copied' : 'Link in address bar';
  setTimeout(() => { els.btnCopyLink.textContent = 'Copy link'; }, 1600);
}

function runSelfTestsPanel() {
  const rows = runSelfTests();
  const passed = rows.filter((r) => r.pass).length;
  els.selftestStatus.textContent = `${passed}/${rows.length} self-tests passed.`;
  els.selftestStatus.dataset.state = passed === rows.length ? 'allow' : 'deny';
  els.selftestList.textContent = '';
  for (const r of rows) {
    const li = h('li', `st-row ${r.pass ? 'st-pass' : 'st-fail'}`);
    li.append(
      h('span', `lab-step-chip status-${r.pass ? 'denied' : 'allowed'}`, r.pass ? 'PASS' : 'FAIL'),
      h('span', 'st-name', r.name),
      h('span', 'st-detail mono', r.detail),
    );
    els.selftestList.appendChild(li);
  }
}

function runVerifyReport() {
  const raw = els.verifyInput.value.trim();
  els.verifyResult.textContent = '';
  if (!raw) {
    els.verifyResult.textContent = 'Paste a policy report first.';
    els.verifyResult.dataset.state = 'malformed';
    return;
  }
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    els.verifyResult.textContent = 'MALFORMED: not valid JSON.';
    els.verifyResult.dataset.state = 'malformed';
    return;
  }
  let result;
  try {
    result = verifyPolicyReport(parsed);
  } catch {
    els.verifyResult.textContent = 'MALFORMED: the report could not be verified.';
    els.verifyResult.dataset.state = 'malformed';
    return;
  }
  els.verifyResult.textContent = `${result.status}: ${result.detail}`;
  els.verifyResult.dataset.state = result.status.toLowerCase();
}

function init() {
  applyHash();
  populateSelects();
  els.compareSelect.addEventListener('change', () => {
    state.compareId = els.compareSelect.value;
    evaluateLab();
    writeHash();
  });
  els.chainSelect.addEventListener('change', () => {
    state.chainId = els.chainSelect.value;
    renderLattice();
    renderChainSelection();
    writeHash();
  });
  els.btnReportJson.addEventListener('click', exportReportJson);
  els.btnReportCsv.addEventListener('click', exportReportCsv);
  els.btnReportMd.addEventListener('click', exportReportMd);
  els.btnCopyLink.addEventListener('click', copyLink);
  els.btnSelftests.addEventListener('click', runSelfTestsPanel);
  els.btnVerifyReport.addEventListener('click', runVerifyReport);
  window.addEventListener('hashchange', () => {
    if (applyHash()) {
      populateSelects();
      evaluateLab();
    }
  });
  evaluateLab();
  writeHash();
}

init();
