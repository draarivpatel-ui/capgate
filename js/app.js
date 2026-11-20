import {
  DEFAULT_POLICY,
  evaluateToolCall,
  evaluateNaiveRegex,
  evaluateFlatGate,
  buildSarifReport,
} from './capability-gate.mjs';
import { ADVERSARIAL_CORPUS } from './corpus.mjs';
import { runCapGateBenchmark } from './benchmark.mjs';
import { buildReceipt, verifyReceipt } from './receipt.mjs';
import { canonicalJson, sha256Hex } from './hash.mjs';
import {
  DETECTORS,
  gaugeArc,
  buildDecisionTrace,
  buildVerdicts,
  buildDetectorCards,
  buildFamilyMatrix,
  proofCases,
} from './viewmodel.mjs';

const state = {
  policy: structuredClone(DEFAULT_POLICY),
  selectedId: ADVERSARIAL_CORPUS[0].id,
  toolCall: structuredClone(ADVERSARIAL_CORPUS[0].toolCall),
  lastEval: null,
  lastBench: null,
  proofIds: [],
  proofIndex: 0,
  proofFamily: 'All',
  attackCommand: '',
};

const els = {
  policyRoot: document.getElementById('policy-root'),
  policyDepth: document.getElementById('policy-depth'),
  policyNet: document.getElementById('policy-net'),
  policySsrf: document.getElementById('policy-ssrf'),
  policySecrets: document.getElementById('policy-secrets'),
  btnResetPolicy: document.getElementById('btn-reset-policy'),
  familyFilter: document.getElementById('family-filter'),
  corpusList: document.getElementById('corpus-list'),
  corpusCount: document.getElementById('corpus-count'),
  kpiDecision: document.getElementById('kpi-decision'),
  kpiRisk: document.getElementById('kpi-risk'),
  kpiDepth: document.getElementById('kpi-depth'),
  kpiCmds: document.getElementById('kpi-cmds'),
  kpiNaive: document.getElementById('kpi-naive'),
  kpiFlat: document.getElementById('kpi-flat'),
  kpiGauge: document.getElementById('kpi-gauge'),
  gaugeTrack: document.getElementById('gauge-track'),
  gaugeFill: document.getElementById('gauge-fill'),
  gaugeText: document.getElementById('gauge-text'),
  toolSelect: document.getElementById('tool-select'),
  argLabel: document.getElementById('arg-label'),
  argInput: document.getElementById('arg-input'),
  btnApplySafe: document.getElementById('btn-apply-safe'),
  findingsList: document.getElementById('findings-list'),
  astList: document.getElementById('ast-list'),
  benchDigest: document.getElementById('bench-digest'),
  detectorCards: document.getElementById('detector-cards'),
  familyMatrix: document.getElementById('family-matrix'),
  btnRunSuite: document.getElementById('btn-run-suite'),
  btnExportSarif: document.getElementById('btn-export-sarif'),
  btnExportReceipt: document.getElementById('btn-export-receipt'),
  themeToggle: document.getElementById('theme-toggle'),
  themeLabel: document.getElementById('theme-label'),
  proofCommand: document.getElementById('proof-command'),
  proofMeta: document.getElementById('proof-meta'),
  proofTrace: document.getElementById('proof-trace'),
  proofVerdicts: document.getElementById('proof-verdicts'),
  proofScore: document.getElementById('proof-score'),
  proofPosition: document.getElementById('proof-position'),
  btnProofNext: document.getElementById('btn-proof-next'),
  btnProofInspect: document.getElementById('btn-proof-inspect'),
  heroVerdict: document.getElementById('hero-verdict'),
  heroVerdictSub: document.getElementById('hero-verdict-sub'),
  heroDiffBody: document.getElementById('hero-diff-body'),
  familyChips: document.getElementById('family-chips'),
  attackEditor: document.getElementById('attack-editor'),
  attackLive: document.getElementById('attack-live'),
  btnVerifyReceipt: document.getElementById('btn-verify-receipt'),
  verifyInput: document.getElementById('verify-input'),
  btnVerifyRun: document.getElementById('btn-verify-run'),
  verifyResult: document.getElementById('verify-result'),
};

/** Small element builder. Text always goes through textContent, never parsed as markup. */
function h(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined && text !== null) el.textContent = String(text);
  return el;
}

function init() {
  initTheme();
  const families = ['All', ...new Set(ADVERSARIAL_CORPUS.map((c) => c.category))];
  for (const fam of families) {
    const opt = document.createElement('option');
    opt.value = fam;
    opt.textContent = fam;
    els.familyFilter.appendChild(opt);
  }

  els.familyFilter.addEventListener('change', renderCorpusList);
  els.btnResetPolicy.addEventListener('click', () => {
    state.policy = structuredClone(DEFAULT_POLICY);
    syncPolicyControls();
    evaluateAll();
  });

  const onPolicyChange = () => {
    state.policy.workspaceRoot = els.policyRoot.value.trim() || '/workspace/app';
    state.policy.maxShellNestingDepth = Math.max(0, Math.min(6, Number(els.policyDepth.value || 2)));
    state.policy.allowNetwork = els.policyNet.checked;
    state.policy.blockPrivateIps = els.policySsrf.checked;
    state.policy.allowEnvSecrets = els.policySecrets.checked;
    evaluateAll();
  };
  for (const el of [els.policyRoot, els.policyDepth, els.policyNet, els.policySsrf, els.policySecrets]) {
    el.addEventListener('change', onPolicyChange);
  }

  els.toolSelect.addEventListener('change', () => {
    state.toolCall = buildToolPayload(els.toolSelect.value, els.argInput.value);
    state.selectedId = null;
    syncInspectorLabel();
    renderCorpusList();
    evaluateCurrent();
  });
  els.argInput.addEventListener('input', () => {
    state.toolCall = buildToolPayload(els.toolSelect.value, els.argInput.value);
    state.selectedId = null;
    renderCorpusList();
    evaluateCurrent();
  });
  els.btnApplySafe.addEventListener('click', () => {
    if (!state.lastEval?.safeRewrite) return;
    state.toolCall = structuredClone(state.lastEval.safeRewrite);
    delete state.toolCall.note;
    state.selectedId = null;
    syncInspectorInputs();
    renderCorpusList();
    evaluateCurrent();
  });

  els.btnRunSuite.addEventListener('click', renderBenchmark);
  els.btnExportSarif.addEventListener('click', exportSarif);
  els.btnExportReceipt.addEventListener('click', exportReceipt);
  els.btnVerifyReceipt.addEventListener('click', () => {
    els.verifyInput.focus();
    els.verifyInput.scrollIntoView({ block: 'center' });
  });
  els.btnVerifyRun.addEventListener('click', runVerifyReceipt);
  els.attackEditor.addEventListener('input', () => {
    state.attackCommand = els.attackEditor.value;
    renderAttackLive();
  });
  els.btnProofNext.addEventListener('click', () => {
    if (!state.proofIds.length) return;
    state.proofIndex = (state.proofIndex + 1) % state.proofIds.length;
    renderProof();
  });
  els.btnProofInspect.addEventListener('click', () => {
    const item = ADVERSARIAL_CORPUS.find((c) => c.id === state.proofIds[state.proofIndex]);
    if (!item) return;
    selectCorpusItem(item);
    els.argInput.focus();
    els.argInput.scrollIntoView({ block: 'center' });
  });

  syncPolicyControls();
  selectCorpusItem(ADVERSARIAL_CORPUS[0]);
  renderBenchmark();
}

/* Theme ---------------------------------------------------------------- */

function readStoredTheme() {
  try {
    return window.localStorage.getItem('capgate-theme');
  } catch {
    return null;
  }
}

function currentTheme() {
  const forced = document.documentElement.getAttribute('data-theme');
  if (forced === 'dark' || forced === 'light') return forced;
  return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

function applyTheme(theme) {
  if (theme === 'dark' || theme === 'light') document.documentElement.setAttribute('data-theme', theme);
  const now = currentTheme();
  els.themeToggle.setAttribute('aria-pressed', String(now === 'dark'));
  els.themeToggle.setAttribute('aria-label', now === 'dark' ? 'Switch to light theme' : 'Switch to dark theme');
  els.themeLabel.textContent = now === 'dark' ? 'Light' : 'Dark';
}

function initTheme() {
  applyTheme(readStoredTheme());
  els.themeToggle.addEventListener('click', () => {
    const next = currentTheme() === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    try {
      window.localStorage.setItem('capgate-theme', next);
    } catch {
      /* storage can be blocked; the theme still switches for this visit */
    }
  });
}

/* Inspector ------------------------------------------------------------ */

function buildToolPayload(tool, rawText) {
  if (tool === 'fs_read' || tool === 'fs_write') return { tool, args: { path: rawText } };
  if (tool === 'http_fetch') return { tool, args: { url: rawText } };
  if (tool === 'env_read') return { tool, args: { name: rawText } };
  return { tool: 'shell_exec', args: { command: rawText } };
}

function extractArgText(toolCall) {
  const a = toolCall?.args || {};
  return a.command ?? a.path ?? a.url ?? a.name ?? '';
}

function syncPolicyControls() {
  els.policyRoot.value = state.policy.workspaceRoot;
  els.policyDepth.value = String(state.policy.maxShellNestingDepth);
  els.policyNet.checked = Boolean(state.policy.allowNetwork);
  els.policySsrf.checked = Boolean(state.policy.blockPrivateIps);
  els.policySecrets.checked = Boolean(state.policy.allowEnvSecrets);
}

function selectCorpusItem(item) {
  state.selectedId = item.id;
  state.toolCall = structuredClone(item.toolCall);
  syncInspectorInputs();
  renderCorpusList();
  evaluateCurrent();
}

function syncInspectorInputs() {
  els.toolSelect.value = state.toolCall.tool;
  els.argInput.value = extractArgText(state.toolCall);
  syncInspectorLabel();
}

function syncInspectorLabel() {
  const map = {
    shell_exec: 'Shell command',
    fs_read: 'File path to read',
    fs_write: 'File path to write',
    http_fetch: 'URL to fetch',
    env_read: 'Environment variable name',
  };
  els.argLabel.textContent = map[els.toolSelect.value] || 'Argument';
}

function renderCorpusList() {
  els.corpusList.textContent = '';
  const fam = els.familyFilter.value;
  let shown = 0;
  for (const item of ADVERSARIAL_CORPUS) {
    if (fam !== 'All' && item.category !== fam) continue;
    shown += 1;
    const btn = h('button', 'corpus-item');
    btn.type = 'button';
    btn.dataset.caseId = item.id;
    const active = state.selectedId === item.id;
    if (active) btn.classList.add('active');
    btn.setAttribute('aria-pressed', String(active));
    const top = h('span', 'corpus-item-top');
    top.append(h('span', 'mono corpus-id', item.id), h('span', `tag ${item.expectedBlocked ? 'tag-unsafe' : 'tag-benign'}`, item.expectedBlocked ? 'Unsafe' : 'Benign'));
    btn.append(top, h('span', 'corpus-item-title', item.title));
    btn.addEventListener('click', () => selectCorpusItem(item));
    els.corpusList.appendChild(btn);
  }
  els.corpusCount.textContent = String(shown);
}

function evaluateAll() {
  evaluateCurrent();
  renderBenchmark();
}

function setGauge(score, stateName) {
  const g = gaugeArc(score);
  els.gaugeTrack.setAttribute('d', g.track);
  els.gaugeFill.setAttribute('d', g.fill);
  els.gaugeText.textContent = String(g.value);
  els.kpiGauge.setAttribute('aria-label', `Risk score ${g.value} out of 100`);
  els.kpiGauge.dataset.state = stateName;
}

function renderTrace(list, nodes, { vertical = false } = {}) {
  list.textContent = '';
  nodes.forEach((node, i) => {
    const li = h('li', `trace-node node-${node.kind}`);
    if (node.severity) li.dataset.severity = node.severity;
    if (node.kind === 'decision') {
      li.dataset.blocked = String(node.blocked);
      li.dataset.decision = node.label;
    }
    if (vertical && node.kind === 'layer') li.dataset.depth = String(Math.min(node.depth, 4));
    const head = h('span', 'trace-head');
    const kindLabel = { input: 'Tool call', layer: `Layer ${node.depth}`, rule: 'Rule', decision: 'Decision' }[node.kind];
    head.append(h('span', 'trace-kind', kindLabel), h('strong', 'trace-label mono', node.label));
    li.append(head, h('code', 'trace-text', node.text));
    if (node.rule && node.kind === 'layer') li.append(h('span', 'trace-rule mono', node.rule));
    if (!vertical && i < nodes.length - 1) li.setAttribute('data-next', 'true');
    list.appendChild(li);
  });
}

function evaluateCurrent() {
  const ev = evaluateToolCall(state.toolCall, state.policy);
  const naive = evaluateNaiveRegex(state.toolCall);
  const flat = evaluateFlatGate(state.toolCall, state.policy);
  state.lastEval = ev;

  els.kpiDecision.textContent = ev.decision;
  els.kpiDecision.dataset.state = ev.decision === 'ESCALATE' ? 'escalate' : ev.blocked ? 'deny' : 'allow';
  els.kpiRisk.textContent = `${ev.findingCount} finding${ev.findingCount === 1 ? '' : 's'}`;
  els.kpiDepth.textContent = String(ev.ast.maxObservedDepth);
  els.kpiCmds.textContent = `${ev.ast.records.length} unwrapped command${ev.ast.records.length === 1 ? '' : 's'}`;
  els.kpiNaive.textContent = naive.blocked ? 'BLOCK' : 'ALLOW';
  els.kpiNaive.dataset.state = naive.blocked ? 'deny' : 'allow';
  els.kpiFlat.textContent = flat.blocked ? 'BLOCK' : 'ALLOW';
  els.kpiFlat.dataset.state = flat.blocked ? 'deny' : 'allow';
  setGauge(ev.riskScore, els.kpiDecision.dataset.state);

  els.btnApplySafe.hidden = !ev.safeRewrite;

  els.findingsList.textContent = '';
  if (ev.findings.length === 0) {
    els.findingsList.appendChild(h('div', 'finding-card finding-ok', 'No capability rule fired. The call is allowed under the current policy.'));
  } else {
    for (const f of ev.findings) {
      const card = h('div', `finding-card ${f.severity}`);
      const head = h('div', 'finding-head');
      head.append(h('strong', 'mono', f.ruleId), h('span', `sev sev-${f.severity}`, f.severity));
      card.append(head, h('strong', 'finding-title', f.title), h('p', 'finding-detail', f.detail), h('p', 'finding-fix', `Fix: ${f.suggestion}`));
      els.findingsList.appendChild(card);
    }
  }

  renderTrace(els.astList, buildDecisionTrace(state.toolCall, ev), { vertical: true });
}

/* Ten-second proof ----------------------------------------------------- */

function renderProof() {
  const id = state.proofIds[state.proofIndex];
  const item = ADVERSARIAL_CORPUS.find((c) => c.id === id);
  if (!item) return;
  const capgate = evaluateToolCall(item.toolCall, state.policy);
  const naive = evaluateNaiveRegex(item.toolCall);
  const flat = evaluateFlatGate(item.toolCall, state.policy);

  els.proofPosition.textContent = `${state.proofIndex + 1} / ${state.proofIds.length} hidden attacks`;
  els.proofMeta.textContent = `${item.category} | ${item.toolCall.tool}`;
  els.proofCommand.textContent = extractArgText(item.toolCall);
  document.getElementById('proof-title').textContent = item.title;
  renderTrace(els.proofTrace, buildDecisionTrace(item.toolCall, capgate));

  // Hero decision word: the verdict is the biggest text on first paint.
  els.heroVerdict.textContent = capgate.decision;
  els.heroVerdictSub.textContent = `${capgate.findingCount} finding${capgate.findingCount === 1 ? '' : 's'}, risk ${capgate.riskScore}/100`;
  const heroWord = els.heroVerdict.parentElement;
  heroWord.dataset.state = capgate.decision === 'ESCALATE' ? 'escalate' : capgate.blocked ? 'deny' : 'allow';

  // Policy-diff explainer: which baseline missed it, and which rule caught it.
  const rules = [...new Set(capgate.findings.map((f) => f.ruleId))].slice(0, 3).join(', ') || 'none';
  els.heroDiffBody.textContent = '';
  const missed = [
    { name: 'Keyword regex', hit: naive.blocked, why: naivedWhy(naive) },
    { name: 'First-word gate', hit: flat.blocked, why: 'only checks the first token' },
  ].filter((d) => !d.hit);
  if (missed.length === 0) missed.push({ name: 'Both baselines', hit: false, why: 'flagged this call' });
  for (const d of missed) {
    const row = h('div', 'diff-row');
    row.append(
      h('strong', 'diff-who', d.name),
      h('span', 'diff-what', 'ALLOW'),
      h('span', 'diff-why', `${d.why}; CapGate fired ${rules}`),
    );
    els.heroDiffBody.appendChild(row);
  }

  // Family chips: one click jumps to any attack family in the proof set.
  renderFamilyChips();
  els.attackEditor.value = extractArgText(item.toolCall);
  state.attackCommand = els.attackEditor.value;
  renderAttackLive();

  els.proofVerdicts.textContent = '';
  for (const v of buildVerdicts({ naive, flat, capgate }, item.expectedBlocked)) {
    const card = h('div', `verdict verdict-${v.key}`);
    card.dataset.blocked = String(v.blocked);
    card.dataset.correct = String(v.correct);
    const detector = DETECTORS.find((d) => d.key === v.key);
    card.append(
      h('span', 'verdict-name', `${v.label} (${detector.detail})`),
      h('strong', 'verdict-word mono', v.verdict),
      h('span', 'verdict-outcome', v.correct ? 'Correct' : 'Missed the attack'),
    );
    els.proofVerdicts.appendChild(card);
  }
}

function naivedWhy(naive) {
  if (!naive.hits || naive.hits.length === 0) return 'raw text has no keyword hit';
  return `saw ${naive.hits.join(', ')} in raw text`;
}

function renderFamilyChips() {
  els.familyChips.textContent = '';
  const families = ['All', ...new Set(ADVERSARIAL_CORPUS.filter((c) => c.expectedBlocked).map((c) => c.category))];
  for (const fam of families) {
    const chip = h('button', `family-chip${state.proofFamily === fam ? ' active' : ''}`, fam);
    chip.type = 'button';
    chip.setAttribute('aria-pressed', String(state.proofFamily === fam));
    chip.addEventListener('click', () => {
      state.proofFamily = fam;
      const ids = state.proofIds.filter((id) => {
        const c = ADVERSARIAL_CORPUS.find((x) => x.id === id);
        return c && (fam === 'All' || c.category === fam);
      });
      if (ids.length) {
        state.proofIds = ids;
        state.proofIndex = 0;
        renderProof();
      }
    });
    els.familyChips.appendChild(chip);
  }
}

function renderAttackLive() {
  const raw = state.attackCommand;
  if (!raw.trim()) {
    els.attackLive.textContent = 'Type a command to see the live verdict.';
    els.attackLive.dataset.state = 'allow';
    return;
  }
  const item = ADVERSARIAL_CORPUS.find((c) => c.id === state.proofIds[state.proofIndex]);
  const tool = item?.toolCall?.tool || 'shell_exec';
  const argKey = { fs_read: 'path', fs_write: 'path', http_fetch: 'url', env_read: 'name' }[tool] || 'command';
  const ev = evaluateToolCall({ tool, args: { [argKey]: raw } }, state.policy);
  els.attackLive.textContent = `${ev.decision} · ${ev.findingCount} finding${ev.findingCount === 1 ? '' : 's'} · risk ${ev.riskScore}/100 · ${ev.findings.slice(0, 2).map((f) => f.ruleId).join(', ') || 'no rule fired'}`;
  els.attackLive.dataset.state = ev.decision === 'ESCALATE' ? 'escalate' : ev.blocked ? 'deny' : 'allow';
}

function renderScoreStrip(bench) {
  els.proofScore.textContent = '';
  for (const d of DETECTORS) {
    const m = bench.detectors[d.key];
    const cell = h('div', `score-cell score-${d.key}`);
    const bar = h('span', 'score-bar');
    const fill = h('span', 'score-fill');
    fill.style.width = `${((m.tp / (m.tp + m.fn)) * 100).toFixed(1)}%`;
    bar.appendChild(fill);
    cell.append(
      h('span', 'score-name', d.label),
      h('strong', 'score-num mono', `${m.tp}/${m.tp + m.fn}`),
      h('span', 'score-sub', `attacks blocked, ${m.fp} false alarm${m.fp === 1 ? '' : 's'} on ${m.fp + m.tn} safe calls`),
      bar,
    );
    els.proofScore.appendChild(cell);
  }
}

/* Benchmark ------------------------------------------------------------ */

function renderBenchmark() {
  const bench = runCapGateBenchmark(ADVERSARIAL_CORPUS, state.policy);
  state.lastBench = bench;

  let proofIds = proofCases(bench);
  if (!proofIds.length) proofIds = bench.rows.filter((r) => r.expectedBlocked).map((r) => r.id);
  if (state.proofFamily !== 'All') {
    const filtered = proofIds.filter((id) => {
      const c = ADVERSARIAL_CORPUS.find((x) => x.id === id);
      return c && c.category === state.proofFamily;
    });
    if (filtered.length) proofIds = filtered;
  }
  const keep = state.proofIds[state.proofIndex];
  state.proofIds = proofIds;
  state.proofIndex = Math.max(0, state.proofIds.indexOf(keep));
  renderProof();
  renderScoreStrip(bench);

  els.detectorCards.textContent = '';
  for (const card of buildDetectorCards(bench)) {
    const el = h('article', `detector-card detector-${card.key}`);
    const head = h('div', 'detector-head');
    head.append(h('h3', 'detector-name', `${card.label}: ${card.detail}`));
    el.append(head, h('p', 'detector-caught', card.caught));
    const metrics = h('div', 'metric-bars');
    for (const m of card.metrics) {
      const row = h('div', 'metric-row');
      row.dataset.good = m.good;
      const track = h('span', 'metric-track');
      const fill = h('span', 'metric-fill');
      fill.style.width = `${(m.value * 100).toFixed(1)}%`;
      track.appendChild(fill);
      row.append(h('span', 'metric-name', m.name), track, h('span', 'metric-val mono', m.value.toFixed(4)));
      metrics.appendChild(row);
    }
    const cm = h('dl', 'confusion');
    for (const [k, label] of [['tp', 'Blocked attacks'], ['fn', 'Missed attacks'], ['tn', 'Allowed safe'], ['fp', 'False alarms']]) {
      const cell = h('div', `cm-cell cm-${k}`);
      cell.append(h('dt', null, label), h('dd', 'mono', card.confusion[k]));
      cm.appendChild(cell);
    }
    el.append(metrics, cm);
    els.detectorCards.appendChild(el);
  }

  els.familyMatrix.textContent = '';
  const headRow = h('div', 'fm-row fm-head');
  headRow.setAttribute('role', 'row');
  const corner = h('span', 'fm-family', 'Family');
  corner.setAttribute('role', 'columnheader');
  headRow.appendChild(corner);
  for (const d of DETECTORS) {
    const c = h('span', 'fm-col', d.label);
    c.setAttribute('role', 'columnheader');
    headRow.appendChild(c);
  }
  els.familyMatrix.appendChild(headRow);
  for (const row of buildFamilyMatrix(bench)) {
    const r = h('div', 'fm-row');
    r.setAttribute('role', 'row');
    const name = h('span', 'fm-family', row.family);
    name.setAttribute('role', 'rowheader');
    r.appendChild(name);
    for (const cell of row.cells) {
      const c = h('span', 'fm-cell mono', `${cell.correct}/${row.total}`);
      c.setAttribute('role', 'cell');
      c.dataset.level = cell.share === 1 ? 'all' : cell.share >= 0.5 ? 'most' : cell.share > 0 ? 'some' : 'none';
      r.appendChild(c);
    }
    els.familyMatrix.appendChild(r);
  }

  const digest = sha256Hex(canonicalJson({ policy: state.policy, detectors: bench.detectors }));
  els.benchDigest.textContent = `SHA-256 ${digest.slice(0, 16)}`;
}

function exportSarif() {
  if (!state.lastBench) return;
  const sarif = buildSarifReport(state.lastBench.rows);
  triggerDownload('capgate-corpus.sarif.json', JSON.stringify(sarif, null, 2), 'application/sarif+json');
}

function exportReceipt() {
  const receipt = buildReceipt({
    policy: state.policy,
    toolCall: state.toolCall,
    evaluation: state.lastEval,
    benchmark: state.lastBench ? {
      version: state.lastBench.version,
      corpusCount: state.lastBench.corpusCount,
      detectors: state.lastBench.detectors,
    } : null,
  });
  triggerDownload('capgate-policy-receipt.json', JSON.stringify(receipt, null, 2), 'application/json');
}

function runVerifyReceipt() {
  const raw = els.verifyInput.value.trim();
  els.verifyResult.textContent = '';
  if (!raw) {
    els.verifyResult.textContent = 'Paste a receipt first.';
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
  const result = verifyReceipt(parsed);
  els.verifyResult.textContent = `${result.status}${result.changedFields.length ? ` (${result.changedFields.join(', ')})` : ''}: ${result.detail}`;
  els.verifyResult.dataset.state = result.status.toLowerCase();
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
  URL.revokeObjectURL(url);
}

init();
