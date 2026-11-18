import {
  DEFAULT_POLICY,
  evaluateToolCall,
  evaluateNaiveRegex,
  evaluateFlatGate,
  buildSarifReport,
} from './capability-gate.mjs';
import { ADVERSARIAL_CORPUS } from './corpus.mjs';
import { runCapGateBenchmark } from './benchmark.mjs';

const state = {
  policy: structuredClone(DEFAULT_POLICY),
  selectedId: ADVERSARIAL_CORPUS[0].id,
  toolCall: structuredClone(ADVERSARIAL_CORPUS[0].toolCall),
  lastEval: null,
  lastBench: null,
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
  kpiDecision: document.getElementById('kpi-decision'),
  kpiRisk: document.getElementById('kpi-risk'),
  kpiDepth: document.getElementById('kpi-depth'),
  kpiCmds: document.getElementById('kpi-cmds'),
  kpiNaive: document.getElementById('kpi-naive'),
  kpiFlat: document.getElementById('kpi-flat'),
  toolSelect: document.getElementById('tool-select'),
  argLabel: document.getElementById('arg-label'),
  argInput: document.getElementById('arg-input'),
  btnApplySafe: document.getElementById('btn-apply-safe'),
  findingsList: document.getElementById('findings-list'),
  astList: document.getElementById('ast-list'),
  benchDigest: document.getElementById('bench-digest'),
  detectorTbody: document.getElementById('detector-tbody'),
  categoryBars: document.getElementById('category-bars'),
  btnRunSuite: document.getElementById('btn-run-suite'),
  btnExportSarif: document.getElementById('btn-export-sarif'),
  btnExportReceipt: document.getElementById('btn-export-receipt'),
};

function init() {
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
    evaluateCurrent();
  });

  els.btnApplySafe.addEventListener('click', () => {
    if (!state.lastEval?.safeRewrite) return;
    state.toolCall = structuredClone(state.lastEval.safeRewrite);
    syncInspectorInputs();
    evaluateCurrent();
  });

  els.btnRunSuite.addEventListener('click', renderBenchmark);
  els.btnExportSarif.addEventListener('click', exportSarif);
  els.btnExportReceipt.addEventListener('click', exportReceipt);

  syncPolicyControls();
  selectCorpusItem(ADVERSARIAL_CORPUS[0]);
  renderBenchmark();
}

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
    shell_exec: 'Shell Command Script',
    fs_read: 'File Read Path',
    fs_write: 'File Write Path',
    http_fetch: 'Target URL',
    env_read: 'Environment Variable Name',
  };
  els.argLabel.textContent = map[els.toolSelect.value] || 'Argument Payload';
}

function renderCorpusList() {
  els.corpusList.textContent = '';
  const fam = els.familyFilter.value;
  for (const item of ADVERSARIAL_CORPUS) {
    if (fam !== 'All' && item.category !== fam) continue;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'corpus-item';
    if (state.selectedId === item.id) btn.classList.add('active');

    const top = document.createElement('div');
    top.className = 'corpus-item-top';
    const idSpan = document.createElement('span');
    idSpan.textContent = item.id;
    const tag = document.createElement('span');
    tag.className = `tag ${item.expectedBlocked ? 'tag-unsafe' : 'tag-benign'}`;
    tag.textContent = item.expectedBlocked ? 'UNSAFE' : 'BENIGN';
    top.append(idSpan, tag);

    const title = document.createElement('div');
    title.className = 'corpus-item-title';
    title.textContent = item.title;

    btn.append(top, title);
    btn.addEventListener('click', () => selectCorpusItem(item));
    els.corpusList.appendChild(btn);
  }
}

function evaluateAll() {
  evaluateCurrent();
  renderBenchmark();
}

function evaluateCurrent() {
  const ev = evaluateToolCall(state.toolCall, state.policy);
  const naive = evaluateNaiveRegex(state.toolCall);
  const flat = evaluateFlatGate(state.toolCall, state.policy);
  state.lastEval = ev;

  els.kpiDecision.textContent = ev.decision;
  els.kpiRisk.textContent = `Risk score ${ev.riskScore}/100 (${ev.findingCount} findings)`;
  els.kpiDepth.textContent = `Depth ${ev.ast.maxObservedDepth}`;
  els.kpiCmds.textContent = `${ev.ast.records.length} unwrapped AST nodes`;
  els.kpiNaive.textContent = naive.blocked ? 'BLOCKED' : 'MISSED / ALLOW';
  els.kpiFlat.textContent = flat.blocked ? 'BLOCKED' : 'MISSED / ALLOW';

  els.btnApplySafe.hidden = !ev.safeRewrite;

  els.findingsList.textContent = '';
  if (ev.findings.length === 0) {
    const ok = document.createElement('div');
    ok.className = 'finding-card';
    ok.textContent = 'No capability policy violations detected. Tool call permitted under current policy.';
    els.findingsList.appendChild(ok);
  } else {
    for (const f of ev.findings) {
      const card = document.createElement('div');
      card.className = `finding-card ${f.severity}`;
      const head = document.createElement('div');
      head.className = 'finding-head';
      const rSpan = document.createElement('strong');
      rSpan.textContent = f.ruleId;
      const sSpan = document.createElement('span');
      sSpan.textContent = f.severity.toUpperCase();
      head.append(rSpan, sSpan);

      const title = document.createElement('strong');
      title.textContent = f.title;
      const detail = document.createElement('p');
      detail.style.margin = '4px 0';
      detail.textContent = f.detail;
      const sug = document.createElement('div');
      sug.className = 'muted-mono';
      sug.textContent = `Fix: ${f.suggestion}`;
      card.append(head, title, detail, sug);
      els.findingsList.appendChild(card);
    }
  }

  els.astList.textContent = '';
  if (ev.ast.records.length === 0) {
    const direct = document.createElement('div');
    direct.className = 'ast-card';
    direct.textContent = `Direct typed tool call: ${state.toolCall.tool}(${extractArgText(state.toolCall)})`;
    els.astList.appendChild(direct);
  } else {
    for (const rec of ev.ast.records) {
      const card = document.createElement('div');
      card.className = 'ast-card';
      const trail = document.createElement('div');
      trail.className = 'ast-trail';
      trail.textContent = `[depth ${rec.depth}] ${rec.trail.join(' -> ')}`;
      const args = document.createElement('div');
      args.className = 'muted-mono';
      args.textContent = `cmd=${rec.command} args=${JSON.stringify(rec.args)}`;
      card.append(trail, args);
      els.astList.appendChild(card);
    }
  }
}

async function renderBenchmark() {
  const bench = runCapGateBenchmark(ADVERSARIAL_CORPUS, state.policy);
  state.lastBench = bench;

  els.detectorTbody.textContent = '';
  const rows = [
    { label: 'CapGate (Recursive AST + Policy)', m: bench.detectors.capgate, best: true },
    { label: 'Flat First-Token Gate', m: bench.detectors.flatGate, best: false },
    { label: 'Naive Substring Regex', m: bench.detectors.naiveRegex, best: false },
  ];
  for (const r of rows) {
    const tr = document.createElement('tr');
    if (r.best) tr.className = 'row-best';
    const cells = [
      r.label,
      r.m.precision.toFixed(4),
      r.m.recall.toFixed(4),
      r.m.f1.toFixed(4),
      r.m.accuracy.toFixed(4),
      r.m.fpr.toFixed(4),
      `${r.m.tp} / ${r.m.fp} / ${r.m.tn} / ${r.m.fn}`,
    ];
    for (const c of cells) {
      const td = document.createElement('td');
      td.textContent = c;
      tr.appendChild(td);
    }
    els.detectorTbody.appendChild(tr);
  }

  els.categoryBars.textContent = '';
  for (const cat of bench.perCategory) {
    const card = document.createElement('div');
    card.className = 'cat-card';
    const title = document.createElement('strong');
    title.textContent = cat.category;
    const line = document.createElement('div');
    line.className = 'muted-mono';
    line.textContent = `CapGate ${cat.capCorrect}/${cat.total} | Flat ${cat.flatCorrect}/${cat.total} | Naive ${cat.naiveCorrect}/${cat.total}`;
    card.append(title, line);
    els.categoryBars.appendChild(card);
  }

  const digest = await sha256Hex(JSON.stringify({ policy: state.policy, detectors: bench.detectors }));
  els.benchDigest.textContent = `Unsigned SHA-256 Digest: ${digest.slice(0, 16)}...`;
}

async function sha256Hex(str) {
  if (!globalThis.crypto?.subtle) return 'unavailable';
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

function exportSarif() {
  if (!state.lastBench) return;
  const sarif = buildSarifReport(state.lastBench.rows);
  triggerDownload('capgate-corpus.sarif.json', JSON.stringify(sarif, null, 2), 'application/sarif+json');
}

async function exportReceipt() {
  const payload = {
    tool: 'CapGate',
    version: '1.0.0',
    signatureStatus: 'unsigned-local-sha256',
    policy: state.policy,
    inspectedToolCall: state.toolCall,
    evaluation: state.lastEval,
  };
  payload.sha256 = await sha256Hex(JSON.stringify(payload));
  triggerDownload('capgate-policy-receipt.json', JSON.stringify(payload, null, 2), 'application/json');
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
