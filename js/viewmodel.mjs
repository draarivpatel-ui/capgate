/**
 * Pure view models for the CapGate studio. No DOM access, so every chart and trace
 * on the page is unit tested in Node.
 */

export const DETECTORS = [
  { key: 'capgate', label: 'CapGate', detail: 'recursive AST + policy' },
  { key: 'flatGate', label: 'Flat first-token gate', detail: 'checks only the first word' },
  { key: 'naiveRegex', label: 'Naive keyword regex', detail: 'scans the raw string' },
];

/** Arc geometry for a 0 to 100 risk gauge drawn as a 240 degree SVG arc. */
export function gaugeArc(score, { cx = 60, cy = 60, r = 48, sweep = 240 } = {}) {
  const value = Math.max(0, Math.min(100, Number(score) || 0));
  const start = 90 + (360 - sweep) / 2;
  const toXY = (deg) => {
    const rad = (deg * Math.PI) / 180;
    return [Number((cx + r * Math.cos(rad)).toFixed(2)), Number((cy + r * Math.sin(rad)).toFixed(2))];
  };
  const arc = (fromDeg, toDeg) => {
    const [x1, y1] = toXY(fromDeg);
    const [x2, y2] = toXY(toDeg);
    const large = toDeg - fromDeg > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
  };
  const end = start + (sweep * value) / 100;
  return {
    value,
    track: arc(start, start + sweep),
    fill: value > 0 ? arc(start, Math.max(start + 0.01, end)) : '',
    band: value >= 70 ? 'critical' : value >= 40 ? 'high' : value > 0 ? 'moderate' : 'clear',
  };
}

/**
 * Decision trace: the raw call, each unwrapped AST layer, the rule that fired on it
 * (if any), and the final decision. Every node carries plain text only.
 */
export function buildDecisionTrace(toolCall, evaluation) {
  const tool = toolCall?.tool || 'shell_exec';
  const a = toolCall?.args || {};
  const raw = String(a.command ?? a.path ?? a.url ?? a.name ?? '');
  const nodes = [{ kind: 'input', label: tool, text: raw, depth: 0 }];
  const records = evaluation?.ast?.records || [];
  const findings = evaluation?.findings || [];
  const sameTrail = (x, y) => x.length === y.length && x.every((v, i) => v === y[i]);
  const used = new Set();
  for (const rec of records) {
    const hit = findings.findIndex((f, i) => !used.has(i) && Array.isArray(f.trail) && sameTrail(f.trail, rec.trail));
    if (hit >= 0) used.add(hit);
    nodes.push({
      kind: 'layer',
      label: rec.command,
      text: [rec.command, ...rec.args].join(' '),
      depth: rec.depth,
      trail: rec.trail.join(' > '),
      rule: hit >= 0 ? findings[hit].ruleId : null,
      severity: hit >= 0 ? findings[hit].severity : null,
    });
  }
  findings.forEach((f, i) => {
    if (used.has(i)) return;
    nodes.push({ kind: 'rule', label: f.ruleId, text: f.title, depth: 0, rule: f.ruleId, severity: f.severity });
  });
  nodes.push({
    kind: 'decision',
    label: evaluation?.decision || 'ALLOW',
    text: evaluation?.blocked
      ? `${findings.length} finding${findings.length === 1 ? '' : 's'}, risk ${evaluation.riskScore}/100`
      : 'No capability rule fired',
    depth: 0,
    blocked: Boolean(evaluation?.blocked),
  });
  return nodes;
}

/** Side-by-side verdicts for one tool call: correct means it matches the label. */
export function buildVerdicts({ naive, flat, capgate }, expectedBlocked) {
  const row = (key, blocked) => ({
    key,
    label: DETECTORS.find((d) => d.key === key).label,
    blocked: Boolean(blocked),
    verdict: blocked ? 'BLOCK' : 'ALLOW',
    correct: typeof expectedBlocked === 'boolean' ? Boolean(blocked) === expectedBlocked : null,
  });
  return [row('naiveRegex', naive.blocked), row('flatGate', flat.blocked), row('capgate', capgate.blocked)];
}

/** Detector cards with the four headline rates as 0 to 1 bars. */
export function buildDetectorCards(bench) {
  return DETECTORS.map((d) => {
    const m = bench.detectors[d.key];
    return {
      ...d,
      metrics: [
        { name: 'Recall', value: m.recall, good: 'high' },
        { name: 'Precision', value: m.precision, good: 'high' },
        { name: 'F1', value: m.f1, good: 'high' },
        { name: 'False positive rate', value: m.fpr, good: 'low' },
      ],
      confusion: { tp: m.tp, fp: m.fp, tn: m.tn, fn: m.fn },
      caught: `${m.tp} of ${m.tp + m.fn} attacks blocked`,
    };
  });
}

/** Family by detector heat grid: share of cases each detector got right. */
export function buildFamilyMatrix(bench) {
  return bench.perCategory.map((c) => ({
    family: c.category,
    total: c.total,
    cells: [
      { key: 'capgate', correct: c.capCorrect, share: c.total ? c.capCorrect / c.total : 0 },
      { key: 'flatGate', correct: c.flatCorrect, share: c.total ? c.flatCorrect / c.total : 0 },
      { key: 'naiveRegex', correct: c.naiveCorrect, share: c.total ? c.naiveCorrect / c.total : 0 },
    ],
  }));
}

/** Unsafe cases that both baselines let through: the strongest ten-second demos. */
export function proofCases(bench) {
  return bench.rows.filter((r) => r.expectedBlocked && r.capBlocked && !r.naiveBlocked && !r.flatBlocked).map((r) => r.id);
}
