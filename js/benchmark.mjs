/**
 * Deterministic 36-case adversarial bypass & false-positive benchmark for CapGate.
 * Compares Naive Keyword Regex, Flat First-Token Gate, and CapGate AST+Capability Firewall.
 */

import {
  DEFAULT_POLICY,
  evaluateToolCall,
  evaluateNaiveRegex,
  evaluateFlatGate,
} from './capability-gate.mjs';
import { ADVERSARIAL_CORPUS } from './corpus.mjs';

function computeBinaryMetrics(predictions, truth) {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  for (let i = 0; i < predictions.length; i++) {
    const pred = Boolean(predictions[i]);
    const actual = Boolean(truth[i]);
    if (pred && actual) tp += 1;
    else if (pred && !actual) fp += 1;
    else if (!pred && !actual) tn += 1;
    else fn += 1;
  }
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy = predictions.length > 0 ? (tp + tn) / predictions.length : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  return {
    tp,
    fp,
    tn,
    fn,
    precision: Number(precision.toFixed(4)),
    recall: Number(recall.toFixed(4)),
    f1: Number(f1.toFixed(4)),
    accuracy: Number(accuracy.toFixed(4)),
    fpr: Number(fpr.toFixed(4)),
  };
}

export function runCapGateBenchmark(corpus = ADVERSARIAL_CORPUS, policy = DEFAULT_POLICY) {
  const rows = [];
  const truth = [];
  const naivePreds = [];
  const flatPreds = [];
  const capPreds = [];
  const categoryStats = new Map();

  for (const item of corpus) {
    const naive = evaluateNaiveRegex(item.toolCall);
    const flat = evaluateFlatGate(item.toolCall, policy);
    const capgate = evaluateToolCall(item.toolCall, policy);

    truth.push(item.expectedBlocked);
    naivePreds.push(naive.blocked);
    flatPreds.push(flat.blocked);
    capPreds.push(capgate.blocked);

    const cat = item.category;
    if (!categoryStats.has(cat)) {
      categoryStats.set(cat, { category: cat, total: 0, capCorrect: 0, naiveCorrect: 0, flatCorrect: 0 });
    }
    const cs = categoryStats.get(cat);
    cs.total += 1;
    if (capgate.blocked === item.expectedBlocked) cs.capCorrect += 1;
    if (naive.blocked === item.expectedBlocked) cs.naiveCorrect += 1;
    if (flat.blocked === item.expectedBlocked) cs.flatCorrect += 1;

    rows.push({
      id: item.id,
      category: item.category,
      title: item.title,
      expectedBlocked: item.expectedBlocked,
      naiveBlocked: naive.blocked,
      flatBlocked: flat.blocked,
      capBlocked: capgate.blocked,
      decision: capgate.decision,
      riskScore: capgate.riskScore,
      findingRules: capgate.findings.map((f) => f.ruleId),
      capgate,
    });
  }

  return {
    version: '1.1.0',
    corpusCount: corpus.length,
    unsafeCount: truth.filter(Boolean).length,
    benignCount: truth.filter((t) => !t).length,
    detectors: {
      naiveRegex: computeBinaryMetrics(naivePreds, truth),
      flatGate: computeBinaryMetrics(flatPreds, truth),
      capgate: computeBinaryMetrics(capPreds, truth),
    },
    perCategory: Array.from(categoryStats.values()),
    guardrails: [
      'Results measure accuracy on an authored 36-case synthetic tool-call corpus, not all possible OS bypasses or kernel escapes.',
      'CapGate performs static shell-AST and capability analysis in-browser/Node; it does not sand-box live syscalls.',
    ],
    rows,
  };
}
