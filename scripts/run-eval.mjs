import { runCapGateBenchmark } from '../js/benchmark.mjs';

const args = new Set(process.argv.slice(2));
const report = runCapGateBenchmark();

if (args.has('--json')) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exit(0);
}

const { naiveRegex, flatGate, capgate } = report.detectors;
console.log(`CapGate Adversarial Capability Benchmark v${report.version}`);
console.log(`Corpus: ${report.corpusCount} traces (${report.unsafeCount} unsafe across 6 families, ${report.benignCount} benign)`);
console.log(`Naive Regex  : P=${naiveRegex.precision} R=${naiveRegex.recall} F1=${naiveRegex.f1} Acc=${naiveRegex.accuracy} FPR=${naiveRegex.fpr}`);
console.log(`Flat Gate    : P=${flatGate.precision} R=${flatGate.recall} F1=${flatGate.f1} Acc=${flatGate.accuracy} FPR=${flatGate.fpr}`);
console.log(`CapGate AST  : P=${capgate.precision} R=${capgate.recall} F1=${capgate.f1} Acc=${capgate.accuracy} FPR=${capgate.fpr}`);

if (args.has('--check')) {
  if (capgate.f1 < 0.98 || capgate.fpr > 0) {
    console.error(`FAIL: CapGate metrics below threshold (F1=${capgate.f1}, FPR=${capgate.fpr})`);
    process.exit(1);
  }
  if (capgate.f1 <= flatGate.f1 || capgate.f1 <= naiveRegex.f1) {
    console.error('FAIL: CapGate did not outperform baselines.');
    process.exit(1);
  }
  console.log('Check: all benchmark precision/recall thresholds passed.');
}
