// ─────────────────────────────────────────────────────────────────
// calculate_metrics.js — Evaluation Metrics Calculator
// CyberShield AI — MSc Cybersecurity
// University of Roehampton, London 2026
//
// Computes Precision, Recall, F1-Score, and Accuracy for both:
//  - The AI classifier (Groq LLaMA 3.3-70B)
//  - The rule-based baseline classifier
//
// Per proposal O6: "measuring precision, recall, F1-score and
// scan-to-alert latency against a rule-based baseline."
//
// Multi-class handling: treats this as a 3-class problem
// (MALICIOUS / SUSPICIOUS / CLEAN) and computes macro-averaged
// Precision/Recall/F1 — the standard approach for multi-class
// classification evaluation in security research.
//
// Usage: node calculate_metrics.js
// Reads from: evaluation/results/*.json
// ─────────────────────────────────────────────────────────────────

const fs   = require('fs');
const path = require('path');

const CLASSES = ['MALICIOUS', 'SUSPICIOUS', 'CLEAN'];

// ─────────────────────────────────────────────
// Confusion matrix for one class (one-vs-rest)
// ─────────────────────────────────────────────
function confusionForClass(results, verdictKey, expectedKey, targetClass) {
  let tp = 0, fp = 0, fn = 0, tn = 0;

  results.forEach(r => {
    const predicted = r[verdictKey];
    const actual    = r[expectedKey];
    if (predicted === 'ERROR' || !predicted) return;

    const predPositive = predicted === targetClass;
    const actPositive  = actual === targetClass;

    if (predPositive && actPositive)       tp++;
    else if (predPositive && !actPositive) fp++;
    else if (!predPositive && actPositive) fn++;
    else                                    tn++;
  });

  const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
  const recall    = (tp + fn) > 0 ? tp / (tp + fn) : 0;
  const f1        = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0;

  return { tp, fp, fn, tn, precision, recall, f1 };
}

// ─────────────────────────────────────────────
// Macro-averaged metrics across all 3 classes
// ─────────────────────────────────────────────
function calculateMetrics(results, verdictKey, expectedKey) {
  const validResults = results.filter(r => r[verdictKey] !== 'ERROR' && r[verdictKey]);

  const perClass = CLASSES.map(cls => ({
    class: cls,
    ...confusionForClass(validResults, verdictKey, expectedKey, cls)
  }));

  const macroPrecision = perClass.reduce((sum, c) => sum + c.precision, 0) / CLASSES.length;
  const macroRecall    = perClass.reduce((sum, c) => sum + c.recall, 0) / CLASSES.length;
  const macroF1        = perClass.reduce((sum, c) => sum + c.f1, 0) / CLASSES.length;

  const correct  = validResults.filter(r => r[verdictKey] === r[expectedKey]).length;
  const accuracy = validResults.length > 0 ? correct / validResults.length : 0;

  return {
    accuracy      : accuracy,
    macroPrecision: macroPrecision,
    macroRecall   : macroRecall,
    macroF1       : macroF1,
    perClass,
    totalSamples  : results.length,
    validSamples  : validResults.length,
    errors        : results.length - validResults.length
  };
}

// ─────────────────────────────────────────────
// Latency statistics
// ─────────────────────────────────────────────
function calculateLatency(results) {
  const durations = results.map(r => r.scanDurationMs).filter(d => d != null);
  if (durations.length === 0) return null;

  const sorted = [...durations].sort((a, b) => a - b);
  const avg    = durations.reduce((a, b) => a + b, 0) / durations.length;
  const median = sorted[Math.floor(sorted.length / 2)];
  const p95    = sorted[Math.floor(sorted.length * 0.95)];

  return {
    avgMs   : Math.round(avg),
    medianMs: median,
    p95Ms   : p95,
    minMs   : sorted[0],
    maxMs   : sorted[sorted.length - 1]
  };
}

// ─────────────────────────────────────────────
// Print formatted report
// ─────────────────────────────────────────────
function printReport(type, results) {
  console.log(`\n${'═'.repeat(70)}`);
  console.log(`  ${type.toUpperCase()} SCANNER — EVALUATION REPORT`);
  console.log(`${'═'.repeat(70)}\n`);

  const aiMetrics       = calculateMetrics(results, 'aiVerdict', 'expected');
  const baselineMetrics = calculateMetrics(results, 'baselineVerdict', 'expected');
  const latency         = calculateLatency(results);

  console.log(`Total samples: ${aiMetrics.totalSamples} (${aiMetrics.errors} errors)\n`);

  console.log('┌─────────────────────┬──────────────┬──────────────┐');
  console.log('│ Metric              │ AI (LLaMA)   │ Rule Baseline│');
  console.log('├─────────────────────┼──────────────┼──────────────┤');
  console.log(`│ Accuracy            │ ${(aiMetrics.accuracy * 100).toFixed(1).padStart(11)}% │ ${(baselineMetrics.accuracy * 100).toFixed(1).padStart(11)}% │`);
  console.log(`│ Precision (macro)   │ ${(aiMetrics.macroPrecision * 100).toFixed(1).padStart(11)}% │ ${(baselineMetrics.macroPrecision * 100).toFixed(1).padStart(11)}% │`);
  console.log(`│ Recall (macro)      │ ${(aiMetrics.macroRecall * 100).toFixed(1).padStart(11)}% │ ${(baselineMetrics.macroRecall * 100).toFixed(1).padStart(11)}% │`);
  console.log(`│ F1-Score (macro)    │ ${(aiMetrics.macroF1 * 100).toFixed(1).padStart(11)}% │ ${(baselineMetrics.macroF1 * 100).toFixed(1).padStart(11)}% │`);
  console.log('└─────────────────────┴──────────────┴──────────────┘\n');

  console.log('Per-class breakdown (AI classifier):');
  aiMetrics.perClass.forEach(c => {
    console.log(`  ${c.class.padEnd(12)} Precision: ${(c.precision*100).toFixed(1)}%  Recall: ${(c.recall*100).toFixed(1)}%  F1: ${(c.f1*100).toFixed(1)}%  (TP:${c.tp} FP:${c.fp} FN:${c.fn})`);
  });

  if (latency) {
    console.log(`\nScan latency:`);
    console.log(`  Average: ${latency.avgMs}ms   Median: ${latency.medianMs}ms   P95: ${latency.p95Ms}ms   Range: ${latency.minMs}-${latency.maxMs}ms`);
  }

  const improvement = ((aiMetrics.macroF1 - baselineMetrics.macroF1) * 100).toFixed(1);
  console.log(`\n${improvement >= 0 ? '▲' : '▼'} AI F1-Score is ${Math.abs(improvement)}pp ${improvement >= 0 ? 'higher' : 'lower'} than rule-based baseline\n`);

  return { aiMetrics, baselineMetrics, latency };
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────
function main() {
  const resultsDir = path.join(__dirname, 'results');
  const types = ['domain', 'ip', 'email', 'hash', 'header'];
  const allReports = {};

  types.forEach(type => {
    const filePath = path.join(resultsDir, `${type}_results.json`);
    if (!fs.existsSync(filePath)) {
      console.log(`\n⚠ No results found for ${type} — run: node run_evaluation.js --type=${type}`);
      return;
    }
    const results = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    allReports[type] = printReport(type, results);
  });

  // Save consolidated report for dissertation appendix
  const summaryPath = path.join(resultsDir, 'evaluation_summary.json');
  fs.writeFileSync(summaryPath, JSON.stringify(allReports, null, 2));
  console.log(`\n${'═'.repeat(70)}`);
  console.log(`  Full summary saved to: ${summaryPath}`);
  console.log(`  Use these numbers in Chapter 4 — Evaluation`);
  console.log(`${'═'.repeat(70)}\n`);
}

main();