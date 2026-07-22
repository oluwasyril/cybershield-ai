// ─────────────────────────────────────────────────────────────────
// run_evaluation.js — CyberShield AI Evaluation Runner
// CyberShield AI — MSc Cybersecurity
// University of Roehampton, London 2026
//
// Satisfies proposal O6:
//   "Evaluate the AI classifier against a labelled IOC dataset,
//    measuring precision, recall, F1-score and scan-to-alert
//    latency against a rule-based baseline."
//
// This runner:
//  1. Sends each labelled IOC to the live CyberShield AI API
//  2. Records the AI verdict + risk score + scan duration
//  3. Re-computes the SAME intelligence through the rule-based
//     baseline classifier (no second API calls — reuses the
//     intelligence object already returned by the scan)
//  4. Saves both sets of results for calculate_metrics.js
//
// Usage:
//   node run_evaluation.js --type=domain
//   node run_evaluation.js --type=ip
//   node run_evaluation.js --type=email
//   node run_evaluation.js --type=all
//
// Requires: export CS_TOKEN="your_firebase_id_token"
// ─────────────────────────────────────────────────────────────────

const fs   = require('fs');
const path = require('path');

const API_BASE = process.env.CS_API_BASE || 'https://cybershield-backend-irzr.onrender.com/api';
const TOKEN    = process.env.CS_TOKEN;

if (!TOKEN) {
  console.error('\n✗ ERROR: CS_TOKEN environment variable not set.');
  console.error('  Get your token from the browser console, then run:');
  console.error('  export CS_TOKEN="your_token_here"\n');
  process.exit(1);
}

// ─────────────────────────────────────────────
// Rule-based baseline classifier
// Mirrors backend/services/ruleBasedClassifier.js
// Duplicated here so the evaluation script has
// zero dependency on the backend codebase —
// it only needs the intelligence JSON already
// returned by the live scan API.
// ─────────────────────────────────────────────
function classifyDomainBaseline(intelligence) {
  let score = 0;
  const i = intelligence || {};
  const vt = i.virusTotal || {}, sb = i.safeBrowsing || {}, cert = i.certificate || {}, w = i.whois || {}, typo = i.typosquatting || [];
  const vtRatio = (vt.malicious || 0) / (vt.totalEngines || 70);
  if (vtRatio > 0.10) score += 40; else if (vtRatio > 0.03) score += 20;
  if (sb.flagged) score += 35;
  if (cert.error) score += 15; else if (cert.isExpired) score += 20;
  if (w.domainAgeDays != null) {
    if (w.domainAgeDays < 7) score += 30;
    else if (w.domainAgeDays < 30) score += 20;
    else if (w.domainAgeDays < 90) score += 10;
  }
  if (typo.length > 0) score += 15;
  score = Math.min(score, 100);
  return { verdict: score >= 60 ? 'MALICIOUS' : score >= 25 ? 'SUSPICIOUS' : 'CLEAN', riskScore: score };
}

function classifyIPBaseline(intelligence) {
  let score = 0;
  const i = intelligence || {};
  const abuse = i.abuseIPDB || {}, asn = i.asn || {};
  score += (abuse.abuseScore || 0) * 0.7;
  if (abuse.isTor) score += 20;
  if ((abuse.totalReports || 0) > 50) score += 15; else if ((abuse.totalReports || 0) > 10) score += 8;
  if (asn.isBulletproof) score += 15;
  score = Math.min(Math.round(score), 100);
  return { verdict: score >= 60 ? 'MALICIOUS' : score >= 25 ? 'SUSPICIOUS' : 'CLEAN', riskScore: score };
}

function classifyEmailBaseline(intelligence) {
  let score = 0;
  const i = intelligence || {};
  const abs = i.abstract || {}, typo = i.typosquatting || [];
  if (abs.isDisposable || i.builtIn?.isDisposable) score += 45;
  score += Math.min((abs.totalBreaches || 0) * 6, 30);
  if (abs.deliverability === 'UNDELIVERABLE') score += 20;
  if (typo.length > 0) score += 20;
  if (abs.qualityScore !== undefined && abs.qualityScore < 0.3) score += 15;
  score = Math.min(Math.round(score), 100);
  return { verdict: score >= 60 ? 'MALICIOUS' : score >= 25 ? 'SUSPICIOUS' : 'CLEAN', riskScore: score };
}

function classifyHashBaseline(intelligence) {
  let score = 0;
  const i  = intelligence || {};
  const vt = i.virusTotal || {};
  const total = vt.totalEngines || 70;
  const ratio = (vt.malicious || 0) / total;
  score += ratio * 90;
  score += Math.min((vt.suspicious || 0) * 2, 10);
  score = Math.min(Math.round(score), 100);
  return { verdict: score >= 60 ? 'MALICIOUS' : score >= 25 ? 'SUSPICIOUS' : 'CLEAN', riskScore: score };
}

function classifyHeaderBaseline(intelligence) {
  let score = 0;
  const i     = intelligence || {};
  const auth  = i.authentication || {};
  const links = i.phishingLinks  || [];
  if (auth.spf === 'fail')   score += 25;
  if (auth.dkim === 'fail')  score += 25;
  if (auth.dmarc === 'fail') score += 15;
  if (i.spoofingDetected)    score += 25;
  const critLinks = links.filter(l => l.risk === 'CRITICAL' || l.risk === 'HIGH');
  score += Math.min(critLinks.length * 10, 30);
  score = Math.min(Math.round(score), 100);
  return { verdict: score >= 60 ? 'MALICIOUS' : score >= 25 ? 'SUSPICIOUS' : 'CLEAN', riskScore: score };
}

function classifyBaseline(scanType, intelligence) {
  if (scanType === 'domain' || scanType === 'url') return classifyDomainBaseline(intelligence);
  if (scanType === 'ip')     return classifyIPBaseline(intelligence);
  if (scanType === 'email')  return classifyEmailBaseline(intelligence);
  if (scanType === 'hash')   return classifyHashBaseline(intelligence);
  if (scanType === 'header') return classifyHeaderBaseline(intelligence);
  return { verdict: 'UNKNOWN', riskScore: 0 };
}

// ─────────────────────────────────────────────
// Endpoint mapping
// ─────────────────────────────────────────────
const ENDPOINTS = {
  domain: { path: 'scan-domain', bodyKey: 'input' },
  ip    : { path: 'scan-ip',     bodyKey: 'ip'    },
  email : { path: 'scan-email',  bodyKey: 'email' },
  hash  : { path: 'scan-hash',   bodyKey: 'hash'  },
  header: { path: 'scan-header', bodyKey: 'headers' } // special-cased below
};

// ─────────────────────────────────────────────
// Run evaluation for one dataset type
// ─────────────────────────────────────────────
async function runDataset(type) {
  const filenameMap = { domain: 'domains.json', hash: 'hashes.json', header: 'headers.json' };
  const filename = filenameMap[type] || `${type}s.json`;
  const datasetPath = path.join(__dirname, 'datasets', filename);

  if (!fs.existsSync(datasetPath)) {
    console.error(`✗ Dataset not found: ${datasetPath}`);
    return null;
  }

  const dataset = JSON.parse(fs.readFileSync(datasetPath, 'utf8'));
  const endpoint = ENDPOINTS[type];

  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  EVALUATING: ${type.toUpperCase()} — ${dataset.length} samples`);
  console.log(`${'═'.repeat(60)}\n`);

  const results = [];

  for (let i = 0; i < dataset.length; i++) {
    const sample = dataset[i];
    const isHeader = type === 'header';
    const value = isHeader
      ? (sample.headers.match(/Subject: (.+)/)?.[1] || `sample-${i + 1}`).slice(0, 40)
      : sample.value;
    const expected = (sample.label || '').toUpperCase();

    process.stdout.write(`[${i + 1}/${dataset.length}] ${value.padEnd(40)} `);

    try {
      const scanStart = Date.now();
      const requestBody = isHeader
        ? { headers: sample.headers, body: sample.body || '' }
        : { [endpoint.bodyKey]: value };

      const res = await fetch(`${API_BASE}/${endpoint.path}`, {
        method : 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + TOKEN },
        body   : JSON.stringify(requestBody)
      });
      const scanDuration = Date.now() - scanStart;
      const data = await res.json();

      if (!data.success) {
        console.log(`ERROR: ${data.error}`);
        results.push({ value, expected, error: data.error, aiVerdict: 'ERROR', baselineVerdict: 'ERROR' });
        continue;
      }

      const aiVerdict       = data.assessment?.verdict || 'UNKNOWN';
      const aiRiskScore     = data.assessment?.riskScore || 0;
      const baselineResult  = classifyBaseline(type, data.intelligence);

      const aiMatch       = aiVerdict === expected ? '✓' : '✗';
      const baselineMatch = baselineResult.verdict === expected ? '✓' : '✗';

      console.log(`AI: ${aiVerdict.padEnd(10)} ${aiMatch}  Baseline: ${baselineResult.verdict.padEnd(10)} ${baselineMatch}  (${scanDuration}ms)`);

      results.push({
        value,
        expected,
        aiVerdict,
        aiRiskScore,
        baselineVerdict: baselineResult.verdict,
        baselineRiskScore: baselineResult.riskScore,
        scanDurationMs: scanDuration,
        aiCorrect: aiVerdict === expected,
        baselineCorrect: baselineResult.verdict === expected
      });

    } catch (err) {
      console.log(`FAILED: ${err.message}`);
      results.push({ value, expected, error: err.message, aiVerdict: 'ERROR', baselineVerdict: 'ERROR' });
    }

    // Rate limit protection — 32 second delay between requests
    // Backend allows 30 scans per 15 minutes (900s / 30 = 30s minimum gap)
    // 32s gives a small safety margin
    if (i < dataset.length - 1) await new Promise(r => setTimeout(r, 32000));
  }

  // Save raw results
  const outPath = path.join(__dirname, 'results', `${type}_results.json`);
  fs.writeFileSync(outPath, JSON.stringify(results, null, 2));
  console.log(`\n✓ Results saved to ${outPath}`);

  return results;
}

// ─────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────
async function main() {
  const typeArg = process.argv.find(a => a.startsWith('--type='));
  const type    = typeArg ? typeArg.split('=')[1] : 'all';

  if (type === 'all') {
    for (const t of ['domain', 'ip', 'email', 'hash', 'header']) {
      await runDataset(t);
    }
  } else {
    await runDataset(type);
  }

  console.log(`\n${'═'.repeat(60)}`);
  console.log('  EVALUATION COMPLETE');
  console.log('  Run: node calculate_metrics.js');
  console.log(`${'═'.repeat(60)}\n`);
}

main();