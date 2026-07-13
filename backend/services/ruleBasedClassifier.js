// ─────────────────────────────────────────────────────────────────
// ruleBasedClassifier.js — Rule-Based Baseline Classifier
// CyberShield AI — MSc Cybersecurity
// University of Roehampton, London 2026
//
// Academic context:
//  - Required by proposal RQ1: "Can an LLM-driven classification
//    engine produce threat verdicts that are comparable in accuracy
//    to those of a manual analyst... measuring precision, recall
//    and F1-score against a rule-based baseline?"
//  - This module provides that baseline.
//
// Methodology:
//  Uses simple weighted threshold scoring on the SAME enrichment
//  data the AI classifier receives — no LLM, no reasoning, just
//  deterministic if/else rules. This represents the kind of
//  rule-based detection logic found in traditional SIEM correlation
//  rules and legacy AV heuristics, predating AI-based classification.
//
// IMPORTANT: This module does NOT call any external API or LLM.
// It re-uses intelligence data already gathered by the main scan
// pipeline (VirusTotal, AbuseIPDB, Safe Browsing, WHOIS, etc.)
// so the comparison is fair — both classifiers see identical input.
// ─────────────────────────────────────────────────────────────────

const VERDICT_THRESHOLDS = {
  MALICIOUS : 60,
  SUSPICIOUS: 25
};

// ─────────────────────────────────────────────
// classifyDomainBaseline
// Simple weighted rule scoring — no AI reasoning
// ─────────────────────────────────────────────
function classifyDomainBaseline(intelligence) {
  let score = 0;
  const i = intelligence || {};
  const vt   = i.virusTotal   || {};
  const sb   = i.safeBrowsing || {};
  const cert = i.certificate  || {};
  const w    = i.whois        || {};
  const typo = i.typosquatting|| [];

  // Rule 1: VirusTotal detection ratio
  const vtRatio = (vt.malicious || 0) / (vt.totalEngines || 70);
  if (vtRatio > 0.10)      score += 40;
  else if (vtRatio > 0.03) score += 20;

  // Rule 2: Safe Browsing flag — binary, high weight
  if (sb.flagged) score += 35;

  // Rule 3: No SSL certificate
  if (cert.error) score += 15;
  else if (cert.isExpired) score += 20;

  // Rule 4: Domain age — newer domains score higher
  if (w.domainAgeDays != null) {
    if (w.domainAgeDays < 7)        score += 30;
    else if (w.domainAgeDays < 30)  score += 20;
    else if (w.domainAgeDays < 90)  score += 10;
  }

  // Rule 5: Typosquatting detected — fixed weight, no nuance
  if (typo.length > 0) score += 15;

  score = Math.min(score, 100);

  return {
    verdict: score >= VERDICT_THRESHOLDS.MALICIOUS ? 'MALICIOUS'
           : score >= VERDICT_THRESHOLDS.SUSPICIOUS ? 'SUSPICIOUS'
           : 'CLEAN',
    riskScore: score,
    method: 'rule-based-baseline'
  };
}

// ─────────────────────────────────────────────
// classifyIPBaseline
// ─────────────────────────────────────────────
function classifyIPBaseline(intelligence) {
  let score = 0;
  const i     = intelligence || {};
  const abuse = i.abuseIPDB || {};
  const asn   = i.asn       || {};

  // Rule 1: AbuseIPDB confidence score — direct mapping
  score += (abuse.abuseScore || 0) * 0.7;

  // Rule 2: Tor exit node — fixed penalty
  if (abuse.isTor) score += 20;

  // Rule 3: Report volume
  if ((abuse.totalReports || 0) > 50)      score += 15;
  else if ((abuse.totalReports || 0) > 10) score += 8;

  // Rule 4: Bulletproof hosting
  if (asn.isBulletproof) score += 15;

  score = Math.min(Math.round(score), 100);

  return {
    verdict: score >= VERDICT_THRESHOLDS.MALICIOUS ? 'MALICIOUS'
           : score >= VERDICT_THRESHOLDS.SUSPICIOUS ? 'SUSPICIOUS'
           : 'CLEAN',
    riskScore: score,
    method: 'rule-based-baseline'
  };
}

// ─────────────────────────────────────────────
// classifyEmailBaseline
// ─────────────────────────────────────────────
function classifyEmailBaseline(intelligence) {
  let score = 0;
  const i    = intelligence || {};
  const abs  = i.abstract    || {};
  const typo = i.typosquatting || [];

  // Rule 1: Disposable email — fixed high weight
  if (abs.isDisposable || i.builtIn?.isDisposable) score += 45;

  // Rule 2: Breach count — linear scaling, capped
  score += Math.min((abs.totalBreaches || 0) * 6, 30);

  // Rule 3: Undeliverable
  if (abs.deliverability === 'UNDELIVERABLE') score += 20;

  // Rule 4: Typosquatting on sender domain
  if (typo.length > 0) score += 20;

  // Rule 5: Quality score — inverse mapping
  if (abs.qualityScore !== undefined && abs.qualityScore < 0.3) score += 15;

  score = Math.min(Math.round(score), 100);

  return {
    verdict: score >= VERDICT_THRESHOLDS.MALICIOUS ? 'MALICIOUS'
           : score >= VERDICT_THRESHOLDS.SUSPICIOUS ? 'SUSPICIOUS'
           : 'CLEAN',
    riskScore: score,
    method: 'rule-based-baseline'
  };
}

// ─────────────────────────────────────────────
// classifyHashBaseline
// ─────────────────────────────────────────────
function classifyHashBaseline(intelligence) {
  let score = 0;
  const i  = intelligence || {};
  const vt = i.virusTotal || {};

  // Rule 1: Detection ratio — direct linear mapping
  const total = vt.totalEngines || 70;
  const ratio = (vt.malicious || 0) / total;
  score += ratio * 90;

  // Rule 2: Suspicious flags add a small fixed amount
  score += Math.min((vt.suspicious || 0) * 2, 10);

  score = Math.min(Math.round(score), 100);

  return {
    verdict: score >= VERDICT_THRESHOLDS.MALICIOUS ? 'MALICIOUS'
           : score >= VERDICT_THRESHOLDS.SUSPICIOUS ? 'SUSPICIOUS'
           : 'CLEAN',
    riskScore: score,
    method: 'rule-based-baseline'
  };
}

// ─────────────────────────────────────────────
// classifyHeaderBaseline
// ─────────────────────────────────────────────
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

  return {
    verdict: score >= VERDICT_THRESHOLDS.MALICIOUS ? 'MALICIOUS'
           : score >= VERDICT_THRESHOLDS.SUSPICIOUS ? 'SUSPICIOUS'
           : 'CLEAN',
    riskScore: score,
    method: 'rule-based-baseline'
  };
}

// ─────────────────────────────────────────────
// MAIN EXPORT — classifyBaseline()
//
// Routes to the correct rule-based classifier
// based on scan type. Used only during evaluation
// runs — NOT called during normal user scans.
// ─────────────────────────────────────────────
function classifyBaseline(scanType, intelligence) {
  switch (scanType) {
    case 'domain':
    case 'url':    return classifyDomainBaseline(intelligence);
    case 'ip':     return classifyIPBaseline(intelligence);
    case 'email':  return classifyEmailBaseline(intelligence);
    case 'hash':   return classifyHashBaseline(intelligence);
    case 'header': return classifyHeaderBaseline(intelligence);
    default:
      return { verdict: 'UNKNOWN', riskScore: 0, method: 'rule-based-baseline' };
  }
}

module.exports = {
  classifyBaseline,
  classifyDomainBaseline,
  classifyIPBaseline,
  classifyEmailBaseline,
  classifyHashBaseline,
  classifyHeaderBaseline
};