// ─────────────────────────────────────────────────────────────────
// routes/bulkScan.js — Bulk IOC Scanner
// CyberShield AI — MSc Cybersecurity
// University of Roehampton, London 2026
//
// Accepts up to 10 IOCs in a single request.
// Detects type automatically (IP, domain, email, hash)
// and routes each to the correct scanner service.
//
// Academic context:
//  - Demonstrates automation at scale — core claim of project
//  - Maps to Cyber Security Automation module
//  - Reduces mean time to triage (MTTT) for multiple IOCs
//  - Mirrors enterprise SOAR playbook bulk enrichment
//
// Rate limiting: inherits scan limiter from server.js (30/15min)
// Additional internal limit: max 10 IOCs per request
// ─────────────────────────────────────────────────────────────────

const express            = require('express');
const router             = express.Router();
const { authenticate }   = require('../middleware/authenticate');
const { logScan }        = require('../middleware/auditLog');
const { sendThreatAlert }= require('../services/alertService');

// Scanner services
const { scanDomain }      = require('../services/domainScanner');
const abuseIPDB           = require('../services/abuseIPDB');
const { scanEmail }       = require('../services/emailScanner');
const { scanHash }        = require('../services/hashScanner');
const groqAI              = require('../services/groqAnalysis');
const { enrichScanResult }= require('../services/threatEnricher');
const { detectTyposquatting, analyseURLBehaviour, scoreCertificateRisk } = require('../services/urlAnalyser');
const { lookupASN, getMalwareFamily } = require('../services/asnIntelligence');

// ─────────────────────────────────────────────
// IOC Type Detection
// Automatically identifies what type each IOC is
// so the user does not have to specify
// ─────────────────────────────────────────────
function detectIOCType(value) {
  const v = value.trim();

  // IP address — IPv4
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ip';

  // Email address
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return 'email';

  // File hash — MD5, SHA1, SHA256
  if (/^[a-f0-9]{32}$/i.test(v)) return 'hash';  // MD5
  if (/^[a-f0-9]{40}$/i.test(v)) return 'hash';  // SHA1
  if (/^[a-f0-9]{64}$/i.test(v)) return 'hash';  // SHA256

  // URL or domain — everything else
  return 'domain';
}

// ─────────────────────────────────────────────
// Scan a single IOC — routes to correct scanner
// Returns a standardised result object
// ─────────────────────────────────────────────
async function scanSingleIOC(value, type) {
  const start = Date.now();

  try {
    let assessment, intelligence, target, enriched;

    if (type === 'domain') {
      const domainIntelligence = await scanDomain(value);
      const urlBehaviour       = analyseURLBehaviour(domainIntelligence.url || value);
      const typosquatting      = detectTyposquatting(domainIntelligence.domain);
      const certRisk           = scoreCertificateRisk(domainIntelligence.intelligence.certificate);

      domainIntelligence.intelligence.urlBehaviour  = urlBehaviour;
      domainIntelligence.intelligence.typosquatting = typosquatting;
      domainIntelligence.intelligence.certRisk      = certRisk;

      assessment  = await groqAI.analyseThreat(domainIntelligence.domain, 'domain', domainIntelligence);
      target      = domainIntelligence.domain;
      intelligence= domainIntelligence.intelligence;
    }

    else if (type === 'ip') {
      const abuseResult = await abuseIPDB.checkIP(value);
      const asnData     = await lookupASN(value);
      intelligence      = { abuseIPDB: abuseResult, asn: asnData };
      assessment        = await groqAI.analyseThreat(value, 'ip', { intelligence });
      target            = value;
    }

    else if (type === 'email') {
      const emailIntelligence     = await scanEmail(value);
      const { detectTyposquatting } = require('../services/urlAnalyser');
      const domain                = value.split('@')[1];
      emailIntelligence.intelligence.typosquatting = detectTyposquatting(domain);
      assessment  = await groqAI.analyseThreat(value, 'email', emailIntelligence);
      target      = value;
      intelligence= emailIntelligence.intelligence;
    }

    else if (type === 'hash') {
      const hashIntelligence = await scanHash(value.trim());
      const vt               = hashIntelligence.intelligence?.virusTotal;
      const malwareFamily    = getMalwareFamily(vt?.threatLabels, vt?.threatCategory);
      if (malwareFamily) hashIntelligence.intelligence.malwareFamily = malwareFamily;
      assessment  = await groqAI.analyseThreat(hashIntelligence.hash, 'hash', hashIntelligence);
      target      = hashIntelligence.hash;
      intelligence= hashIntelligence.intelligence;
    }

    try {
      enriched = enrichScanResult(type, target, assessment, intelligence);
    } catch (enrichErr) {
      enriched = { timestamp: new Date().toISOString(), target, scanType: type, assessment, intelligence, enrichment: null };
    }

    return {
      success  : true,
      scanType : type,
      target,
      duration : Date.now() - start,
      ...enriched
    };

  } catch (err) {
    return {
      success  : false,
      scanType : type,
      target   : value,
      duration : Date.now() - start,
      error    : err.message,
      assessment: { verdict: 'ERROR', riskScore: 0, summary: `Scan failed: ${err.message}`, keyIndicators: [], recommendedAction: 'REVIEW' }
    };
  }
}

// ─────────────────────────────────────────────
// POST /api/bulk/scan
// Accepts: { iocs: ["domain.com", "1.2.3.4", ...] }
// Max 10 IOCs per request
// Scans sequentially with 1.5s delay to respect
// free tier rate limits across all APIs
// ─────────────────────────────────────────────
router.post('/scan', authenticate, async (req, res) => {
  const { iocs } = req.body;

  if (!Array.isArray(iocs) || iocs.length === 0) {
    return res.status(400).json({ success: false, error: 'Please provide an array of IOCs to scan.' });
  }

  if (iocs.length > 10) {
    return res.status(400).json({ success: false, error: 'Maximum 10 IOCs per bulk scan request.' });
  }

  // Validate and deduplicate
  const cleanIOCs = [...new Set(iocs.map(i => String(i).trim()).filter(i => i.length >= 3))];

  if (cleanIOCs.length === 0) {
    return res.status(400).json({ success: false, error: 'No valid IOCs found in request.' });
  }

  console.log(`\n[BULK SCAN] ═══ ${cleanIOCs.length} IOCs — User: ${req.user.uid} ═══`);

  const results = [];
  const summary = { total: cleanIOCs.length, malicious: 0, suspicious: 0, clean: 0, errors: 0 };

  for (let i = 0; i < cleanIOCs.length; i++) {
    const value = cleanIOCs[i];
    const type  = detectIOCType(value);

    console.log(`[BULK] [${i + 1}/${cleanIOCs.length}] ${type.toUpperCase()}: ${value}`);

    const result = await scanSingleIOC(value, type);
    results.push(result);

    // Update summary counts
    const verdict = result.assessment?.verdict;
    if (verdict === 'MALICIOUS')  summary.malicious++;
    else if (verdict === 'SUSPICIOUS') summary.suspicious++;
    else if (verdict === 'CLEAN') summary.clean++;
    else                          summary.errors++;

    // Log to audit trail
    logScan(req, type, value, verdict, result.assessment?.riskScore);

    // Send alert if malicious
    if (verdict === 'MALICIOUS') {
      sendThreatAlert(req.user?.email, type, value, result.assessment, result.enrichment);
    }

    // Delay between requests to respect API rate limits
    // Skip delay after the last IOC
    if (i < cleanIOCs.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 1500));
    }
  }

  console.log(`[BULK SCAN] Complete — ${summary.malicious} malicious, ${summary.suspicious} suspicious, ${summary.clean} clean`);

  res.json({
    success: true,
    summary,
    results,
    timestamp: new Date().toISOString()
  });
});

module.exports = router;