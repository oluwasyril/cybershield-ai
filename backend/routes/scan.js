// ─────────────────────────────────────────────
// scan.js — All Scanner Routes
// CyberShield AI — MSc Cybersecurity
// University of Roehampton, London 2026
// ─────────────────────────────────────────────

const express      = require('express');
const router       = express.Router();

// ── Middleware ────────────────────────────────
const { validateScanInput, validateIPInput } = require('../middleware/validateInput');
const { authenticate }                        = require('../middleware/authenticate');
const { logScan }                             = require('../middleware/auditLog');

// ── Core Services ─────────────────────────────
const virusTotal   = require('../services/virusTotal');
const safeBrowsing = require('../services/safeBrowsing');
const abuseIPDB    = require('../services/abuseIPDB');
const groqAI       = require('../services/groqAnalysis');

// ── Scanner Services ──────────────────────────
const { scanEmail }     = require('../services/emailScanner');
const { analyseHeaders }= require('../services/headerAnalyser');
const { scanHash }      = require('../services/hashScanner');
const { scanDomain }    = require('../services/domainScanner');

// ── New Intelligence Services ─────────────────
const { mapToATTACK }                     = require('../services/mitreMapper');
const { detectTyposquatting,
        analyseURLBehaviour,
        scoreCertificateRisk }            = require('../services/urlAnalyser');
const { lookupASN, getMalwareFamily }     = require('../services/asnIntelligence');
const { enrichScanResult }               = require('../services/threatEnricher');
const { sendThreatAlert }                = require('../services/alertService');

// ─────────────────────────────────────────────
// POST /api/scan-url
// Legacy URL scan — kept for backwards compat
// ─────────────────────────────────────────────

router.post('/scan-url', authenticate, validateScanInput, async (req, res) => {
  const { url } = req.body;
  console.log(`\n[SCAN] ═══ URL: ${url} ═══`);
  try {
    const [vtResult, gsbResult] = await Promise.allSettled([
      virusTotal.scanUrl(url),
      safeBrowsing.checkUrl(url)
    ]);
    const intelligence = {
      virusTotal  : vtResult.status  === 'fulfilled' ? vtResult.value  : { error: true },
      safeBrowsing: gsbResult.status === 'fulfilled' ? gsbResult.value : { error: true }
    };
    const assessment = await groqAI.analyseThreat(url, 'url', intelligence);
    res.status(200).json({
      success   : true,
      timestamp : new Date().toISOString(),
      target    : url,
      scanType  : 'url',
      assessment,
      intelligence
    });
  } catch (error) {
    console.error('[URL SCAN ERROR]', error.message);
    res.status(500).json({ success: false, error: 'Scan failed.' });
  }
});

// ─────────────────────────────────────────────
// POST /api/scan-domain
// Full Domain & URL Intelligence Scanner
// ─────────────────────────────────────────────

router.post('/scan-domain', authenticate, async (req, res) => {
  const { input } = req.body;
  const scanStartTime = Date.now();

  if (!input || typeof input !== 'string' || input.trim().length < 4) {
    return res.status(400).json({ success: false, error: 'A valid URL or domain is required.' });
  }

  console.log(`\n[SCAN] ═══ Domain: ${input.trim()} ═══`);

  try {
    const domainIntelligence = await scanDomain(input.trim());
    const urlBehaviour       = analyseURLBehaviour(domainIntelligence.url || input.trim());
    const typosquatting      = detectTyposquatting(domainIntelligence.domain);
    const certRisk           = scoreCertificateRisk(domainIntelligence.intelligence.certificate);

    domainIntelligence.intelligence.urlBehaviour  = urlBehaviour;
    domainIntelligence.intelligence.typosquatting = typosquatting;
    domainIntelligence.intelligence.certRisk      = certRisk;

    const assessment = await groqAI.analyseThreat(
      domainIntelligence.domain,
      'domain',
      domainIntelligence
    );

    console.log(`[SCAN] Domain complete — Verdict: ${assessment.verdict} Risk: ${assessment.riskScore} MITRE: ${assessment.mitre?.techniques?.length || 0} techniques`);

    let enriched;
    try {
      enriched = enrichScanResult('domain', domainIntelligence.domain, assessment, domainIntelligence.intelligence);
    } catch (enrichErr) {
      console.error('[DOMAIN ENRICH ERROR]', enrichErr.message, enrichErr.stack);
      enriched = { timestamp: new Date().toISOString(), target: domainIntelligence.domain, scanType: 'domain', assessment, intelligence: domainIntelligence.intelligence, enrichment: null };
    }

    res.status(200).json({ success: true, ...enriched });

    const { scanCompletedAt } = await logScan(req, 'domain', domainIntelligence.domain, assessment.verdict, assessment.riskScore, 'SUCCESS', scanStartTime);
    sendThreatAlert(req.user?.email, 'domain', domainIntelligence.domain, assessment, req, scanCompletedAt);

  } catch (error) {
    console.error('[DOMAIN SCAN ERROR]', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ─────────────────────────────────────────────
// POST /api/scan-ip
// IP Address Scanner
// ─────────────────────────────────────────────

router.post('/scan-ip', authenticate, validateIPInput, async (req, res) => {
  const { ip } = req.body;
  const scanStartTime = Date.now();
  console.log(`\n[SCAN] ═══ IP: ${ip} ═══`);

  try {
    const abuseResult = await abuseIPDB.checkIP(ip);
    const asnData     = await lookupASN(ip);
    const intelligence = { abuseIPDB: abuseResult, asn: asnData };
    const assessment   = await groqAI.analyseThreat(ip, 'ip', { intelligence });

    console.log(`[SCAN] IP complete — Verdict: ${assessment.verdict} Abuse: ${abuseResult.abuseScore}% ASN: ${asnData.asn || 'N/A'} MITRE: ${assessment.mitre?.techniques?.length || 0} techniques`);

    let enrichedIP;
    try {
      enrichedIP = enrichScanResult('ip', ip, assessment, intelligence);
    } catch (enrichErr) {
      console.error('[IP ENRICH ERROR]', enrichErr.message);
      enrichedIP = { timestamp: new Date().toISOString(), target: ip, scanType: 'ip', assessment, intelligence, enrichment: null };
    }

    res.status(200).json({ success: true, ...enrichedIP });

    const { scanCompletedAt } = await logScan(req, 'ip', ip, assessment.verdict, assessment.riskScore, 'SUCCESS', scanStartTime);
    sendThreatAlert(req.user?.email, 'ip', ip, assessment, req, scanCompletedAt);

  } catch (error) {
    console.error('[IP SCAN ERROR]', error.message);
    res.status(500).json({ success: false, error: 'IP scan failed.' });
  }
});

// ─────────────────────────────────────────────
// POST /api/scan-email
// Email Address Scanner
// ─────────────────────────────────────────────

router.post('/scan-email', authenticate, async (req, res) => {
  const { email } = req.body;
  const scanStartTime = Date.now();

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ success: false, error: 'Valid email address required.' });
  }

  const cleanEmail = email.trim().toLowerCase();
  const domain     = cleanEmail.split('@')[1];
  console.log(`\n[SCAN] ═══ Email: ${cleanEmail} ═══`);

  try {
    const emailIntelligence = await scanEmail(cleanEmail);
    const typosquatting     = detectTyposquatting(domain);
    emailIntelligence.intelligence.typosquatting = typosquatting;

    const assessment = await groqAI.analyseThreat(cleanEmail, 'email', emailIntelligence);

    console.log(`[SCAN] Email complete — Verdict: ${assessment.verdict} Risk: ${assessment.riskScore} Typosquat hits: ${typosquatting.length} MITRE: ${assessment.mitre?.techniques?.length || 0} techniques`);

    let enrichedEmail;
    try {
      enrichedEmail = enrichScanResult('email', cleanEmail, assessment, emailIntelligence.intelligence);
    } catch (enrichErr) {
      console.error('[EMAIL ENRICH ERROR]', enrichErr.message);
      enrichedEmail = { timestamp: new Date().toISOString(), target: cleanEmail, scanType: 'email', assessment, intelligence: emailIntelligence.intelligence, enrichment: null };
    }

    res.status(200).json({ success: true, ...enrichedEmail });

    const { scanCompletedAt } = await logScan(req, 'email', cleanEmail, assessment.verdict, assessment.riskScore, 'SUCCESS', scanStartTime);
    sendThreatAlert(req.user?.email, 'email', cleanEmail, assessment, req, scanCompletedAt);

  } catch (error) {
    console.error('[EMAIL SCAN ERROR]', error.message);
    res.status(500).json({ success: false, error: 'Email scan failed.' });
  }
});

// ─────────────────────────────────────────────
// POST /api/scan-header
// Email Header Analyser
// ─────────────────────────────────────────────

router.post('/scan-header', authenticate, async (req, res) => {
  const { headers: rawHeaders, body: emailBody } = req.body;
  const scanStartTime = Date.now();

  if (!rawHeaders || rawHeaders.trim().length < 20) {
    return res.status(400).json({ success: false, error: 'Please paste the full raw email headers.' });
  }

  console.log(`\n[SCAN] ═══ Header Analysis ═══`);

  try {
    const headerIntelligence = await analyseHeaders(rawHeaders, emailBody || '');
    const assessment = await groqAI.analyseThreat(headerIntelligence.target, 'header', headerIntelligence);

    console.log(`[SCAN] Header complete — Verdict: ${assessment.verdict} SPF: ${headerIntelligence.intelligence?.authentication?.spf} DKIM: ${headerIntelligence.intelligence?.authentication?.dkim} MITRE: ${assessment.mitre?.techniques?.length || 0} techniques`);

    let enrichedHeader;
    try {
      enrichedHeader = enrichScanResult('header', headerIntelligence.target, assessment, headerIntelligence.intelligence);
    } catch (enrichErr) {
      console.error('[HEADER ENRICH ERROR]', enrichErr.message);
      enrichedHeader = { timestamp: new Date().toISOString(), target: headerIntelligence.target, scanType: 'header', assessment, intelligence: headerIntelligence.intelligence, enrichment: null };
    }

    res.status(200).json({ success: true, ...enrichedHeader });

    const { scanCompletedAt } = await logScan(req, 'header', headerIntelligence.target, assessment.verdict, assessment.riskScore, 'SUCCESS', scanStartTime);
    sendThreatAlert(req.user?.email, 'header', headerIntelligence.target, assessment, req, scanCompletedAt);

  } catch (error) {
    console.error('[HEADER SCAN ERROR]', error.message);
    res.status(500).json({ success: false, error: 'Header analysis failed.' });
  }
});

// ─────────────────────────────────────────────
// POST /api/scan-hash
// File Hash Scanner
// ─────────────────────────────────────────────

router.post('/scan-hash', authenticate, async (req, res) => {
  const { hash } = req.body;
  const scanStartTime = Date.now();

  if (!hash || typeof hash !== 'string') {
    return res.status(400).json({ success: false, error: 'A hash string is required.' });
  }

  console.log(`\n[SCAN] ═══ Hash: ${hash.trim().slice(0, 16)}... ═══`);

  try {
    const hashIntelligence = await scanHash(hash.trim());
    const vt                = hashIntelligence.intelligence?.virusTotal;
    const malwareFamily     = getMalwareFamily(vt?.threatLabels, vt?.threatCategory);
    if (malwareFamily) hashIntelligence.intelligence.malwareFamily = malwareFamily;

    const assessment = await groqAI.analyseThreat(hashIntelligence.hash, 'hash', hashIntelligence);

    console.log(`[SCAN] Hash complete — Verdict: ${assessment.verdict} Detections: ${vt?.malicious || 0}/${vt?.totalEngines || 0} Family: ${malwareFamily?.name || 'Unknown'} MITRE: ${assessment.mitre?.techniques?.length || 0} techniques`);

    let enrichedHash;
    try {
      enrichedHash = enrichScanResult('hash', hashIntelligence.hash, assessment, hashIntelligence.intelligence);
    } catch (enrichErr) {
      console.error('[HASH ENRICH ERROR]', enrichErr.message);
      enrichedHash = { timestamp: new Date().toISOString(), target: hashIntelligence.hash, scanType: 'hash', assessment, intelligence: hashIntelligence.intelligence, enrichment: null };
    }

    res.status(200).json({ success: true, ...enrichedHash });

    const { scanCompletedAt } = await logScan(req, 'hash', hashIntelligence.hash, assessment.verdict, assessment.riskScore, 'SUCCESS', scanStartTime);
    sendThreatAlert(req.user?.email, 'hash', hashIntelligence.hash, assessment, req, scanCompletedAt);

  } catch (error) {
    console.error('[HASH SCAN ERROR]', error.message);
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;

// ─────────────────────────────────────────────
// GET /api/test-enrichment
// Diagnostic route — confirms enrichScanResult works
// Remove before final submission
// ─────────────────────────────────────────────

router.get('/test-enrichment', async (req, res) => {
  try {
    const mockAssessment = {
      verdict: 'SUSPICIOUS', riskScore: 65, confidenceLevel: 'MEDIUM',
      recommendedAction: 'MONITOR', summary: 'Test',
      keyIndicators: ['Phishing detected'],
      mitre: { techniques: [{ id: 'T1566.002', name: 'Spearphishing Link', tactic: 'Initial Access', confidence: 'HIGH', url: 'https://attack.mitre.org/techniques/T1566/002/', colour: { bg: 'rgba(255,0,153,0.12)', border: 'rgba(255,0,153,0.4)', text: '#FF0099' } }], tacticsSummary: ['Initial Access'] }
    };
    const mockIntel = {
      virusTotal: { malicious: 13, totalEngines: 91, suspicious: 0, reputation: 0 },
      safeBrowsing: { flagged: false, threats: [] },
      certificate: { error: true },
      whois: { registrar: 'OVH', domainAgeDays: 385 },
      typosquatting: [{ brand: 'PayPal', canonical: 'paypal.com', type: 'brand_in_domain', detail: 'paypal embedded in domain', confidence: 'HIGH' }],
      urlBehaviour: { flags: [], urlStats: { tld: 'com', subdomains: 0 } }
    };
    const result = enrichScanResult('domain', 'paypal-security-check.com', mockAssessment, mockIntel);
    res.json({ success: true, hasEnrichment: !!result.enrichment, enrichmentKeys: Object.keys(result.enrichment || {}), riskItemCount: result.enrichment?.riskBreakdown?.items?.length });
  } catch (err) {
    res.json({ success: false, error: err.message, stack: err.stack });
  }
});