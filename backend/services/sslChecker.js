// ─────────────────────────────────────────────
// sslChecker.js — SSL/TLS Certificate Analysis
//
// Sources:
//   1. SSL Labs API (free, no key needed)
//      Performs full TLS handshake analysis
//      Returns grade A-F, certificate details,
//      protocol support, vulnerability checks
//
//   2. Node.js built-in tls module
//      Direct certificate inspection for
//      expiry date and issuer (fast fallback)
//
// SSL Labs is slow (60-90s for new domains).
// We use polling: start scan → check every 10s
// ─────────────────────────────────────────────

const axios = require('axios');
const tls   = require('tls');
const https = require('https');

const SSL_LABS_BASE = 'https://api.ssllabs.com/api/v3';

// ─────────────────────────────────────────────
// HELPER — clean domain input
// Strips https://, http://, trailing slashes
// ─────────────────────────────────────────────

function cleanDomain(input) {
  return input
    .replace(/^https?:\/\//i, '')
    .replace(/\/.*$/, '')
    .trim()
    .toLowerCase();
}

// ─────────────────────────────────────────────
// SOURCE 1 — Direct TLS certificate inspection
// Uses Node's built-in tls module.
// Fast, but gives us raw cert data only —
// no grade, no vulnerability checks.
// Runs as a fallback or to supplement SSL Labs.
// ─────────────────────────────────────────────

function directCertCheck(domain) {
  return new Promise((resolve) => {
    const options = {
      host              : domain,
      port              : 443,
      servername        : domain,
      rejectUnauthorized: false, // we check validity ourselves
      timeout           : 10000
    };

    const socket = tls.connect(options, () => {
      try {
        const cert      = socket.getPeerCertificate(true);
        const authorized = socket.authorized;
        socket.destroy();

        if (!cert || !cert.subject) {
          return resolve({ error: true, message: 'No certificate returned' });
        }

        const validFrom   = new Date(cert.valid_from);
        const validTo     = new Date(cert.valid_to);
        const now         = new Date();
        const daysLeft    = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
        const isExpired   = daysLeft < 0;
        const isExpiringSoon = daysLeft >= 0 && daysLeft <= 30;

        resolve({
          error            : false,
          subject          : cert.subject?.CN || cert.subject?.O || domain,
          issuer           : cert.issuer?.O   || cert.issuer?.CN  || 'Unknown',
          issuerCN         : cert.issuer?.CN  || null,
          validFrom        : validFrom.toISOString(),
          validTo          : validTo.toISOString(),
          daysUntilExpiry  : daysLeft,
          isExpired,
          isExpiringSoon,
          isAuthorized     : authorized,
          serialNumber     : cert.serialNumber || null,
          fingerprint      : cert.fingerprint  || null,
          subjectAltNames  : cert.subjectaltname
            ? cert.subjectaltname.split(', ').map(s => s.replace('DNS:', '')).slice(0, 10)
            : [],
          bits             : cert.bits || null
        });
      } catch (err) {
        socket.destroy();
        resolve({ error: true, message: err.message });
      }
    });

    socket.on('error', (err) => {
      resolve({ error: true, message: err.message });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ error: true, message: 'Connection timed out' });
    });
  });
}

// ─────────────────────────────────────────────
// SOURCE 2 — SSL Labs API
// Starts a scan and polls until complete.
// Returns grade, protocol list, vuln checks.
// ─────────────────────────────────────────────

async function startSSLLabsScan(domain) {
  const response = await axios.get(`${SSL_LABS_BASE}/analyze`, {
    params : {
      host        : domain,
      startNew    : 'on',
      all         : 'done',
      ignoreMismatch: 'on'
    },
    timeout: 15000
  });
  return response.data;
}

async function pollSSLLabsScan(domain) {
  const response = await axios.get(`${SSL_LABS_BASE}/analyze`, {
    params : {
      host          : domain,
      all           : 'done',
      ignoreMismatch: 'on'
    },
    timeout: 15000
  });
  return response.data;
}

async function runSSLLabsScan(domain) {
  try {
    console.log(`[SSL] Starting SSL Labs scan for: ${domain}`);

    // Start the scan
    await startSSLLabsScan(domain);

    // Poll until status is READY or ERROR
    // Max wait: 120 seconds (12 polls × 10 seconds)
    const MAX_POLLS = 12;
    const POLL_MS   = 10000;

    for (let i = 0; i < MAX_POLLS; i++) {
      await new Promise(r => setTimeout(r, POLL_MS));

      const data   = await pollSSLLabsScan(domain);
      const status = data.status;

      console.log(`[SSL] Poll ${i + 1}/${MAX_POLLS} — Status: ${status}`);

      if (status === 'READY') {
        return parseSSLLabsResult(data, domain);
      }

      if (status === 'ERROR') {
        return {
          error  : true,
          message: data.statusMessage || 'SSL Labs scan failed'
        };
      }

      // DNS or connection error
      if (status === 'DNS' || status === 'IN_PROGRESS') {
        continue; // keep polling
      }
    }

    // Timed out — return what we have
    return { error: true, message: 'SSL Labs scan timed out after 120 seconds' };

  } catch (error) {
    console.error('[SSL] SSL Labs error:', error.message);
    return { error: true, message: error.message };
  }
}

// ─────────────────────────────────────────────
// SSL LABS RESULT PARSER
// Extracts the most useful fields from the
// verbose SSL Labs response
// ─────────────────────────────────────────────

function parseSSLLabsResult(data, domain) {
  const endpoint = data.endpoints?.[0];

  if (!endpoint) {
    return { error: true, message: 'No endpoint data returned' };
  }

  const details = endpoint.details || {};

  // Protocol versions supported
  const protocols = (details.protocols || []).map(p => `${p.name} ${p.version}`);

  // Vulnerability checks
  const vulns = {
    heartbleed   : details.heartbleed          || false,
    poodle       : details.poodle              || false,
    freak        : details.freak               || false,
    logjam       : details.logjam              || false,
    drown        : details.drownVulnerable     || false,
    beast        : details.vulnBeast           || false,
    ticketbleed  : details.ticketbleed === 2   || false,
    robot        : details.bleichenbacher > 0  || false,
  };

  const vulnCount = Object.values(vulns).filter(Boolean).length;

  // Certificate details from SSL Labs
  const cert = details.cert || details.certChains?.[0]?.certIds?.[0] || {};

  // Key exchange info
  const suites = (details.suites?.[0]?.list || []).map(s => s.name).slice(0, 5);

  return {
    source         : 'SSLLabs',
    error          : false,
    grade          : endpoint.grade          || 'N/A',
    gradeTrustIgnored: endpoint.gradeTrustIgnored || endpoint.grade || 'N/A',
    hasWarnings    : endpoint.hasWarnings    || false,
    statusMessage  : endpoint.statusMessage  || '',

    // Server info
    serverIP       : endpoint.ipAddress      || null,
    serverName     : data.host               || domain,

    // Protocol support
    protocols,
    supportsSSL2   : protocols.some(p => p.includes('SSL 2')),
    supportsSSL3   : protocols.some(p => p.includes('SSL 3')),
    supportsTLS10  : protocols.some(p => p.includes('TLS 1.0')),
    supportsTLS11  : protocols.some(p => p.includes('TLS 1.1')),
    supportsTLS12  : protocols.some(p => p.includes('TLS 1.2')),
    supportsTLS13  : protocols.some(p => p.includes('TLS 1.3')),

    // Cipher suites
    cipherSuites   : suites,

    // Features
    supportsHSTS   : details.hstsPolicy?.status === 'present' || false,
    hstMaxAge      : details.hstsPolicy?.maxAge || null,
    supportsHPKP   : details.hpkpPolicy?.status === 'present' || false,
    forwardSecrecy : details.forwardSecrecy > 0 || false,

    // Vulnerabilities
    vulnerabilities: vulns,
    vulnCount,

    // Test metadata
    testedOn       : new Date(data.startTime || Date.now()).toISOString()
  };
}

// ─────────────────────────────────────────────
// RISK SCORE CALCULATOR
// Combines SSL Labs grade + cert expiry +
// vulnerability count into a 0-100 risk score
// ─────────────────────────────────────────────

function calculateRisk(sslLabsResult, certResult) {
  let score = 0;

  // Grade-based score
  if (sslLabsResult && !sslLabsResult.error) {
    const gradeScores = { 'A+': 0, 'A': 5, 'A-': 8, 'B': 30, 'C': 50, 'D': 65, 'E': 75, 'F': 90, 'T': 85, 'N/A': 40 };
    score += gradeScores[sslLabsResult.grade] ?? 40;

    // Vulnerability bonuses
    score += sslLabsResult.vulnCount * 12;

    // Old protocol penalties
    if (sslLabsResult.supportsSSL2) score += 25;
    if (sslLabsResult.supportsSSL3) score += 20;
    if (sslLabsResult.supportsTLS10) score += 10;
    if (sslLabsResult.supportsTLS11) score += 5;

    // No HSTS penalty
    if (!sslLabsResult.supportsHSTS) score += 5;
  }

  // Certificate expiry
  if (certResult && !certResult.error) {
    if (certResult.isExpired)         score += 40;
    else if (certResult.daysUntilExpiry <= 7)  score += 25;
    else if (certResult.daysUntilExpiry <= 30) score += 15;
    else if (certResult.daysUntilExpiry <= 60) score += 5;

    if (!certResult.isAuthorized)     score += 20;
  }

  return Math.min(score, 100);
}

// ─────────────────────────────────────────────
// MAIN EXPORT — checkSSL()
// Runs both checks in parallel for speed
// ─────────────────────────────────────────────

async function checkSSL(rawInput) {
  const domain = cleanDomain(rawInput);

  if (!domain || domain.length < 3) {
    throw new Error('Please enter a valid domain name (e.g. example.com)');
  }

  console.log(`[SSL SCAN] Starting for: ${domain}`);

  // Run direct cert check immediately (fast)
  // SSL Labs runs in parallel (slow — up to 90s)
  const [certResult, sslLabsResult] = await Promise.allSettled([
    directCertCheck(domain),
    runSSLLabsScan(domain)
  ]);

  const cert    = certResult.status    === 'fulfilled' ? certResult.value    : { error: true, message: 'Direct check failed' };
  const ssllabs = sslLabsResult.status === 'fulfilled' ? sslLabsResult.value : { error: true, message: 'SSL Labs check failed' };

  const riskScore = calculateRisk(ssllabs, cert);

  console.log(`[SSL SCAN] Complete — Domain: ${domain} — Grade: ${ssllabs.grade||'N/A'} — Risk: ${riskScore}`);

  return {
    domain,
    riskScore,
    intelligence: {
      certificate : cert,
      sslLabs     : ssllabs
    }
  };
}

module.exports = { checkSSL, cleanDomain };