// ─────────────────────────────────────────────
// headerAnalyser.js — Email Header & Body Analysis
//
// What it does:
//   1. Parses raw email headers into key/value pairs
//   2. Extracts SPF, DKIM, DMARC from Authentication-Results
//   3. Extracts sending IP from Received: headers
//   4. Checks sending IP against AbuseIPDB
//   5. Detects spoofing (From vs Reply-To mismatch, etc.)
//   6. Builds email routing path from Received: chain
//   7. Scans email body for suspicious/phishing links
//   8. Calculates overall risk score
// ─────────────────────────────────────────────

const axios = require('axios');

// ─────────────────────────────────────────────
// HEADER PARSER
// Turns raw header text into a key/value map
// Handles multi-line (folded) headers correctly
// ─────────────────────────────────────────────

function parseHeaders(rawHeaders) {
  const headers = {};
  const lines   = rawHeaders.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

  // Unfold headers (continuation lines start with whitespace)
  const unfolded = lines.replace(/\n[ \t]+/g, ' ');
  const headerLines = unfolded.split('\n');

  for (const line of headerLines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const key   = line.slice(0, colonIdx).trim().toLowerCase();
    const value = line.slice(colonIdx + 1).trim();
    if (!key) continue;

    // Support multiple headers with the same name (e.g. Received)
    if (headers[key]) {
      if (!Array.isArray(headers[key])) headers[key] = [headers[key]];
      headers[key].push(value);
    } else {
      headers[key] = value;
    }
  }

  return headers;
}

// ─────────────────────────────────────────────
// AUTHENTICATION RESULTS PARSER
// Extracts SPF / DKIM / DMARC from the
// Authentication-Results header value
// ─────────────────────────────────────────────

function parseAuthResults(authHeader) {
  if (!authHeader) return { spf: 'unknown', dkim: 'unknown', dmarc: 'unknown' };

  const text   = Array.isArray(authHeader) ? authHeader.join(' ') : authHeader;
  const lower  = text.toLowerCase();

  const extract = (protocol) => {
    const regex = new RegExp(`${protocol}=([a-z]+)`, 'i');
    const match = lower.match(regex);
    return match ? match[1] : 'unknown';
  };

  return {
    spf : extract('spf'),
    dkim: extract('dkim'),
    dmarc: extract('dmarc')
  };
}

// ─────────────────────────────────────────────
// SENDING IP EXTRACTOR
// Finds the ORIGINATING IP from Received: headers
// The last Received: header is closest to sender
// We skip internal mail server IPs
// ─────────────────────────────────────────────

function extractSendingIP(headers) {
  const received = headers['received'];
  if (!received) return null;

  const receivedList = Array.isArray(received) ? received : [received];
  const ipRegex      = /\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/g;

  // Internal/private IP ranges to skip
  const isPrivate = (ip) => {
    const parts = ip.split('.').map(Number);
    return (
      parts[0] === 10 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      parts[0] === 127 ||
      ip === '::1'
    );
  };

  // Work through received headers from last (originator) to first
  for (let i = receivedList.length - 1; i >= 0; i--) {
    const line = receivedList[i];
    let match;
    while ((match = ipRegex.exec(line)) !== null) {
      const ip = match[1];
      if (!isPrivate(ip)) return ip;
    }
    ipRegex.lastIndex = 0;
  }

  return null;
}

// ─────────────────────────────────────────────
// ROUTING PATH BUILDER
// Produces a human-readable hop list from
// all Received: headers
// ─────────────────────────────────────────────

function buildRoutingPath(headers) {
  const received = headers['received'];
  if (!received) return [];

  const list = Array.isArray(received) ? received : [received];

  return list.reverse().map(line => {
    // Clean up the line for readability
    return line.replace(/\s+/g, ' ').trim().slice(0, 120);
  });
}

// ─────────────────────────────────────────────
// SPOOFING DETECTOR
// Checks for common email spoofing indicators
// ─────────────────────────────────────────────

function detectSpoofing(headers, authResults) {
  const indicators = [];

  const from     = headers['from']      || '';
  const replyTo  = headers['reply-to']  || '';
  const returnPath = headers['return-path'] || '';
  const sender   = headers['sender']    || '';

  // Extract domain from email address
  const domainOf = (str) => {
    const match = str.match(/@([a-zA-Z0-9.-]+)/);
    return match ? match[1].toLowerCase() : null;
  };

  const fromDomain     = domainOf(from);
  const replyDomain    = domainOf(replyTo);
  const returnDomain   = domainOf(returnPath);
  const senderDomain   = domainOf(sender);

  // From vs Reply-To domain mismatch — common phishing tactic
  if (fromDomain && replyDomain && fromDomain !== replyDomain) {
    indicators.push(`From domain (${fromDomain}) differs from Reply-To domain (${replyDomain}) — common phishing tactic`);
  }

  // From vs Return-Path mismatch
  if (fromDomain && returnDomain && fromDomain !== returnDomain) {
    indicators.push(`From domain (${fromDomain}) differs from Return-Path domain (${returnDomain}) — possible spoofing`);
  }

  // Sender header mismatch
  if (fromDomain && senderDomain && fromDomain !== senderDomain) {
    indicators.push(`From domain (${fromDomain}) differs from Sender header domain (${senderDomain})`);
  }

  // Authentication failures
  if (authResults.spf === 'fail' || authResults.spf === 'softfail') {
    indicators.push(`SPF ${authResults.spf.toUpperCase()} — sending server not authorised to send for this domain`);
  }
  if (authResults.dkim === 'fail') {
    indicators.push('DKIM FAIL — email signature invalid, message may have been tampered with');
  }
  if (authResults.dmarc === 'fail') {
    indicators.push('DMARC FAIL — domain policy violated, high likelihood of spoofing or phishing');
  }

  // All three failing simultaneously is very high risk
  if (authResults.spf !== 'pass' && authResults.dkim !== 'pass' && authResults.dmarc !== 'pass') {
    if (authResults.spf !== 'unknown' || authResults.dkim !== 'unknown') {
      indicators.push('All authentication checks failed — strong spoofing indicator');
    }
  }

  return {
    detected  : indicators.length > 0,
    indicators: indicators
  };
}

// ─────────────────────────────────────────────
// KEY EMAIL DETAILS EXTRACTOR
// Returns the most useful fields for display
// ─────────────────────────────────────────────

function extractEmailDetails(headers) {
  const fields = [
    { label: 'From',        key: 'from'          },
    { label: 'To',          key: 'to'            },
    { label: 'Subject',     key: 'subject'       },
    { label: 'Date',        key: 'date'          },
    { label: 'Reply-To',    key: 'reply-to'      },
    { label: 'Return-Path', key: 'return-path'   },
    { label: 'Message-ID',  key: 'message-id'    },
    { label: 'X-Mailer',    key: 'x-mailer'      },
    { label: 'MIME-Version',key: 'mime-version'  },
  ];

  return fields
    .filter(f => headers[f.key])
    .map(f => ({
      label: f.label,
      value: String(headers[f.key]).slice(0, 200)
    }));
}

// ─────────────────────────────────────────────
// PHISHING LINK SCANNER
// Extracts URLs from email body and flags
// suspicious ones based on known patterns
// ─────────────────────────────────────────────

function scanBodyForPhishing(body) {
  if (!body || body.trim().length === 0) return [];

  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  const urls     = [...new Set(body.match(urlRegex) || [])];

  // Suspicious patterns
  const RISKY_TLDS = ['.xyz','.top','.click','.link','.site','.online','.club','.info','.biz','.tk','.ml','.ga','.cf','.gq'];
  const URL_SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','short.io','rebrand.ly','cutt.ly'];
  const BRAND_IMPERSONATORS = ['paypa1','paypai','amaz0n','g00gle','micros0ft','app1e','netf1ix','linkedln','faceb00k'];

  const flagged = [];

  for (const url of urls.slice(0, 20)) {
    const reasons = [];
    let risk      = 'LOW';

    try {
      const parsed = new URL(url);
      const domain = parsed.hostname.toLowerCase();

      // URL shortener
      if (URL_SHORTENERS.some(s => domain === s || domain.endsWith('.' + s))) {
        reasons.push('URL shortener used — destination hidden from recipient');
        risk = 'HIGH';
      }

      // Risky TLD
      if (RISKY_TLDS.some(tld => domain.endsWith(tld))) {
        reasons.push(`Suspicious top-level domain: ${domain.split('.').pop()}`);
        risk = 'HIGH';
      }

      // Brand impersonation in domain
      if (BRAND_IMPERSONATORS.some(b => domain.includes(b))) {
        reasons.push('Domain appears to impersonate a known brand using character substitution');
        risk = 'CRITICAL';
      }

      // IP address instead of domain
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain)) {
        reasons.push('URL uses raw IP address instead of domain name — common in phishing');
        risk = 'HIGH';
      }

      // Suspicious keywords in path
      const path = parsed.pathname.toLowerCase();
      const SUSPECT_PATHS = ['login','signin','verify','account','secure','update','confirm','password','credential'];
      if (SUSPECT_PATHS.some(k => path.includes(k))) {
        reasons.push(`Path contains credential-harvesting keyword: "${SUSPECT_PATHS.find(k => path.includes(k))}"`);
        if (risk === 'LOW') risk = 'MEDIUM';
      }

      // Many subdomains (often used to disguise phishing URLs)
      const subdomains = domain.split('.').length - 2;
      if (subdomains > 2) {
        reasons.push(`Unusually deep subdomain structure (${subdomains} subdomains) — often used to obscure destination`);
        if (risk === 'LOW') risk = 'MEDIUM';
      }

      if (reasons.length > 0) {
        flagged.push({ url: url.slice(0, 100), risk, reason: reasons.join('. ') });
      }
    } catch {
      // Invalid URL — skip
    }
  }

  return flagged.sort((a, b) => {
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
    return order[a.risk] - order[b.risk];
  });
}

// ─────────────────────────────────────────────
// AbuseIPDB CHECK
// ─────────────────────────────────────────────

async function checkSendingIP(ip) {
  try {
    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
      params : { ipAddress: ip, maxAgeInDays: 90 },
      timeout: 7000
    });

    const d = response.data.data;
    return {
      ip,
      abuseScore  : d.abuseConfidenceScore,
      totalReports: d.totalReports,
      countryCode : d.countryCode,
      isp         : d.isp,
      usageType   : d.usageType,
      isTor       : d.isTor,
      domain      : d.domain
    };
  } catch (error) {
    console.error('[HEADER] AbuseIPDB error:', error.message);
    return { ip, error: true, message: error.message };
  }
}

// ─────────────────────────────────────────────
// RISK SCORE CALCULATOR
// ─────────────────────────────────────────────

function calculateRisk(authResults, spoofing, ipRep, phishingLinks) {
  let score = 0;

  // Authentication failures — most important signals
  if (authResults.spf   === 'fail')     score += 25;
  else if (authResults.spf === 'softfail') score += 12;
  if (authResults.dkim  === 'fail')     score += 25;
  if (authResults.dmarc === 'fail')     score += 25;

  // Spoofing indicators
  if (spoofing.detected) {
    score += Math.min(spoofing.indicators.length * 10, 25);
  }

  // IP reputation
  if (ipRep && !ipRep.error) {
    if (ipRep.abuseScore > 75)  score += 30;
    else if (ipRep.abuseScore > 50) score += 20;
    else if (ipRep.abuseScore > 25) score += 10;
    if (ipRep.isTor)            score += 15;
  }

  // Phishing links
  const critical = phishingLinks.filter(l => l.risk === 'CRITICAL').length;
  const high     = phishingLinks.filter(l => l.risk === 'HIGH').length;
  const medium   = phishingLinks.filter(l => l.risk === 'MEDIUM').length;
  score += critical * 20;
  score += high     * 12;
  score += medium   * 6;

  // Credit for passing all three auth checks
  if (authResults.spf === 'pass' && authResults.dkim === 'pass' && authResults.dmarc === 'pass') {
    score = Math.max(score - 10, 0);
  }

  return Math.min(score, 100);
}

// ─────────────────────────────────────────────
// MAIN EXPORT — analyseHeaders()
// ─────────────────────────────────────────────

async function analyseHeaders(rawHeaders, emailBody = '') {
  console.log('[HEADER] Starting analysis...');

  // [1] Parse headers
  const headers = parseHeaders(rawHeaders);

  // [2] Extract authentication results
  const authResults = parseAuthResults(headers['authentication-results']);

  // [3] Extract sending IP
  const sendingIP = extractSendingIP(headers);

  // [4] Check IP in parallel with other analysis
  const [ipResult] = await Promise.allSettled([
    sendingIP ? checkSendingIP(sendingIP) : Promise.resolve(null)
  ]);

  const ipReputation = ipResult.status === 'fulfilled' ? ipResult.value : null;

  // [5] Build routing path
  const routingPath = buildRoutingPath(headers);

  // [6] Detect spoofing
  const spoofing = detectSpoofing(headers, authResults);

  // [7] Extract display fields
  const emailDetails = extractEmailDetails(headers);

  // [8] Scan body for phishing links
  const phishingLinks = scanBodyForPhishing(emailBody);

  // [9] Calculate risk score
  const riskScore = calculateRisk(authResults, spoofing, ipReputation, phishingLinks);

  // [10] Generate a target string for display (from the From header)
  const target = headers['from']
    ? `From: ${String(headers['from']).slice(0, 60)}`
    : 'Email Header Analysis';

  console.log(`[HEADER] Complete — Risk: ${riskScore} — SPF: ${authResults.spf} — DKIM: ${authResults.dkim} — DMARC: ${authResults.dmarc} — Sending IP: ${sendingIP || 'not found'}`);

  return {
    target,
    riskScore,
    intelligence: {
      authentication   : authResults,
      sendingIP,
      ipReputation,
      spoofingDetected : spoofing.detected,
      spoofingIndicators: spoofing.indicators,
      routingPath,
      emailDetails,
      phishingLinks,
      parsedHeaders    : {
        from        : headers['from']        || null,
        to          : headers['to']          || null,
        subject     : headers['subject']     || null,
        date        : headers['date']        || null,
        replyTo     : headers['reply-to']    || null,
        returnPath  : headers['return-path'] || null,
        messageId   : headers['message-id'] || null,
      }
    }
  };
}

module.exports = { analyseHeaders };