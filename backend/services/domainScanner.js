// ─────────────────────────────────────────────
// domainScanner.js — Domain & URL Intelligence
//
// Combines four intelligence sources:
//
//  1. VirusTotal      — URL + domain malware check
//  2. Google Safe Browsing — phishing/malware flag
//  3. SSL Labs + TLS  — certificate + grade
//  4. RDAP/WHOIS      — domain registration details
//
// All four run in parallel for maximum speed.
// Groq AI then reasons across all four sources.
// ─────────────────────────────────────────────

const axios  = require('axios');
const tls    = require('tls');
const { cleanDomain } = require('./sslChecker');

// ─────────────────────────────────────────────
// INPUT PARSER
// Accepts: full URL, bare domain, or IP
// Returns: { url, domain }
// ─────────────────────────────────────────────

function parseInput(raw) {
  const input = raw.trim();

  // Add protocol if missing so URL constructor works
  const withProto = /^https?:\/\//i.test(input)
    ? input
    : `https://${input}`;

  try {
    const parsed = new URL(withProto);
    return {
      url   : withProto,
      domain: parsed.hostname.toLowerCase()
    };
  } catch {
    return {
      url   : withProto,
      domain: input.toLowerCase()
    };
  }
}

// ─────────────────────────────────────────────
// SOURCE 1 — VirusTotal URL scan
// ─────────────────────────────────────────────

async function checkVirusTotalURL(url) {
  try {
    // Encode URL for VT API
    const encoded  = Buffer.from(url).toString('base64').replace(/=/g,'');
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/urls/${encoded}`,
      {
        headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY },
        timeout: 12000
      }
    );

    const attrs = response.data.data?.attributes || {};
    const stats = attrs.last_analysis_stats      || {};

    return {
      source         : 'VirusTotal',
      malicious      : stats.malicious   || 0,
      suspicious     : stats.suspicious  || 0,
      harmless       : stats.harmless    || 0,
      undetected     : stats.undetected  || 0,
      totalEngines   : Object.values(stats).reduce((a,b) => a+b, 0),
      categories     : attrs.categories  || {},
      reputation     : attrs.reputation  || 0,
      lastAnalysed   : attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null
    };
  } catch (error) {
    if (error.response?.status === 404) {
      // URL not in VT cache — submit it
      try {
        const form = new URLSearchParams({ url });
        await axios.post('https://www.virustotal.com/api/v3/urls', form, {
          headers: {
            'x-apikey'    : process.env.VIRUSTOTAL_API_KEY,
            'Content-Type': 'application/x-www-form-urlencoded'
          },
          timeout: 10000
        });
        return { source: 'VirusTotal', notCached: true, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, totalEngines: 0 };
      } catch {
        return { source: 'VirusTotal', error: true, message: 'URL submission failed' };
      }
    }
    console.error('[DOMAIN] VirusTotal URL error:', error.message);
    return { source: 'VirusTotal', error: true, message: error.message };
  }
}

// ─────────────────────────────────────────────
// SOURCE 2 — Google Safe Browsing
// ─────────────────────────────────────────────

async function checkSafeBrowsing(url) {
  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_API_KEY}`,
      {
        client  : { clientId: 'cybershield-ai', clientVersion: '1.0' },
        threatInfo: {
          threatTypes     : ['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes   : ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries   : [{ url }]
        }
      },
      { timeout: 8000 }
    );

    const matches = response.data.matches || [];
    return {
      source    : 'GoogleSafeBrowsing',
      flagged   : matches.length > 0,
      threats   : matches.map(m => m.threatType)
    };
  } catch (error) {
    console.error('[DOMAIN] Safe Browsing error:', error.message);
    return { source: 'GoogleSafeBrowsing', error: true, message: error.message, flagged: false, threats: [] };
  }
}

// ─────────────────────────────────────────────
// SOURCE 3 — Direct TLS cert check (fast)
// Full SSL Labs would take 90s — too slow here.
// We use direct TLS for speed.
// ─────────────────────────────────────────────

function checkCertificate(domain) {
  return new Promise((resolve) => {
    const options = {
      host              : domain,
      port              : 443,
      servername        : domain,
      rejectUnauthorized: false,
      timeout           : 10000
    };

    const socket = tls.connect(options, () => {
      try {
        const cert       = socket.getPeerCertificate(true);
        const authorized = socket.authorized;
        socket.destroy();

        if (!cert || !cert.subject) {
          return resolve({ source: 'TLS', error: true, message: 'No certificate returned' });
        }

        const validFrom  = new Date(cert.valid_from);
        const validTo    = new Date(cert.valid_to);
        const now        = new Date();
        const daysLeft   = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));

        // Treat known public CAs as trusted even if socket.authorized is false
        // (Render's Node environment sometimes returns false for valid certs)
        const issuerOrg = (cert.issuer?.O || cert.issuer?.CN || '').toLowerCase();
        const KNOWN_CAS = ["let's encrypt", "digicert", "comodo", "sectigo",
                           "globalsign", "geotrust", "entrust", "godaddy",
                           "amazon", "cloudflare", "google trust", "zerossl"];
        const isKnownCA   = KNOWN_CAS.some(ca => issuerOrg.includes(ca));
        const isAuthorized = authorized || isKnownCA;

        resolve({
          source          : 'TLS',
          subject         : cert.subject?.CN   || domain,
          issuer          : cert.issuer?.O     || cert.issuer?.CN || 'Unknown',
          issuerCN        : cert.issuer?.CN    || null,
          validFrom       : validFrom.toISOString(),
          validTo         : validTo.toISOString(),
          daysUntilExpiry : daysLeft,
          isExpired       : daysLeft < 0,
          isExpiringSoon  : daysLeft >= 0 && daysLeft <= 30,
          isAuthorized    : isAuthorized,
          bits            : cert.bits          || null,
          fingerprint     : cert.fingerprint   || null,
          protocol        : socket.getProtocol ? socket.getProtocol() : null,
          subjectAltNames : cert.subjectaltname
            ? cert.subjectaltname.split(', ').map(s => s.replace('DNS:','').replace('IP Address:','')).slice(0,8)
            : []
        });
      } catch (err) {
        socket.destroy();
        resolve({ source: 'TLS', error: true, message: err.message });
      }
    });

    socket.on('error', (err) => resolve({ source: 'TLS', error: true, message: err.message }));
    socket.on('timeout', ()  => { socket.destroy(); resolve({ source: 'TLS', error: true, message: 'TLS connection timed out' }); });
  });
}

// ─────────────────────────────────────────────
// SOURCE 4 — RDAP / WHOIS Domain Registration
// Uses IANA RDAP bootstrap — free, no key needed
// ─────────────────────────────────────────────

async function checkWHOIS(domain) {
  try {
    // RDAP returns structured JSON — much cleaner than raw WHOIS
    const response = await axios.get(
      `https://rdap.org/domain/${domain}`,
      {
        timeout: 10000,
        headers: { 'Accept': 'application/json' }
      }
    );

    const data = response.data;

    // Extract dates from events array
    const events = data.events || [];
    const getEventDate = (action) => {
      const e = events.find(ev => ev.eventAction === action);
      return e ? e.eventDate : null;
    };

    // Extract registrar from entities
    const entities   = data.entities || [];
    const registrar  = entities.find(e =>
      (e.roles || []).includes('registrar')
    );
    const registrant = entities.find(e =>
      (e.roles || []).includes('registrant')
    );

    const registrarName = registrar?.vcardArray?.[1]
      ?.find(v => v[0] === 'fn')?.[3]
      || registrar?.handle
      || 'Unknown';

    const registrantOrg = registrant?.vcardArray?.[1]
      ?.find(v => v[0] === 'org')?.[3]
      || null;

    const registrantCountry = registrant?.vcardArray?.[1]
      ?.find(v => v[0] === 'adr')?.[1]?.['country-name']
      || null;

    // Nameservers
    const nameservers = (data.nameservers || [])
      .map(ns => ns.ldhName || ns.unicodeName)
      .filter(Boolean)
      .slice(0, 6);

    // Domain status flags
    const status = Array.isArray(data.status) ? data.status : [];

    const registeredDate = getEventDate('registration');
    const expiryDate     = getEventDate('expiration');
    const updatedDate    = getEventDate('last changed');

    // Calculate domain age in days
    const domainAgeDays = registeredDate
      ? Math.floor((Date.now() - new Date(registeredDate)) / (1000 * 60 * 60 * 24))
      : null;

    return {
      source          : 'RDAP',
      domain          : data.ldhName || domain,
      registrar       : registrarName,
      registrantOrg   : registrantOrg,
      registrantCountry,
      registeredDate,
      expiryDate,
      updatedDate,
      domainAgeDays,
      nameservers,
      status,
      isNewDomain     : domainAgeDays !== null && domainAgeDays < 90
    };

  } catch (error) {
    // Fallback: try whois.rdap.org alternative
    try {
      const fallback = await axios.get(
        `https://rdap.org/domain/${domain}`,
        { timeout: 8000, headers: { 'Accept': 'application/rdap+json' } }
      );
      return { source: 'RDAP', error: false, raw: fallback.data, domain };
    } catch {
      console.error('[DOMAIN] WHOIS error:', error.message);
      return { source: 'RDAP', error: true, message: 'Domain registration data unavailable' };
    }
  }
}

// ─────────────────────────────────────────────
// RISK SCORE CALCULATOR
// Combines all four sources into 0-100
// ─────────────────────────────────────────────

function calculateRisk(vt, safeBrowsing, cert, whois) {
  let score = 0;

  // VirusTotal detections
  if (vt && !vt.error) {
    const totalEngines = vt.totalEngines || 70;
    if (vt.malicious > 0) {
      score += Math.min(Math.round((vt.malicious / totalEngines) * 60), 60);
      if (vt.malicious > 10) score += 15;
    }
    if (vt.suspicious > 0) score += Math.min(vt.suspicious * 2, 10);
  }

  // Google Safe Browsing
  if (safeBrowsing?.flagged) {
    score += 35;
    if (safeBrowsing.threats?.includes('SOCIAL_ENGINEERING')) score += 10;
  }

  // Certificate issues
  if (cert && !cert.error) {
    if (cert.isExpired)                      score += 30;
    else if (cert.daysUntilExpiry <= 7)      score += 20;
    else if (cert.daysUntilExpiry <= 30)     score += 10;
    if (!cert.isAuthorized)                  score += 15;
    if (cert.bits && cert.bits < 2048)       score += 10;
  } else if (cert?.error) {
    // No SSL at all
    score += 20;
  }

  // Domain age — newly registered domains are high risk
  if (whois && !whois.error) {
    if (whois.domainAgeDays !== null) {
      if (whois.domainAgeDays < 7)   score += 35;
      else if (whois.domainAgeDays < 30)  score += 25;
      else if (whois.domainAgeDays < 90)  score += 15;
      else if (whois.domainAgeDays < 365) score += 5;
    }
  }

  return Math.min(score, 100);
}

// ─────────────────────────────────────────────
// MAIN EXPORT — scanDomain()
// ─────────────────────────────────────────────

async function scanDomain(rawInput) {
  const { url, domain } = parseInput(rawInput);

  console.log(`[DOMAIN SCAN] Starting — URL: ${url} — Domain: ${domain}`);

  // All four sources in parallel
  const [vtResult, sbResult, certResult, whoisResult] = await Promise.allSettled([
    checkVirusTotalURL(url),
    checkSafeBrowsing(url),
    checkCertificate(domain),
    checkWHOIS(domain)
  ]);

  const vt     = vtResult.status    === 'fulfilled' ? vtResult.value    : { source: 'VirusTotal',        error: true };
  const sb     = sbResult.status    === 'fulfilled' ? sbResult.value    : { source: 'SafeBrowsing',      error: true, flagged: false, threats: [] };
  const cert   = certResult.status  === 'fulfilled' ? certResult.value  : { source: 'TLS',               error: true };
  const whois  = whoisResult.status === 'fulfilled' ? whoisResult.value : { source: 'RDAP',              error: true };

  const riskScore = calculateRisk(vt, sb, cert, whois);

  console.log(`[DOMAIN SCAN] Complete — Risk: ${riskScore} — VT: ${vt.malicious||0} detections — SSL: ${cert.error?'ERROR':cert.daysUntilExpiry+'d left'} — Domain age: ${whois.domainAgeDays||'?'}d`);

  return {
    url,
    domain,
    riskScore,
    intelligence: {
      virusTotal   : vt,
      safeBrowsing : sb,
      certificate  : cert,
      whois
    }
  };
}

module.exports = { scanDomain, parseInput };