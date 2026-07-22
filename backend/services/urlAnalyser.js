// ─────────────────────────────────────────────
// urlAnalyser.js — URL Behaviour & Typosquatting
//
// Pure logic — no API needed.
// Analyses URL structure for suspicious patterns
// and detects domain impersonation attempts.
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// KNOWN BRAND LIST FOR TYPOSQUATTING DETECTION
// Canonical domain → display name
// ─────────────────────────────────────────────

const KNOWN_BRANDS = {
  'paypal.com'      : 'PayPal',
  'amazon.com'      : 'Amazon',
  'amazon.co.uk'    : 'Amazon UK',
  'google.com'      : 'Google',
  'microsoft.com'   : 'Microsoft',
  'apple.com'       : 'Apple',
  'facebook.com'    : 'Facebook',
  'instagram.com'   : 'Instagram',
  'twitter.com'     : 'Twitter/X',
  'netflix.com'     : 'Netflix',
  'spotify.com'     : 'Spotify',
  'linkedin.com'    : 'LinkedIn',
  'dropbox.com'     : 'Dropbox',
  'ebay.com'        : 'eBay',
  'ebay.co.uk'      : 'eBay UK',
  'yahoo.com'       : 'Yahoo',
  'outlook.com'     : 'Outlook',
  'office.com'      : 'Microsoft Office',
  'live.com'        : 'Microsoft Live',
  'hotmail.com'     : 'Hotmail',
  'gmail.com'       : 'Gmail',
  'icloud.com'      : 'iCloud',
  'chase.com'       : 'Chase Bank',
  'wellsfargo.com'  : 'Wells Fargo',
  'bankofamerica.com': 'Bank of America',
  'barclays.co.uk'  : 'Barclays',
  'lloydsbank.com'  : 'Lloyds Bank',
  'natwest.com'     : 'NatWest',
  'hsbc.co.uk'      : 'HSBC',
  'santander.co.uk' : 'Santander',
  'dhl.com'         : 'DHL',
  'fedex.com'       : 'FedEx',
  'ups.com'         : 'UPS',
  'royalmail.com'   : 'Royal Mail',
  'hmrc.gov.uk'     : 'HMRC',
  'gov.uk'          : 'UK Government',
  'nhs.uk'          : 'NHS',
  'coinbase.com'    : 'Coinbase',
  'binance.com'     : 'Binance',
  'steam.com'       : 'Steam',
  'steampowered.com': 'Steam',
  'discord.com'     : 'Discord',
  'adobe.com'       : 'Adobe',
  'github.com'      : 'GitHub',
  'stripe.com'      : 'Stripe',
  'microsoft.com'   : 'Microsoft Corp',
  'office365.com'   : 'Microsoft 365',
  'outlook.com'     : 'Microsoft Outlook',
  'amazon.co.uk'    : 'Amazon UK',
  'apple.co.uk'     : 'Apple UK',
  'netflix.co.uk'   : 'Netflix UK',
  // Major legitimate domains that should never be flagged
  'bbc.co.uk'       : 'BBC',
  'bbc.com'         : 'BBC',
  'itv.com'         : 'ITV',
  'sky.com'         : 'Sky',
  'bt.com'          : 'BT',
  'virginmedia.com' : 'Virgin Media',
  'vodafone.co.uk'  : 'Vodafone',
  'o2.co.uk'        : 'O2',
  'tesco.com'       : 'Tesco',
  'bbc.co.uk'       : 'BBC',
  'reuters.com'     : 'Reuters',
  'theguardian.com' : 'The Guardian',
  'dailymail.co.uk' : 'Daily Mail',
  'telegraph.co.uk' : 'The Telegraph',
  'boe.co.uk'       : 'Bank of England',
  'wikipedia.org'   : 'Wikipedia',
  'cloudflare.com'  : 'Cloudflare',
  'shopify.com'     : 'Shopify',
  'salesforce.com'  : 'Salesforce',
  'zoom.us'         : 'Zoom',
  'slack.com'       : 'Slack',
};

// Risky TLDs associated with abuse
const RISKY_TLDS = new Set([
  'xyz','top','click','link','site','online','club','tk','ml','ga','cf','gq',
  'pw','cc','ws','biz','info','name','mobi','tv','me','io','co','app','vip',
  'rest','buzz','fun','store','shop','icu','cyou','loan','work','life','ltd'
]);

// URL shortener domains
const SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','short.io','rebrand.ly',
  'cutt.ly','is.gd','buff.ly','ift.tt','dlvr.it','po.st','bl.ink','shorte.st'
]);

// Suspicious keywords in paths
const SUSPECT_KEYWORDS = [
  'login','signin','sign-in','verify','verification','confirm','secure',
  'account','update','password','credential','authenticate','banking',
  'wallet','recovery','unlock','suspended','alert','limited','unusual'
];

// ─────────────────────────────────────────────
// LEVENSHTEIN DISTANCE
// Measures how many single-character edits
// separate two strings. Used for typosquatting.
// ─────────────────────────────────────────────

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i-1] === b[j-1]
        ? dp[i-1][j-1]
        : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
    }
  }
  return dp[m][n];
}

// ─────────────────────────────────────────────
// HOMOGLYPH NORMALISER
// Converts visually similar characters to
// their ASCII equivalents before comparison
// e.g. paypa1 → paypal, rn → m lookalikes
// ─────────────────────────────────────────────

function normaliseHomoglyphs(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/6/g, 'g')
    .replace(/8/g, 'b')
    .replace(/\$/g, 's')
    .replace(/vv/g, 'w')
    .replace(/rn/g, 'm')
    .replace(/ln/g, 'in')
    .replace(/\u0430/g, 'a') // Cyrillic а
    .replace(/\u0435/g, 'e') // Cyrillic е
    .replace(/\u043e/g, 'o') // Cyrillic о
    .replace(/\u0440/g, 'p') // Cyrillic р
    .replace(/\u0441/g, 'c') // Cyrillic с
    .replace(/\u0445/g, 'x'); // Cyrillic х
}

// ─────────────────────────────────────────────
// TYPOSQUATTING DETECTOR
// Checks if a domain is impersonating a brand
// ─────────────────────────────────────────────

function detectTyposquatting(domain) {
  const results = [];
  const cleanDomain = domain.toLowerCase().replace(/^www\./, '');

  // Skip if the domain IS a known brand
  if (KNOWN_BRANDS[cleanDomain]) return results;

  // Extract domain without TLD for comparison
  const domainParts  = cleanDomain.split('.');
  const domainNoTLD  = domainParts.slice(0, -1).join('.');

  // Also extract just the first segment before any hyphen
  // e.g. "paypa1-secure" → "paypa1" for better matching
  const domainFirstSeg = domainNoTLD.split('-')[0];

  const normalisedFull = normaliseHomoglyphs(domainNoTLD);
  const normalisedSeg  = normaliseHomoglyphs(domainFirstSeg);

  for (const [brandDomain, brandName] of Object.entries(KNOWN_BRANDS)) {
    const brandParts  = brandDomain.split('.');
    const brandNoTLD  = brandParts.slice(0, -1).join('.');
    const normBrand   = normaliseHomoglyphs(brandNoTLD);

    // Check 1: Exact homoglyph match on full domain (without TLD)
    if (normalisedFull === normBrand && cleanDomain !== brandDomain) {
      results.push({
        type      : 'homoglyph',
        brand     : brandName,
        canonical : brandDomain,
        detail    : `Character substitution detected: "${cleanDomain}" mimics "${brandDomain}"`,
        confidence: 'HIGH'
      });
      continue;
    }

    // Check 2: Homoglyph match on first segment only
    // Catches: paypa1-secure.ml → paypa1 → paypal
    if (normalisedSeg === normBrand && domainFirstSeg !== brandNoTLD) {
      const tld = domainParts[domainParts.length - 1];
      results.push({
        type      : 'homoglyph',
        brand     : brandName,
        canonical : brandDomain,
        detail    : `Character substitution in domain prefix: "${domainFirstSeg}" mimics "${brandNoTLD}" (full domain: "${cleanDomain}")`,
        confidence: RISKY_TLDS.has(tld) ? 'HIGH' : 'HIGH'
      });
      continue;
    }

    // Check 3: Brand name contained in domain (after homoglyph normalisation)
    // Catches: paypal-secure.xyz, secure-paypal.ml
    if (normalisedFull.includes(normBrand) && cleanDomain !== brandDomain) {
      const tld = domainParts[domainParts.length - 1];
      if (!brandDomain.endsWith('.' + tld) || RISKY_TLDS.has(tld)) {
        results.push({
          type      : 'brand_in_domain',
          brand     : brandName,
          canonical : brandDomain,
          detail    : `Brand name "${brandNoTLD}" embedded in suspicious domain "${cleanDomain}"`,
          confidence: RISKY_TLDS.has(tld) ? 'HIGH' : 'MEDIUM'
        });
        continue;
      }
    }

    // Check 4: Levenshtein distance ≤ 2 on first segment
    // Catches: paypol.com, payapl.xyz
    if (normBrand.length > 4) {
      const distFull = levenshtein(normalisedFull, normBrand);
      const distSeg  = levenshtein(normalisedSeg, normBrand);
      const dist     = Math.min(distFull, distSeg);

      const lenRatio = Math.min(normalisedFull.length, normBrand.length) /
                       Math.max(normalisedFull.length, normBrand.length);
      if (dist <= 2 && dist > 0 && lenRatio >= 0.6) {
        results.push({
          type      : 'typo',
          brand     : brandName,
          canonical : brandDomain,
          detail    : `Possible typo: "${cleanDomain}" is ${dist} character edit(s) from "${brandDomain}"`,
          confidence: dist === 1 ? 'HIGH' : 'MEDIUM'
        });
      }
    }
  }

  // Deduplicate — keep highest confidence per brand
  const seen = new Map();
  for (const r of results) {
    if (!seen.has(r.brand) || r.confidence === 'HIGH') seen.set(r.brand, r);
  }
  return [...seen.values()].slice(0, 5);
}

// ─────────────────────────────────────────────
// URL BEHAVIOUR ANALYSER
// Analyses URL structure for suspicious patterns
// ─────────────────────────────────────────────

function analyseURLBehaviour(rawUrl) {
  const flags  = [];
  let riskBonus = 0;

  let parsed;
  try {
    parsed = new URL(rawUrl.startsWith('http') ? rawUrl : `https://${rawUrl}`);
  } catch {
    return { flags: [{ label: 'Invalid URL format', severity: 'HIGH' }], riskBonus: 10, urlStats: {} };
  }

  const domain   = parsed.hostname.toLowerCase();
  const path     = parsed.pathname.toLowerCase();
  const fullUrl  = rawUrl.toLowerCase();

  // [1] URL shortener
  if (SHORTENERS.has(domain)) {
    flags.push({ label: 'URL shortener used — true destination is hidden', severity: 'HIGH' });
    riskBonus += 20;
  }

  // [2] Risky TLD
  const tld = domain.split('.').pop();
  if (RISKY_TLDS.has(tld)) {
    flags.push({ label: `Risky top-level domain: .${tld} — commonly abused`, severity: 'HIGH' });
    riskBonus += 15;
  }

  // [3] IP address as hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
    flags.push({ label: 'Raw IP address used instead of domain name', severity: 'HIGH' });
    riskBonus += 20;
  }

  // [4] Excessive subdomains (≥ 4 levels)
  const subdomainCount = domain.split('.').length - 2;
  if (subdomainCount >= 3) {
    flags.push({ label: `Excessive subdomain depth: ${subdomainCount} levels — used to obscure domain`, severity: 'MEDIUM' });
    riskBonus += 10;
  }

  // [5] URL length > 100 characters
  if (rawUrl.length > 100) {
    flags.push({ label: `Unusually long URL: ${rawUrl.length} characters — can obscure true destination`, severity: 'LOW' });
    riskBonus += 5;
  }

  // [6] Suspicious keywords in path
  const foundKeywords = SUSPECT_KEYWORDS.filter(k => path.includes(k));
  if (foundKeywords.length > 0) {
    flags.push({ label: `Credential harvesting keywords in URL path: ${foundKeywords.slice(0,3).join(', ')}`, severity: 'MEDIUM' });
    riskBonus += foundKeywords.length * 5;
  }

  // [7] URL encoding / obfuscation
  if ((fullUrl.match(/%[0-9a-f]{2}/gi) || []).length > 5) {
    flags.push({ label: 'Heavy URL encoding detected — common obfuscation technique', severity: 'MEDIUM' });
    riskBonus += 10;
  }

  // [8] Multiple redirects in URL (double http)
  if ((fullUrl.match(/https?:\/\//g) || []).length > 1) {
    flags.push({ label: 'URL contains embedded redirect', severity: 'HIGH' });
    riskBonus += 15;
  }

  // [9] Hyphen abuse — many hyphens suggest constructed domain
  const hyphenCount = (domain.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    flags.push({ label: `High hyphen count in domain: ${hyphenCount} hyphens — suggests auto-generated or deceptive domain`, severity: 'MEDIUM' });
    riskBonus += 8;
  }

  // [10] HTTP not HTTPS
  if (parsed.protocol === 'http:') {
    flags.push({ label: 'Unencrypted HTTP connection — no transport security', severity: 'MEDIUM' });
    riskBonus += 8;
  }

  return {
    flags,
    riskBonus : Math.min(riskBonus, 50),
    urlStats  : {
      length        : rawUrl.length,
      subdomains    : subdomainCount,
      tld,
      protocol      : parsed.protocol.replace(':', ''),
      hasQueryParams: parsed.search.length > 0,
      pathDepth     : path.split('/').filter(Boolean).length
    }
  };
}

// ─────────────────────────────────────────────
// CERTIFICATE RISK SCORER
// Extends basic cert data with risk assessment
// ─────────────────────────────────────────────

function scoreCertificateRisk(cert) {
  if (!cert || cert.error) return { score: 30, flags: ['Certificate unavailable — HTTPS may not be configured'], grade: 'F' };

  const flags = [];
  let score   = 0;

  // Expiry
  if (cert.isExpired) {
    flags.push('Certificate has expired'); score += 40;
  } else if (cert.daysUntilExpiry <= 7) {
    flags.push(`Critical: certificate expires in ${cert.daysUntilExpiry} days`); score += 30;
  } else if (cert.daysUntilExpiry <= 30) {
    flags.push(`Warning: certificate expires in ${cert.daysUntilExpiry} days`); score += 15;
  }

  // Trust
  if (!cert.isAuthorized) {
    flags.push('Certificate not trusted by system CA store — possible self-signed'); score += 30;
  }

  // Key strength — ECDSA 256-bit is strong, RSA needs 2048+
  if (cert.bits) {
    const protocol  = (cert.protocol || '').toLowerCase();
    const issuerStr = (cert.issuer  || '').toLowerCase();
    // ECDSA/EC keys: 256-bit is equivalent to RSA 3072-bit — strong
    const isECDSA = protocol.includes('ecdsa') || issuerStr.includes('trust services') ||
                    cert.bits <= 521; // EC key sizes: 256, 384, 521
    if (!isECDSA) {
      if (cert.bits < 1024)      { flags.push('Critically weak RSA key: less than 1024-bit'); score += 35; }
      else if (cert.bits < 2048) { flags.push('Weak RSA key: less than 2048-bit'); score += 20; }
    }
  }

  // Self-signed detection (issuer === subject)
  if (cert.issuer && cert.subject) {
    const issuer  = cert.issuer.toLowerCase();
    const subject = (cert.subject || '').toLowerCase();
    const KNOWN_CAS = ["let's encrypt","digicert","comodo","sectigo","globalsign","geotrust","entrust","godaddy","amazon","cloudflare","google","zerossl"];
    const isSelfSigned = !KNOWN_CAS.some(ca => issuer.includes(ca)) && issuer === subject;
    if (isSelfSigned) { flags.push('Self-signed certificate — not issued by a trusted CA'); score += 25; }
  }

  const grade = score === 0 ? 'A+' : score <= 10 ? 'A' : score <= 20 ? 'B' : score <= 35 ? 'C' : score <= 50 ? 'D' : 'F';

  return {
    score: Math.min(score, 100),
    grade,
    flags,
    keyStrength: cert.bits ? `${cert.bits}-bit RSA` : 'Unknown',
    daysLeft   : cert.daysUntilExpiry
  };
}

module.exports = { detectTyposquatting, analyseURLBehaviour, scoreCertificateRisk, levenshtein };