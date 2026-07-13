// ─────────────────────────────────────────────
// emailScanner.js — Email Reputation Scanner
//
// Primary source: AbstractAPI Email Reputation
// URL: https://emailreputation.abstractapi.com/v1/
//
// Supplementary: AbuseIPDB (domain IP check)
// Built-in: disposable domains, role prefixes,
//           free providers lists
// ─────────────────────────────────────────────

const axios = require('axios');
const dns   = require('dns').promises;

// ─────────────────────────────────────────────
// BUILT-IN LISTS — no API needed
// ─────────────────────────────────────────────

const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com','guerrillamail.com','10minutemail.com','tempmail.com',
  'throwaway.email','yopmail.com','sharklasers.com','trashmail.com',
  'trashmail.me','dispostable.com','maildrop.cc','spamgourmet.com',
  'getairmail.com','throwam.com','tempr.email','discard.email',
  'fakeinbox.com','tempemail.net','mailtemporary.com','emailondeck.com',
  'tempmail.ninja','burnermail.io','guerrillamail.info','spam4.me',
  'trashmail.at','trashmail.io','trashmail.net','wegwerfmail.de',
  'mailnesia.com','spamevader.com','spambox.us','spamoff.de'
]);

const FREE_PROVIDERS = new Set([
  'gmail.com','yahoo.com','hotmail.com','outlook.com','live.com',
  'icloud.com','me.com','mac.com','aol.com','protonmail.com',
  'proton.me','tutanota.com','zoho.com','mail.com','gmx.com',
  'fastmail.com','yandex.com','inbox.com'
]);

const ROLE_PREFIXES = [
  'admin','administrator','info','support','help','contact','sales',
  'marketing','hr','finance','it','tech','webmaster','hostmaster',
  'postmaster','noreply','no-reply','donotreply','security','abuse'
];

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

function getDomain(email)  { return email.split('@')[1]?.toLowerCase() || ''; }
function getPrefix(email)  { return email.split('@')[0]?.toLowerCase() || ''; }

function builtInChecks(email) {
  const domain        = getDomain(email);
  const prefix        = getPrefix(email);
  const isDisposable  = DISPOSABLE_DOMAINS.has(domain);
  const isFree        = FREE_PROVIDERS.has(domain);
  const isRole        = ROLE_PREFIXES.some(r => prefix === r || prefix.startsWith(r + '.') || prefix.startsWith(r + '+'));
  return { domain, prefix, isDisposable, isFree, isRole };
}

// ─────────────────────────────────────────────
// SOURCE 1 — AbstractAPI Email Reputation
// Returns deliverability, quality, sender info,
// domain info, risk status AND breach history
// all in one call
// ─────────────────────────────────────────────

async function checkAbstractReputation(email) {
  try {
    const response = await axios.get('https://emailreputation.abstractapi.com/v1/', {
      params : { api_key: process.env.ABSTRACT_API_KEY, email },
      timeout: 10000
    });

    const d = response.data;

    return {
      source        : 'AbstractAPI Email Reputation',
      raw           : d,

      // Deliverability
      deliverability: d.email_deliverability?.status         || 'UNKNOWN',
      statusDetail  : d.email_deliverability?.status_detail  || '',
      isFormatValid : d.email_deliverability?.is_format_valid ?? true,
      isSmtpValid   : d.email_deliverability?.is_smtp_valid   ?? false,
      isMxValid     : d.email_deliverability?.is_mx_valid     ?? false,
      mxRecords     : d.email_deliverability?.mx_records      || [],

      // Quality
      qualityScore      : d.email_quality?.score               || 0,
      isFreeEmail       : d.email_quality?.is_free_email        ?? false,
      isSuspiciousUser  : d.email_quality?.is_username_suspicious ?? false,
      isDisposable      : d.email_quality?.is_disposable        ?? false,
      isCatchAll        : d.email_quality?.is_catchall           ?? false,
      isSubaddress      : d.email_quality?.is_subaddress         ?? false,
      isRole            : d.email_quality?.is_role               ?? false,
      isDmarcEnforced   : d.email_quality?.is_dmarc_enforced     ?? false,
      isSpfStrict       : d.email_quality?.is_spf_strict         ?? false,
      minimumAge        : d.email_quality?.minimum_age           || null,

      // Sender info
      firstName         : d.email_sender?.first_name            || null,
      lastName          : d.email_sender?.last_name             || null,
      providerName      : d.email_sender?.email_provider_name   || null,
      orgName           : d.email_sender?.organization_name     || null,
      orgType           : d.email_sender?.organization_type     || null,

      // Domain info
      domain            : d.email_domain?.domain                || '',
      domainAge         : d.email_domain?.domain_age            || null,
      isLiveSite        : d.email_domain?.is_live_site          ?? false,
      registrar         : d.email_domain?.registrar             || null,
      dateRegistered    : d.email_domain?.date_registered       || null,
      dateExpires       : d.email_domain?.date_expires          || null,
      isRiskyTld        : d.email_domain?.is_risky_tld          ?? false,

      // Risk assessment (AbstractAPI's own verdict)
      addressRisk       : d.email_risk?.address_risk_status     || 'unknown',
      domainRisk        : d.email_risk?.domain_risk_status      || 'unknown',

      // Breach data (built into AbstractAPI — no HIBP needed)
      totalBreaches     : d.email_breaches?.total_breaches      || 0,
      firstBreached     : d.email_breaches?.date_first_breached || null,
      lastBreached      : d.email_breaches?.date_last_breached  || null,
      breachedDomains   : d.email_breaches?.breached_domains    || []
    };

  } catch (error) {
    const status = error.response?.status;
    const msg    = status === 401 ? 'Invalid API key — check ABSTRACT_API_KEY on Render'
                 : status === 422 ? 'AbstractAPI quota reached for this month'
                 : status === 429 ? 'AbstractAPI rate limit — wait 1 second and retry'
                 : error.message;

    console.error(`[EMAIL] AbstractAPI error (${status||'network'}): ${msg}`);
    return { source: 'AbstractAPI', error: true, status, message: msg };
  }
}

// ─────────────────────────────────────────────
// SOURCE 2 — AbuseIPDB domain IP reputation
// Resolves the email domain to an IP address
// and checks its abuse history
// ─────────────────────────────────────────────

async function checkDomainIP(domain) {
  try {
    const addresses = await dns.resolve4(domain);
    const ip        = addresses[0];
    if (!ip) throw new Error('No A record found for domain');

    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      headers: { 'Key': process.env.ABUSEIPDB_API_KEY, 'Accept': 'application/json' },
      params : { ipAddress: ip, maxAgeInDays: 90 },
      timeout: 6000
    });

    const d = response.data.data;
    return {
      source      : 'AbuseIPDB',
      ip,
      abuseScore  : d.abuseConfidenceScore,
      totalReports: d.totalReports,
      countryCode : d.countryCode,
      isp         : d.isp,
      usageType   : d.usageType,
      isTor       : d.isTor
    };
  } catch (error) {
    console.error('[EMAIL] AbuseIPDB domain check error:', error.message);
    return { source: 'AbuseIPDB', error: true, message: error.message };
  }
}

// ─────────────────────────────────────────────
// RISK SCORE CALCULATOR
// Produces a 0–100 score from all signals
// ─────────────────────────────────────────────

function calculateRisk(abstract, domainIP, builtIn) {
  // If AbstractAPI failed entirely, use builtIn signals only
  if (abstract.error) {
    let score = 0;
    if (builtIn.isDisposable) score += 45;
    if (builtIn.isRole)       score += 5;
    return Math.min(score, 100);
  }

  let score = 0;

  // AbstractAPI's own risk verdict
  if (abstract.addressRisk === 'high')   score += 35;
  if (abstract.addressRisk === 'medium') score += 15;
  if (abstract.domainRisk  === 'high')   score += 20;
  if (abstract.domainRisk  === 'medium') score += 10;

  // Disposable email — highest individual signal
  if (abstract.isDisposable || builtIn.isDisposable) score += 40;

  // Deliverability signals
  if (abstract.deliverability === 'UNDELIVERABLE') score += 20;
  if (!abstract.isMxValid)                          score += 15;
  if (!abstract.isSmtpValid)                        score += 10;

  // Suspicious username
  if (abstract.isSuspiciousUser) score += 10;

  // Risky TLD (.xyz, .top, .click etc.)
  if (abstract.isRiskyTld)       score += 15;

  // Breach data from AbstractAPI
  if (abstract.totalBreaches > 0) {
    score += 15;
    score += Math.min(abstract.totalBreaches * 3, 15); // up to +15 more
  }

  // Domain abuse
  if (domainIP && !domainIP.error) {
    if (domainIP.abuseScore > 50) score += 20;
    else if (domainIP.abuseScore > 20) score += 10;
    if (domainIP.isTor) score += 15;
  }

  // Low quality score
  const q = abstract.qualityScore || 0;
  if (q < 0.3) score += 15;
  else if (q < 0.5) score += 8;

  // Small bonuses/reductions
  if (abstract.isRole) score += 5;
  if (abstract.isDmarcEnforced && abstract.isSpfStrict) score -= 5; // good security posture

  return Math.min(Math.max(score, 0), 100);
}

// ─────────────────────────────────────────────
// MAIN — scanEmail()
// Orchestrates all sources in parallel
// ─────────────────────────────────────────────

async function scanEmail(email) {
  const builtIn = builtInChecks(email);
  const domain  = builtIn.domain;

  console.log(`[EMAIL SCAN] Starting: ${email}`);

  const [abstractResult, domainResult] = await Promise.allSettled([
    checkAbstractReputation(email),
    checkDomainIP(domain)
  ]);

  const abstract = abstractResult.status === 'fulfilled'
    ? abstractResult.value
    : { source: 'AbstractAPI', error: true, message: 'Request failed' };

  const domainIP = domainResult.status === 'fulfilled'
    ? domainResult.value
    : { source: 'AbuseIPDB', error: true };

  const riskScore = calculateRisk(abstract, domainIP, builtIn);

  console.log(`[EMAIL SCAN] Complete: ${email} — Risk: ${riskScore} — AbstractAPI: ${abstract.error ? 'ERROR: '+abstract.message : 'OK'}`);

  return {
    email,
    domain,
    riskScore,
    intelligence: { abstract, domainIP, builtIn }
  };
}

module.exports = { scanEmail };