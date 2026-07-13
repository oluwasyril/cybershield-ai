// ─────────────────────────────────────────────────────────────────
// threatEnricher.js — Scan Result Enrichment Engine
//
// Adds 8 professional enhancements to every scan result:
//  1. Risk Score Breakdown   — dynamic scoring explanation
//  2. Confidence Explanation — evidence for/against
//  3. Threat Classification  — primary/secondary categories
//  4. Infrastructure Intel   — IP, ASN, hosting details
//  5. Brand Impersonation    — typosquatting analysis section
//  6. MITRE Reasoning        — why each technique was mapped
//  7. Investigation Summary  — SOC-style analyst card
//  8. IOC Extraction         — clickable pivot indicators
//
// Called at the end of every route, before res.status(200).json()
// ─────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────
// 1. RISK SCORE BREAKDOWN
// Shows exactly what contributed to the score
// ─────────────────────────────────────────────

function buildRiskBreakdown(scanType, intelligence, riskScore) {
  const items  = [];
  const i      = intelligence || {};

  if (scanType === 'domain' || scanType === 'url') {
    const vt  = i.virusTotal   || {};
    const sb  = i.safeBrowsing || {};
    const cert= i.certificate  || {};
    const w   = i.whois        || {};
    const beh = i.urlBehaviour || {};
    const typo= i.typosquatting|| [];

    if ((vt.malicious || 0) >= 10) {
      items.push({ label: 'High VirusTotal detection count', points: Math.min(Math.round((vt.malicious / (vt.totalEngines || 70)) * 60), 45), direction: 'bad' });
    } else if ((vt.malicious || 0) >= 3) {
      items.push({ label: 'Multiple VirusTotal engine detections', points: Math.round((vt.malicious / (vt.totalEngines || 70)) * 50), direction: 'bad' });
    } else if ((vt.malicious || 0) === 0) {
      items.push({ label: 'No VirusTotal detections', points: 0, direction: 'good' });
    }

    if (sb.flagged) {
      const types = (sb.threats || []).join(', ') || 'threat';
      items.push({ label: `Google Safe Browsing: ${types}`, points: 35, direction: 'bad' });
    }

    if (cert.isExpired) {
      items.push({ label: 'SSL certificate has expired', points: 30, direction: 'bad' });
    } else if (cert.daysUntilExpiry <= 7) {
      items.push({ label: `SSL certificate expiring in ${cert.daysUntilExpiry} days`, points: 20, direction: 'bad' });
    } else if (cert.daysUntilExpiry <= 30) {
      items.push({ label: `SSL certificate expiring in ${cert.daysUntilExpiry} days`, points: 10, direction: 'bad' });
    } else if (!cert.error && !cert.isExpired) {
      items.push({ label: 'Valid SSL/TLS certificate', points: 0, direction: 'good' });
    }

    if (cert.error) {
      items.push({ label: 'No SSL certificate found', points: 20, direction: 'bad' });
    }

    if (w.domainAgeDays !== undefined && w.domainAgeDays !== null) {
      if (w.domainAgeDays < 7) {
        items.push({ label: `Domain registered only ${w.domainAgeDays} days ago`, points: 35, direction: 'bad' });
      } else if (w.domainAgeDays < 30) {
        items.push({ label: `Recently registered domain: ${w.domainAgeDays} days old`, points: 25, direction: 'bad' });
      } else if (w.domainAgeDays < 90) {
        items.push({ label: `New domain: ${w.domainAgeDays} days old`, points: 15, direction: 'bad' });
      } else if (w.domainAgeDays > 365) {
        items.push({ label: `Established domain: ${Math.floor(w.domainAgeDays/365)} year(s) old`, points: 0, direction: 'good' });
      }
    }

    if (typo.length > 0) {
      items.push({ label: `Brand impersonation: ${typo[0].brand}`, points: 15, direction: 'bad' });
    }

    const highFlags = (beh.flags || []).filter(f => f.severity === 'HIGH');
    const midFlags  = (beh.flags || []).filter(f => f.severity === 'MEDIUM');
    if (highFlags.length > 0) {
      items.push({ label: `${highFlags.length} high-severity URL behaviour flag(s)`, points: highFlags.length * 8, direction: 'bad' });
    }
    if (midFlags.length > 0) {
      items.push({ label: `${midFlags.length} medium-severity URL behaviour flag(s)`, points: midFlags.length * 4, direction: 'bad' });
    }

    if ((vt.reputation || 0) > 0) {
      items.push({ label: 'Positive VirusTotal community reputation', points: 0, direction: 'good' });
    }
  }

  if (scanType === 'ip') {
    const abuse = i.abuseIPDB || {};
    const asn   = i.asn       || {};

    if ((abuse.abuseScore || 0) > 75) {
      items.push({ label: `Very high abuse score: ${abuse.abuseScore}%`, points: 55, direction: 'bad' });
    } else if ((abuse.abuseScore || 0) > 50) {
      items.push({ label: `High abuse score: ${abuse.abuseScore}%`, points: 40, direction: 'bad' });
    } else if ((abuse.abuseScore || 0) > 25) {
      items.push({ label: `Moderate abuse score: ${abuse.abuseScore}%`, points: 25, direction: 'bad' });
    } else if ((abuse.abuseScore || 0) <= 5) {
      items.push({ label: 'Very low abuse score', points: 0, direction: 'good' });
    }

    if (abuse.isTor) {
      items.push({ label: 'Known Tor exit node', points: 20, direction: 'bad' });
    }

    if ((abuse.totalReports || 0) > 100) {
      items.push({ label: `High report volume: ${abuse.totalReports} abuse reports`, points: 15, direction: 'bad' });
    } else if ((abuse.totalReports || 0) > 0) {
      items.push({ label: `${abuse.totalReports} documented abuse report(s)`, points: 5, direction: 'bad' });
    }

    if (asn.isBulletproof) {
      items.push({ label: 'ASN associated with bulletproof hosting', points: 20, direction: 'bad' });
    }

    if (asn.isProxy) {
      items.push({ label: 'IP identified as proxy or VPN', points: 15, direction: 'bad' });
    }

    if (asn.isLegitCloud && !abuse.isTor) {
      items.push({ label: 'Hosted by major legitimate cloud provider', points: 0, direction: 'good' });
    }
  }

  if (scanType === 'email') {
    const abs  = i.abstract   || {};
    const bi   = i.builtIn    || {};
    const typo = i.typosquatting || [];

    if (abs.isDisposable || bi.isDisposable) {
      items.push({ label: 'Disposable / throwaway email address', points: 45, direction: 'bad' });
    }

    if ((abs.totalBreaches || 0) > 0) {
      items.push({ label: `Email found in ${abs.totalBreaches} data breach(es)`, points: Math.min(abs.totalBreaches * 8, 30), direction: 'bad' });
    }

    if (abs.deliverability === 'UNDELIVERABLE') {
      items.push({ label: 'Email address is undeliverable', points: 20, direction: 'bad' });
    } else if (abs.deliverability === 'DELIVERABLE') {
      items.push({ label: 'Email address is deliverable', points: 0, direction: 'good' });
    }

    if (typo.length > 0) {
      items.push({ label: `Domain impersonates: ${typo[0].brand}`, points: 20, direction: 'bad' });
    }

    if ((abs.qualityScore || 0) > 0.7) {
      items.push({ label: `High quality score: ${abs.qualityScore}`, points: 0, direction: 'good' });
    } else if ((abs.qualityScore || 0) < 0.3 && abs.qualityScore !== undefined) {
      items.push({ label: `Low quality score: ${abs.qualityScore}`, points: 15, direction: 'bad' });
    }
  }

  if (scanType === 'header') {
    const auth  = i.authentication || {};
    const ip    = i.ipReputation   || {};
    const links = i.phishingLinks  || [];

    if (auth.spf === 'fail')  items.push({ label: 'SPF authentication failure', points: 20, direction: 'bad' });
    if (auth.dkim === 'fail') items.push({ label: 'DKIM signature invalid', points: 20, direction: 'bad' });
    if (auth.dmarc === 'fail')items.push({ label: 'DMARC policy violation', points: 15, direction: 'bad' });

    if (auth.spf === 'pass')  items.push({ label: 'SPF authentication passed', points: 0, direction: 'good' });
    if (auth.dkim === 'pass') items.push({ label: 'DKIM signature verified', points: 0, direction: 'good' });

    if (i.spoofingDetected) {
      items.push({ label: 'Email spoofing indicators detected', points: 25, direction: 'bad' });
    }

    const critLinks = links.filter(l => l.risk === 'CRITICAL' || l.risk === 'HIGH');
    if (critLinks.length > 0) {
      items.push({ label: `${critLinks.length} phishing link(s) in email body`, points: critLinks.length * 10, direction: 'bad' });
    }

    if ((ip.abuseScore || 0) > 30) {
      items.push({ label: `Sending IP abuse score: ${ip.abuseScore}%`, points: 15, direction: 'bad' });
    }
  }

  if (scanType === 'hash') {
    const vt = i.virusTotal || {};

    if ((vt.malicious || 0) > 30) {
      items.push({ label: `Detected by ${vt.malicious} of ${vt.totalEngines} AV engines`, points: 60, direction: 'bad' });
    } else if ((vt.malicious || 0) > 10) {
      items.push({ label: `Detected by ${vt.malicious} of ${vt.totalEngines} AV engines`, points: 45, direction: 'bad' });
    } else if ((vt.malicious || 0) > 0) {
      items.push({ label: `Detected by ${vt.malicious} of ${vt.totalEngines} AV engines`, points: 25, direction: 'bad' });
    } else {
      items.push({ label: 'No AV engine detections', points: 0, direction: 'good' });
    }

    if ((vt.suspicious || 0) > 0) {
      items.push({ label: `${vt.suspicious} engines flagged as suspicious`, points: vt.suspicious * 3, direction: 'bad' });
    }

    const cat = (vt.threatCategory || '').toLowerCase();
    if (cat.includes('ransom'))   items.push({ label: 'Classified as ransomware', points: 15, direction: 'bad' });
    if (cat.includes('trojan'))   items.push({ label: 'Classified as trojan', points: 10, direction: 'bad' });
    if (cat.includes('backdoor')) items.push({ label: 'Classified as backdoor', points: 12, direction: 'bad' });

    if (i.malwareFamily) {
      items.push({ label: `Known malware family: ${i.malwareFamily.name}`, points: 10, direction: 'bad' });
    }
  }

  return {
    items,
    total: riskScore,
    label: riskScore <= 20 ? 'Low Risk' : riskScore <= 50 ? 'Moderate Risk' : riskScore <= 75 ? 'High Risk' : 'Critical Risk'
  };
}

// ─────────────────────────────────────────────
// 2. CONFIDENCE EXPLANATION
// What supports and what reduces confidence
// ─────────────────────────────────────────────

function buildConfidenceExplanation(scanType, intelligence, assessment) {
  const supporting = [];
  const reducing   = [];
  const i          = intelligence || {};

  if (scanType === 'domain' || scanType === 'url') {
    const vt   = i.virusTotal   || {};
    const sb   = i.safeBrowsing || {};
    const cert = i.certificate  || {};
    const w    = i.whois        || {};
    const typo = i.typosquatting|| [];
    const mitre= assessment.mitre?.techniques || [];
    const isClean = (assessment.verdict || '') === 'CLEAN';

    if ((vt.malicious || 0) >= 5)        supporting.push('Multiple threat intelligence engine detections');
    if (sb.flagged)                       supporting.push('Confirmed by Google Safe Browsing');
    if (typo.length > 0)                  supporting.push('Brand impersonation confirmed via multiple methods');
    if (mitre.filter(t=>t.confidence==='HIGH').length > 0) supporting.push('High-confidence MITRE ATT&CK technique mapping');
    if (cert.isExpired)                   supporting.push('Expired SSL certificate is a strong phishing indicator');
    if (w.domainAgeDays != null && w.domainAgeDays < 30) supporting.push('Very recently registered domain');

    // For clean results, clean signals SUPPORT the verdict
    if (isClean) {
      if ((vt.malicious || 0) === 0 && !sb.flagged) supporting.push('No detections by VirusTotal or Google Safe Browsing');
      if (w.domainAgeDays > 365)            supporting.push(`Established domain — active for over ${Math.floor(w.domainAgeDays/365)} year(s)`);
      if (!cert.error && !cert.isExpired)   supporting.push('Valid SSL certificate from trusted CA');
      if ((vt.reputation || 0) > 0)        supporting.push(`Positive VirusTotal community reputation: ${vt.reputation}`);
    } else {
      // For suspicious/malicious, clean signals reduce confidence
      if ((vt.malicious || 0) === 0 && !sb.flagged) reducing.push('No detections by VirusTotal or Google Safe Browsing');
      if (w.domainAgeDays > 365)            reducing.push('Domain has been active for over one year');
      if (!cert.error && !cert.isExpired)   reducing.push('Valid SSL certificate from trusted CA');
      if ((vt.reputation || 0) > 0)        reducing.push('Positive VirusTotal community reputation');
      if ((vt.malicious || 0) < 3 && (vt.malicious || 0) > 0) reducing.push('Low number of engine detections — may be false positive');
    }
  }  // ← closes if (scanType === 'domain' || scanType === 'url')

  if (scanType === 'ip') {
    const abuse = i.abuseIPDB || {};
    const asn   = i.asn       || {};
    const mitre = assessment.mitre?.techniques || [];

    if ((abuse.abuseScore || 0) > 50)    supporting.push(`High AbuseIPDB confidence score: ${abuse.abuseScore}%`);
    if ((abuse.totalReports || 0) > 10)  supporting.push(`Corroborated by ${abuse.totalReports} independent abuse reports`);
    if (abuse.isTor)                     supporting.push('Confirmed Tor exit node — objective fact');
    if (asn.isBulletproof)               supporting.push('ASN documented in threat intelligence feeds');
    if (mitre.filter(t=>t.confidence==='HIGH').length > 0) supporting.push('Strong MITRE ATT&CK technique alignment');

    if ((abuse.abuseScore || 0) < 10)    reducing.push('Low overall abuse confidence score');
    if ((abuse.totalReports || 0) === 0) reducing.push('No abuse reports on record');
    if (asn.isLegitCloud)                reducing.push('IP belongs to a well-known legitimate cloud provider');
  }

  if (scanType === 'email') {
    const abs  = i.abstract || {};
    const typo = i.typosquatting || [];

    if (abs.isDisposable)                supporting.push('Confirmed disposable email service');
    if ((abs.totalBreaches || 0) > 0)    supporting.push(`Verified in ${abs.totalBreaches} known data breach(es)`);
    if (typo.length > 0)                 supporting.push('Domain impersonation confirmed');
    if (abs.deliverability === 'UNDELIVERABLE') supporting.push('Email is undeliverable — likely fake');

    if (abs.deliverability === 'DELIVERABLE') reducing.push('Email is deliverable');
    if ((abs.qualityScore || 0) > 0.7)   reducing.push(`High quality score: ${abs.qualityScore}`);
    if ((abs.totalBreaches || 0) === 0)  reducing.push('No known data breach history');
  }

  if (scanType === 'header') {
    const auth  = i.authentication || {};
    const links = i.phishingLinks  || [];

    const failCount = ['spf','dkim','dmarc'].filter(k => auth[k]==='fail').length;
    if (failCount === 3)  supporting.push('All three email authentication checks failed');
    else if (failCount > 0) supporting.push(`${failCount} of 3 email authentication check(s) failed`);
    if (i.spoofingDetected) supporting.push('Email spoofing definitively detected');
    if (links.filter(l=>l.risk==='CRITICAL').length > 0) supporting.push('Critical phishing links in email body');

    if (auth.spf === 'pass')  reducing.push('SPF authentication passed');
    if (auth.dkim === 'pass') reducing.push('DKIM signature is valid');
    if (links.length === 0)   reducing.push('No phishing links detected in body');
  }

  if (scanType === 'hash') {
    const vt = i.virusTotal || {};

    if ((vt.malicious || 0) > 20)        supporting.push(`Widely detected: ${vt.malicious} AV engines`);
    else if ((vt.malicious || 0) > 0)    supporting.push(`Detected by ${vt.malicious} independent AV engines`);
    if (i.malwareFamily)                 supporting.push(`Matches known malware family: ${i.malwareFamily.name}`);
    if ((vt.timesSubmitted || 0) > 10)   supporting.push('File has been submitted to VirusTotal multiple times');

    if ((vt.malicious || 0) < 5 && (vt.malicious || 0) > 0) reducing.push('Low engine detection count — possible false positive');
    if (!vt.found)                       reducing.push('Hash not found in VirusTotal database — file may be new or rare');
    if ((vt.harmless || 0) > 50)         reducing.push('Majority of engines classify as harmless');
  }

  return { supporting, reducing };
}

// ─────────────────────────────────────────────
// 3. THREAT CLASSIFICATION
// Primary and secondary threat categories
// ─────────────────────────────────────────────

const THREAT_CATEGORIES = {
  PHISHING              : 'Phishing',
  MALWARE               : 'Malware',
  CREDENTIAL_HARVESTING : 'Credential Harvesting',
  SPAM                  : 'Spam',
  BOTNET                : 'Botnet',
  C2                    : 'Command & Control',
  BRAND_IMPERSONATION   : 'Brand Impersonation',
  SUSPICIOUS_INFRA      : 'Suspicious Infrastructure',
  MALICIOUS_ATTACHMENT  : 'Malicious Attachment',
  RANSOMWARE            : 'Ransomware',
  INFOSTEALER           : 'Infostealer',
  DISPOSABLE_EMAIL      : 'Disposable Email',
  LEGITIMATE            : 'Legitimate',
  UNKNOWN               : 'Unknown'
};

function classifyThreat(scanType, intelligence, assessment) {
  const categories = new Set();
  const i          = intelligence || {};
  const verdict    = (assessment.verdict || '').toUpperCase();
  const aiCat      = (assessment.threatCategory || '').toLowerCase();

  if (verdict === 'CLEAN') {
    return {
      primary   : THREAT_CATEGORIES.LEGITIMATE,
      secondary : null,
      level     : 'None',
      categories: [THREAT_CATEGORIES.LEGITIMATE]
    };
  }

  // From AI classification
  if (aiCat.includes('phish'))       categories.add(THREAT_CATEGORIES.PHISHING);
  if (aiCat.includes('malware'))     categories.add(THREAT_CATEGORIES.MALWARE);
  if (aiCat.includes('ransom'))      categories.add(THREAT_CATEGORIES.RANSOMWARE);
  if (aiCat.includes('spam'))        categories.add(THREAT_CATEGORIES.SPAM);
  if (aiCat.includes('botnet'))      categories.add(THREAT_CATEGORIES.BOTNET);
  if (aiCat.includes('c2') || aiCat.includes('command')) categories.add(THREAT_CATEGORIES.C2);

  if (scanType === 'domain' || scanType === 'url') {
    const vt   = i.virusTotal   || {};
    const sb   = i.safeBrowsing || {};
    const typo = i.typosquatting|| [];
    const beh  = i.urlBehaviour || {};

    if (sb.flagged && (sb.threats || []).includes('SOCIAL_ENGINEERING')) categories.add(THREAT_CATEGORIES.PHISHING);
    if (sb.flagged && (sb.threats || []).includes('MALWARE'))            categories.add(THREAT_CATEGORIES.MALWARE);
    if (typo.length > 0) categories.add(THREAT_CATEGORIES.BRAND_IMPERSONATION);

    const hasCredKeywords = (beh.flags || []).some(f => f.label?.includes('Credential'));
    if (hasCredKeywords) categories.add(THREAT_CATEGORIES.CREDENTIAL_HARVESTING);

    const vtLabels = (vt.categories || {});
    if (Object.values(vtLabels).some(c => String(c).toLowerCase().includes('malware')))  categories.add(THREAT_CATEGORIES.MALWARE);
    if (Object.values(vtLabels).some(c => String(c).toLowerCase().includes('phishing'))) categories.add(THREAT_CATEGORIES.PHISHING);
  }

  if (scanType === 'ip') {
    const abuse = i.abuseIPDB || {};
    const asn   = i.asn       || {};

    if ((abuse.abuseScore || 0) > 30) categories.add(THREAT_CATEGORIES.SUSPICIOUS_INFRA);
    if (abuse.isTor)                  categories.add(THREAT_CATEGORIES.C2);
    if (asn.isBulletproof)            categories.add(THREAT_CATEGORIES.SUSPICIOUS_INFRA);
  }

  if (scanType === 'email') {
    const abs  = i.abstract || {};
    const typo = i.typosquatting || [];

    if (abs.isDisposable || i.builtIn?.isDisposable) categories.add(THREAT_CATEGORIES.DISPOSABLE_EMAIL);
    if (typo.length > 0)                             categories.add(THREAT_CATEGORIES.BRAND_IMPERSONATION);
    if ((abs.totalBreaches || 0) > 0)                categories.add(THREAT_CATEGORIES.CREDENTIAL_HARVESTING);
  }

  if (scanType === 'header') {
    categories.add(THREAT_CATEGORIES.PHISHING);
    if (i.spoofingDetected) categories.add(THREAT_CATEGORIES.BRAND_IMPERSONATION);
    if ((i.phishingLinks || []).length > 0) categories.add(THREAT_CATEGORIES.CREDENTIAL_HARVESTING);
  }

  if (scanType === 'hash') {
    const vt  = i.virusTotal || {};
    const cat = (vt.threatCategory || '').toLowerCase();
    const fam = i.malwareFamily;

    if (cat.includes('ransom') || fam?.type?.toLowerCase().includes('ransom'))   categories.add(THREAT_CATEGORIES.RANSOMWARE);
    if (cat.includes('trojan'))                                                   categories.add(THREAT_CATEGORIES.MALWARE);
    if (cat.includes('backdoor'))                                                 categories.add(THREAT_CATEGORIES.C2);
    if (cat.includes('spy') || fam?.type?.toLowerCase().includes('infostealer')) categories.add(THREAT_CATEGORIES.INFOSTEALER);
    if ((vt.malicious || 0) > 0)                                                 categories.add(THREAT_CATEGORIES.MALWARE);
    if ((vt.malicious || 0) > 0) categories.add(THREAT_CATEGORIES.MALICIOUS_ATTACHMENT);
  }

  if (categories.size === 0) {
    categories.add(verdict === 'SUSPICIOUS' ? THREAT_CATEGORIES.SUSPICIOUS_INFRA : THREAT_CATEGORIES.UNKNOWN);
  }

  const catArray  = [...categories];
  const riskScore = assessment.riskScore || 0;
  const level     = riskScore > 75 ? 'Critical' : riskScore > 50 ? 'High' : riskScore > 25 ? 'Medium' : 'Low';

  return {
    primary   : catArray[0],
    secondary : catArray[1] || null,
    level,
    categories: catArray
  };
}

// ─────────────────────────────────────────────
// 4. INFRASTRUCTURE INTELLIGENCE
// IP, ASN, hosting details with pivot targets
// ─────────────────────────────────────────────

function extractInfrastructure(scanType, intelligence, target) {
  const i     = intelligence || {};
  const infra = {};

  if (scanType === 'domain' || scanType === 'url') {
    const cert = i.certificate || {};
    const w    = i.whois       || {};

    if (cert.issuer)     infra.tlsIssuer     = cert.issuer;
    if (cert.protocol)   infra.tlsProtocol   = cert.protocol;
    if (w.registrar)     infra.registrar      = w.registrar;
    if (w.nameservers)   infra.nameservers    = w.nameservers.slice(0, 3);
    if (w.domainAgeDays !== undefined && w.domainAgeDays !== null) infra.domainAgeDays = w.domainAgeDays;
    if (w.registrantCountry) infra.country   = w.registrantCountry;
    if (w.registrantOrg)     infra.org       = w.registrantOrg;
  }

  if (scanType === 'ip') {
    const abuse = i.abuseIPDB || {};
    const asn   = i.asn       || {};

    infra.ip          = target;
    infra.country     = abuse.countryName || abuse.countryCode || asn.country;
    infra.isp         = abuse.isp         || asn.isp;
    infra.org         = asn.org;
    infra.asn         = asn.asn;
    infra.asnName     = asn.asnName;
    infra.hostingType = asn.hostingType;
    infra.isProxy     = asn.isProxy;
    infra.isTor       = abuse.isTor;

    // Pivot target
    infra.pivots = [];
  }

  if (scanType === 'email') {
    const domain   = target.split('@')[1];
    const abs      = i.abstract  || {};
    const domainIP = i.domainIP  || {};

    infra.domain       = domain;
    infra.registrar    = abs.domainRegistrar;
    infra.domainAgeDays= abs.domainAgeDays;

    if (domainIP.ipAddress) {
      infra.ip      = domainIP.ipAddress;
      infra.country = domainIP.country;
      infra.isp     = domainIP.isp;
    }

    infra.pivots = [
      { label: 'Investigate Domain', type: 'domain', value: domain },
      domainIP.ipAddress ? { label: 'Investigate IP', type: 'ip', value: domainIP.ipAddress } : null
    ].filter(Boolean);
  }

  if (scanType === 'header') {
    const ip = i.ipReputation || {};

    if (i.sendingIP) {
      infra.ip          = i.sendingIP;
      infra.country     = ip.countryName || ip.countryCode;
      infra.isp         = ip.isp;
      infra.abuseScore  = ip.abuseScore;
    }

    infra.pivots = i.sendingIP
      ? [{ label: 'Investigate Sending IP', type: 'ip', value: i.sendingIP }]
      : [];
  }

  return infra;
}

// ─────────────────────────────────────────────
// 5. BRAND IMPERSONATION ANALYSIS
// Detailed typosquatting section
// ─────────────────────────────────────────────

function buildImpersonationAnalysis(intelligence) {
  const i    = intelligence || {};
  const typo = i.typosquatting || [];

  if (typo.length === 0) return null;

  return typo.map(hit => {
    // Calculate similarity score from edit distance or type
    let similarity = 70;
    if (hit.type === 'homoglyph')       similarity = 92;
    if (hit.type === 'brand_in_domain') similarity = 85;
    if (hit.type === 'typo')            similarity = 78;

    // Detection methods
    const methods = [];
    if (hit.type === 'homoglyph' || hit.type === 'typo') methods.push('Levenshtein Distance');
    if (hit.type === 'brand_in_domain')                  methods.push('Keyword Matching');
    if (hit.detail?.includes('substitution'))            methods.push('Homoglyph Analysis');
    if (methods.length === 0)                            methods.push('Pattern Matching');

    // Extract suspicious keywords from domain or URL stats
    const searchTarget = String(hit.canonical || '') + ' ' + String(hit.detail || '');
    const keywords = ['login','secure','verify','account','update','password','signin','support']
      .filter(k => searchTarget.includes(k));

    return {
      brand      : hit.brand,
      canonical  : hit.canonical,
      type       : hit.type,
      detail     : hit.detail,
      confidence : hit.confidence,
      similarity,
      methods,
      keywords   : keywords.length > 0 ? keywords : [],
      risk       : hit.confidence === 'HIGH' ? 'High' : 'Medium'
    };
  });
}

// ─────────────────────────────────────────────
// 6. MITRE ATT&CK REASONING
// Why each technique was mapped
// ─────────────────────────────────────────────

const TECHNIQUE_REASONING = {
  'T1566'     : (i, scanType) => buildPhishingReason(i, scanType),
  'T1566.001' : (i) => i.authentication?.spf === 'fail' ? 'SPF failure indicates potential email spoofing used to deliver malicious attachments.' : 'Email authentication failures consistent with spearphishing attachment delivery.',
  'T1566.002' : (i, scanType) => buildPhishingReason(i, scanType),
  'T1598'     : (i) => 'Phishing indicators suggest reconnaissance-phase credential collection targeting.',
  'T1583.001' : (i) => {
    const days = i.whois?.domainAgeDays;
    if (days !== null && days !== undefined && days < 30) return `Domain registered only ${days} days ago, consistent with adversary infrastructure acquisition for a specific campaign.`;
    return 'Domain characteristics suggest purpose-registered infrastructure for malicious use.';
  },
  'T1583.003' : (i) => {
    if (i.asn?.isBulletproof) return 'IP hosted in an ASN associated with bulletproof hosting providers that resist abuse takedown requests.';
    return 'Infrastructure hosted in a data centre environment typical of adversary VPS acquisition.';
  },
  'T1584'     : (i) => 'Infrastructure characteristics suggest a potentially compromised or repurposed legitimate server.',
  'T1585'     : (i) => 'Disposable or purpose-created email account consistent with establishing accounts for targeted operations.',
  'T1586'     : (i) => {
    const b = i.abstract?.totalBreaches || 0;
    return b > 0 ? `Email address found in ${b} data breach(es) — account may have been compromised and repurposed.` : 'Email account characteristics consistent with account compromise for malicious use.';
  },
  'T1090.003' : (i) => 'IP identified as a Tor network exit node, providing multi-hop anonymisation consistent with adversary operational security.',
  'T1071'     : (i) => 'High-abuse data centre IP may be serving as C2 infrastructure using standard application protocols to blend with legitimate traffic.',
  'T1110'     : (i) => `IP reported for brute force activity with an abuse score of ${i.abuseIPDB?.abuseScore || 0}%.`,
  'T1595'     : (i) => 'IP documented as conducting active scanning, consistent with reconnaissance phase targeting.',
  'T1498'     : (i) => 'IP associated with DDoS or volumetric network attack activity.',
  'T1204.001' : (i) => 'Malicious URL requires user interaction to execute — relies on the target clicking the link.',
  'T1204.002' : (i) => {
    const fam = i.malwareFamily?.name;
    return fam ? `File identified as ${fam} requires user execution to deploy the malicious payload.` : 'Malicious file execution requires user interaction to activate the payload.';
  },
  'T1486'     : (i) => {
    const fam = i.malwareFamily?.name;
    return fam ? `${fam} is a documented ransomware family that encrypts victim data and demands payment.` : 'File classification indicates ransomware behaviour — encrypts data to impact availability.';
  },
  'T1056'     : (i) => 'Credential harvesting keywords or behaviour detected — consistent with input capture techniques.',
  'T1539'     : (i) => 'Email breach history indicates credentials may have been compromised for session hijacking.',
  'T1219'     : (i) => 'File characteristics consistent with remote access tooling used for persistent unauthorised access.',
  'T1059'     : (i) => 'File type or behaviour indicators suggest script or command interpreter abuse for execution.',
  'T1588'     : (i) => 'File represents a malicious capability that an adversary has obtained for use in operations.',
  'T1189'     : (i) => 'URL characteristics consistent with drive-by compromise — may exploit browser vulnerabilities on visit.',
  'T1114'     : (i) => 'Email targeting indicators suggest collection of email content as part of the attack objective.',
};

function buildPhishingReason(i, scanType) {
  const parts = [];
  const vt    = i.virusTotal   || {};
  const sb    = i.safeBrowsing || {};
  const typo  = i.typosquatting|| [];
  const auth  = i.authentication|| {};

  if ((vt.malicious || 0) > 0) parts.push(`${vt.malicious} VirusTotal engine(s) flagged this as phishing`);
  if (sb.flagged)               parts.push('Google Safe Browsing confirmed phishing designation');
  if (typo.length > 0)         parts.push(`domain impersonates ${typo[0].brand}`);
  if (auth.spf === 'fail')     parts.push('SPF authentication failed');
  if (auth.dmarc === 'fail')   parts.push('DMARC policy violated');

  if (parts.length === 0) return 'Multiple indicators are consistent with phishing infrastructure or delivery mechanisms.';
  return `Mapped because: ${parts.join('; ')}.`;
}

function enrichMITREWithReasoning(techniques, scanType, intelligence) {
  if (!techniques || techniques.length === 0) return techniques;

  return techniques.map(t => {
    const reasonFn = TECHNIQUE_REASONING[t.id];
    const reason   = reasonFn
      ? reasonFn(intelligence, scanType)
      : `Detected indicators are consistent with the ${t.name} technique as documented in MITRE ATT&CK Enterprise.`;

    return { ...t, reasoning: reason };
  });
}

// ─────────────────────────────────────────────
// 7. INVESTIGATION SUMMARY (SOC-style card)
// ─────────────────────────────────────────────

function buildInvestigationSummary(target, scanType, assessment, threatClass, riskBreakdown) {
  const topIndicators = riskBreakdown.items
    .filter(item => item.direction === 'bad' && item.points > 0)
    .sort((a, b) => b.points - a.points)
    .slice(0, 4)
    .map(item => item.label);

  return {
    target,
    scanType,
    verdict          : assessment.verdict,
    riskScore        : assessment.riskScore,
    riskLabel        : riskBreakdown.label,
    primaryThreat    : threatClass.primary,
    secondaryThreat  : threatClass.secondary,
    threatLevel      : threatClass.level,
    recommendedAction: assessment.recommendedAction,
    confidence       : assessment.confidenceLevel,
    topIndicators,
    analystNote      : assessment.analystNotes || null,
    model            : 'LLaMA 3.3-70B via Groq',
    timestamp        : new Date().toISOString()
  };
}

// ─────────────────────────────────────────────
// 8. IOC EXTRACTION
// Clickable indicators for pivoting
// ─────────────────────────────────────────────

function extractIOCs(scanType, intelligence, target, assessment) {
  const iocs = [];
  const i    = intelligence || {};

  const addIOC = (type, value, context) => {
    if (!value || String(value).trim() === '') return;
    iocs.push({ type, value: String(value).trim(), context, pivotTab: getPivotTab(type) });
  };

  const getPivotTab = (type) => ({
    'domain' : 'domain',
    'url'    : 'domain',
    'ip'     : 'ip',
    'email'  : 'email',
    'hash'   : 'hash',
    'asn'    : 'ip'
  })[type] || null;

  if (scanType === 'domain' || scanType === 'url') {
    addIOC('domain', target, 'Scanned target');

    const w = i.whois || {};
    if (w.nameservers) w.nameservers.slice(0, 2).forEach(ns => addIOC('domain', ns, 'Nameserver'));
    if (w.registrantOrg) addIOC('domain', w.registrantOrg, 'Registrant organisation');

    const typo = i.typosquatting || [];
    typo.forEach(t => addIOC('domain', t.canonical, `Impersonated brand: ${t.brand}`));
  }

  if (scanType === 'ip') {
    addIOC('ip', target, 'Scanned IP address');
    const asn = i.asn || {};
    if (asn.asn) addIOC('asn', asn.asn, `ASN: ${asn.asnName || ''}`);
  }

  if (scanType === 'email') {
    addIOC('email', target, 'Scanned email address');
    const domain = target.split('@')[1];
    if (domain) addIOC('domain', domain, 'Email sender domain');
    const domainIP = i.domainIP || {};
    if (domainIP.ipAddress) addIOC('ip', domainIP.ipAddress, 'Domain resolves to');
  }

  if (scanType === 'header') {
    if (i.sendingIP) addIOC('ip', i.sendingIP, 'Email sending IP');
    (i.phishingLinks || []).forEach(l => addIOC('url', l.url, 'Phishing link in body'));
    if (i.fromDomain) addIOC('domain', i.fromDomain, 'Sender domain');
  }

  if (scanType === 'hash') {
    addIOC('hash', target, 'Scanned file hash');
    const vt = i.virusTotal || {};
    if (vt.hashes?.md5    && vt.hashes.md5    !== target) addIOC('hash', vt.hashes.md5,    'MD5 hash');
    if (vt.hashes?.sha1   && vt.hashes.sha1   !== target) addIOC('hash', vt.hashes.sha1,   'SHA1 hash');
    if (vt.hashes?.sha256 && vt.hashes.sha256 !== target) addIOC('hash', vt.hashes.sha256, 'SHA256 hash');
    (vt.fileNames || []).slice(0, 3).forEach(fn => addIOC('domain', fn, 'Associated file name'));
  }

  return iocs;
}

// ─────────────────────────────────────────────
// MAIN EXPORT — enrichScanResult()
//
// Call this at the end of every route handler,
// passing the full result object.
//
// Usage in scan.js:
//   const enriched = enrichScanResult(scanType, target, assessment, intelligence);
//   res.status(200).json({ success: true, ...enriched });
// ─────────────────────────────────────────────

function enrichScanResult(scanType, target, assessment, intelligence) {
  const riskBreakdown = buildRiskBreakdown(scanType, intelligence, assessment.riskScore || 0);
  const confidence    = buildConfidenceExplanation(scanType, intelligence, assessment);
  const threatClass   = classifyThreat(scanType, intelligence, assessment);
  const infra         = extractInfrastructure(scanType, intelligence, target);
  const impersonation = buildImpersonationAnalysis(intelligence);
  const iocs          = extractIOCs(scanType, intelligence, target, assessment);
  const summary       = buildInvestigationSummary(target, scanType, assessment, threatClass, riskBreakdown);

  // Enrich MITRE techniques with reasoning
  if (assessment.mitre?.techniques) {
    assessment.mitre.techniques = enrichMITREWithReasoning(
      assessment.mitre.techniques, scanType, intelligence
    );
  }

  return {
    timestamp     : new Date().toISOString(),
    target,
    scanType,
    assessment,
    intelligence,
    enrichment: {
      riskBreakdown,
      confidence,
      threatClassification: threatClass,
      infrastructure      : infra,
      impersonationAnalysis: impersonation,
      iocs,
      investigationSummary : summary
    }
  };
}

module.exports = {
  enrichScanResult,
  buildRiskBreakdown,
  buildConfidenceExplanation,
  classifyThreat,
  extractInfrastructure,
  buildImpersonationAnalysis,
  enrichMITREWithReasoning,
  buildInvestigationSummary,
  extractIOCs
};