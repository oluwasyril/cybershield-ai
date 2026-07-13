// ─────────────────────────────────────────────
// mitreMapper.js — MITRE ATT&CK Technique Mapper
//
// Maps CyberShield AI scanner findings to
// MITRE ATT&CK Enterprise techniques.
//
// Framework: MITRE ATT&CK Enterprise v14
// Reference: https://attack.mitre.org/
//
// No API needed — pure lookup logic.
// Called by every scanner after analysis.
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
// ATT&CK TECHNIQUE DEFINITIONS
// Each technique has:
//   id         — ATT&CK technique ID
//   name       — official technique name
//   tactic     — parent tactic
//   tacticCode — tactic short code
//   url        — ATT&CK reference URL
//   desc       — one-line description
// ─────────────────────────────────────────────

const TECHNIQUES = {

  // ── Initial Access ──────────────────────────
  T1566: {
    id       : 'T1566',
    name     : 'Phishing',
    tactic   : 'Initial Access',
    tacticCode: 'TA0001',
    url      : 'https://attack.mitre.org/techniques/T1566/',
    desc     : 'Adversaries send phishing messages to gain access to victim systems.'
  },
  'T1566.001': {
    id       : 'T1566.001',
    name     : 'Spearphishing Attachment',
    tactic   : 'Initial Access',
    tacticCode: 'TA0001',
    url      : 'https://attack.mitre.org/techniques/T1566/001/',
    desc     : 'Adversaries send spearphishing emails with malicious attachments.'
  },
  'T1566.002': {
    id       : 'T1566.002',
    name     : 'Spearphishing Link',
    tactic   : 'Initial Access',
    tacticCode: 'TA0001',
    url      : 'https://attack.mitre.org/techniques/T1566/002/',
    desc     : 'Adversaries send spearphishing emails containing malicious links.'
  },
  T1190: {
    id       : 'T1190',
    name     : 'Exploit Public-Facing Application',
    tactic   : 'Initial Access',
    tacticCode: 'TA0001',
    url      : 'https://attack.mitre.org/techniques/T1190/',
    desc     : 'Adversaries exploit weaknesses in internet-facing systems.'
  },
  T1189: {
    id       : 'T1189',
    name     : 'Drive-by Compromise',
    tactic   : 'Initial Access',
    tacticCode: 'TA0001',
    url      : 'https://attack.mitre.org/techniques/T1189/',
    desc     : 'Adversaries compromise systems through web browser exploitation.'
  },

  // ── Execution ────────────────────────────────
  T1204: {
    id       : 'T1204',
    name     : 'User Execution',
    tactic   : 'Execution',
    tacticCode: 'TA0002',
    url      : 'https://attack.mitre.org/techniques/T1204/',
    desc     : 'Adversaries rely on user interaction to execute malicious code.'
  },
  'T1204.001': {
    id       : 'T1204.001',
    name     : 'Malicious Link',
    tactic   : 'Execution',
    tacticCode: 'TA0002',
    url      : 'https://attack.mitre.org/techniques/T1204/001/',
    desc     : 'Adversaries rely on a user clicking a malicious link.'
  },
  'T1204.002': {
    id       : 'T1204.002',
    name     : 'Malicious File',
    tactic   : 'Execution',
    tacticCode: 'TA0002',
    url      : 'https://attack.mitre.org/techniques/T1204/002/',
    desc     : 'Adversaries rely on a user opening a malicious file.'
  },
  T1059: {
    id       : 'T1059',
    name     : 'Command and Scripting Interpreter',
    tactic   : 'Execution',
    tacticCode: 'TA0002',
    url      : 'https://attack.mitre.org/techniques/T1059/',
    desc     : 'Adversaries abuse command and script interpreters to execute commands.'
  },

  // ── Persistence ──────────────────────────────
  T1098: {
    id       : 'T1098',
    name     : 'Account Manipulation',
    tactic   : 'Persistence',
    tacticCode: 'TA0003',
    url      : 'https://attack.mitre.org/techniques/T1098/',
    desc     : 'Adversaries manipulate accounts to maintain access.'
  },

  // ── Credential Access ────────────────────────
  T1056: {
    id       : 'T1056',
    name     : 'Input Capture',
    tactic   : 'Credential Access',
    tacticCode: 'TA0006',
    url      : 'https://attack.mitre.org/techniques/T1056/',
    desc     : 'Adversaries capture user input to obtain credentials.'
  },
  T1539: {
    id       : 'T1539',
    name     : 'Steal Web Session Cookie',
    tactic   : 'Credential Access',
    tacticCode: 'TA0006',
    url      : 'https://attack.mitre.org/techniques/T1539/',
    desc     : 'Adversaries steal session cookies to bypass authentication.'
  },
  T1110: {
    id       : 'T1110',
    name     : 'Brute Force',
    tactic   : 'Credential Access',
    tacticCode: 'TA0006',
    url      : 'https://attack.mitre.org/techniques/T1110/',
    desc     : 'Adversaries use brute force techniques to gain access to accounts.'
  },

  // ── Discovery ────────────────────────────────
  T1046: {
    id       : 'T1046',
    name     : 'Network Service Discovery',
    tactic   : 'Discovery',
    tacticCode: 'TA0007',
    url      : 'https://attack.mitre.org/techniques/T1046/',
    desc     : 'Adversaries enumerate services running on remote hosts.'
  },

  // ── Collection ───────────────────────────────
  T1114: {
    id       : 'T1114',
    name     : 'Email Collection',
    tactic   : 'Collection',
    tacticCode: 'TA0009',
    url      : 'https://attack.mitre.org/techniques/T1114/',
    desc     : 'Adversaries target email to collect sensitive information.'
  },

  // ── Command and Control ──────────────────────
  T1071: {
    id       : 'T1071',
    name     : 'Application Layer Protocol',
    tactic   : 'Command and Control',
    tacticCode: 'TA0011',
    url      : 'https://attack.mitre.org/techniques/T1071/',
    desc     : 'Adversaries communicate using application layer protocols.'
  },
  T1090: {
    id       : 'T1090',
    name     : 'Proxy',
    tactic   : 'Command and Control',
    tacticCode: 'TA0011',
    url      : 'https://attack.mitre.org/techniques/T1090/',
    desc     : 'Adversaries use proxies to route traffic to avoid detection.'
  },
  'T1090.003': {
    id       : 'T1090.003',
    name     : 'Multi-hop Proxy',
    tactic   : 'Command and Control',
    tacticCode: 'TA0011',
    url      : 'https://attack.mitre.org/techniques/T1090/003/',
    desc     : 'Adversaries chain multiple proxies to obfuscate traffic origin.'
  },
  T1219: {
    id       : 'T1219',
    name     : 'Remote Access Software',
    tactic   : 'Command and Control',
    tacticCode: 'TA0011',
    url      : 'https://attack.mitre.org/techniques/T1219/',
    desc     : 'Adversaries use legitimate remote access tools for C2.'
  },

  // ── Exfiltration ─────────────────────────────
  T1048: {
    id       : 'T1048',
    name     : 'Exfiltration Over Alternative Protocol',
    tactic   : 'Exfiltration',
    tacticCode: 'TA0010',
    url      : 'https://attack.mitre.org/techniques/T1048/',
    desc     : 'Adversaries exfiltrate data using non-standard protocols.'
  },

  // ── Impact ───────────────────────────────────
  T1486: {
    id       : 'T1486',
    name     : 'Data Encrypted for Impact',
    tactic   : 'Impact',
    tacticCode: 'TA0040',
    url      : 'https://attack.mitre.org/techniques/T1486/',
    desc     : 'Adversaries encrypt data to interrupt availability (ransomware).'
  },
  T1498: {
    id       : 'T1498',
    name     : 'Network Denial of Service',
    tactic   : 'Impact',
    tacticCode: 'TA0040',
    url      : 'https://attack.mitre.org/techniques/T1498/',
    desc     : 'Adversaries perform network DoS to degrade or block resource availability.'
  },

  // ── Resource Development ─────────────────────
  T1583: {
    id       : 'T1583',
    name     : 'Acquire Infrastructure',
    tactic   : 'Resource Development',
    tacticCode: 'TA0042',
    url      : 'https://attack.mitre.org/techniques/T1583/',
    desc     : 'Adversaries buy or rent infrastructure for staging operations.'
  },
  'T1583.001': {
    id       : 'T1583.001',
    name     : 'Domains',
    tactic   : 'Resource Development',
    tacticCode: 'TA0042',
    url      : 'https://attack.mitre.org/techniques/T1583/001/',
    desc     : 'Adversaries acquire domains for use in targeting.'
  },
  'T1583.003': {
    id       : 'T1583.003',
    name     : 'Virtual Private Server',
    tactic   : 'Resource Development',
    tacticCode: 'TA0042',
    url      : 'https://attack.mitre.org/techniques/T1583/003/',
    desc     : 'Adversaries rent VPS infrastructure to stage operations.'
  },
  T1584: {
    id       : 'T1584',
    name     : 'Compromise Infrastructure',
    tactic   : 'Resource Development',
    tacticCode: 'TA0042',
    url      : 'https://attack.mitre.org/techniques/T1584/',
    desc     : 'Adversaries compromise third-party infrastructure for use in campaigns.'
  },
  T1585: {
    id       : 'T1585',
    name     : 'Establish Accounts',
    tactic   : 'Resource Development',
    tacticCode: 'TA0042',
    url      : 'https://attack.mitre.org/techniques/T1585/',
    desc     : 'Adversaries create accounts to further targeting.'
  },
  T1586: {
    id       : 'T1586',
    name     : 'Compromise Accounts',
    tactic   : 'Resource Development',
    tacticCode: 'TA0042',
    url      : 'https://attack.mitre.org/techniques/T1586/',
    desc     : 'Adversaries compromise existing accounts to aid targeting.'
  },
  T1588: {
    id       : 'T1588',
    name     : 'Obtain Capabilities',
    tactic   : 'Resource Development',
    tacticCode: 'TA0042',
    url      : 'https://attack.mitre.org/techniques/T1588/',
    desc     : 'Adversaries acquire tools, exploits, or malware for operations.'
  },

  // ── Reconnaissance ───────────────────────────
  T1595: {
    id       : 'T1595',
    name     : 'Active Scanning',
    tactic   : 'Reconnaissance',
    tacticCode: 'TA0043',
    url      : 'https://attack.mitre.org/techniques/T1595/',
    desc     : 'Adversaries actively probe infrastructure to gather information.'
  },
  T1598: {
    id       : 'T1598',
    name     : 'Phishing for Information',
    tactic   : 'Reconnaissance',
    tacticCode: 'TA0043',
    url      : 'https://attack.mitre.org/techniques/T1598/',
    desc     : 'Adversaries send phishing messages to elicit sensitive information.'
  }
};

// ─────────────────────────────────────────────
// TACTIC COLOURS
// Used by the frontend for badge colouring
// ─────────────────────────────────────────────

const TACTIC_COLOURS = {
  'Initial Access'         : { bg: 'rgba(255,0,153,0.12)',   border: 'rgba(255,0,153,0.4)',   text: '#FF0099' },
  'Execution'              : { bg: 'rgba(255,80,0,0.12)',    border: 'rgba(255,80,0,0.4)',     text: '#FF5000' },
  'Persistence'            : { bg: 'rgba(255,140,0,0.12)',   border: 'rgba(255,140,0,0.4)',    text: '#FF8C00' },
  'Credential Access'      : { bg: 'rgba(255,208,68,0.12)',  border: 'rgba(255,208,68,0.4)',   text: '#FFD044' },
  'Discovery'              : { bg: 'rgba(30,144,255,0.12)',  border: 'rgba(30,144,255,0.4)',   text: '#1E90FF' },
  'Collection'             : { bg: 'rgba(0,191,255,0.12)',   border: 'rgba(0,191,255,0.4)',    text: '#00BFFF' },
  'Command and Control'    : { bg: 'rgba(148,0,211,0.12)',   border: 'rgba(148,0,211,0.4)',    text: '#9400D3' },
  'Exfiltration'           : { bg: 'rgba(255,0,153,0.12)',   border: 'rgba(255,0,153,0.4)',    text: '#FF0099' },
  'Impact'                 : { bg: 'rgba(220,20,60,0.12)',   border: 'rgba(220,20,60,0.4)',    text: '#DC143C' },
  'Resource Development'   : { bg: 'rgba(0,255,133,0.10)',   border: 'rgba(0,255,133,0.3)',    text: '#00FF85' },
  'Reconnaissance'         : { bg: 'rgba(100,149,237,0.12)', border: 'rgba(100,149,237,0.4)',  text: '#6495ED' }
};

// ─────────────────────────────────────────────
// MAPPING RULES
// Maps scanner findings → ATT&CK techniques
// Each rule has:
//   condition — function(intelligence) → boolean
//   techniques — array of technique IDs
//   confidence — HIGH / MEDIUM / LOW
// ─────────────────────────────────────────────

const MAPPING_RULES = {

  // ── DOMAIN / URL SCANNER ─────────────────────
  domain: [
    {
      label    : 'Malicious URL detected by multiple AV engines',
      condition: (i) => (i.virusTotal?.malicious || 0) >= 5,
      techniques: ['T1566.002', 'T1204.001'],
      confidence: 'HIGH'
    },
    {
      label    : 'URL flagged by Google Safe Browsing as phishing',
      condition: (i) => i.safeBrowsing?.flagged &&
                        (i.safeBrowsing?.threats || []).includes('SOCIAL_ENGINEERING'),
      techniques: ['T1566.002', 'T1598'],
      confidence: 'HIGH'
    },
    {
      label    : 'URL flagged by Google Safe Browsing as malware',
      condition: (i) => i.safeBrowsing?.flagged &&
                        (i.safeBrowsing?.threats || []).includes('MALWARE'),
      techniques: ['T1189', 'T1204.001'],
      confidence: 'HIGH'
    },
    {
      label    : 'Newly registered domain (< 90 days)',
      condition: (i) => i.whois?.domainAgeDays != null && i.whois.domainAgeDays < 90,
      techniques: ['T1583.001'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'Very recently registered domain (< 7 days)',
      condition: (i) => i.whois?.domainAgeDays != null && i.whois.domainAgeDays < 7,
      techniques: ['T1583.001', 'T1566'],
      confidence: 'HIGH'
    },
    {
      label    : 'SSL certificate not trusted',
      condition: (i) => i.certificate && !i.certificate.isAuthorized && !i.certificate.error,
      techniques: ['T1584', 'T1583.003'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'Domain IP has high abuse score',
      condition: (i) => (i.virusTotal?.reputation || 0) < -10,
      techniques: ['T1583.003', 'T1584'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'URL submitted but not previously seen (rare/new)',
      condition: (i) => i.virusTotal?.notCached === true,
      techniques: ['T1583.001'],
      confidence: 'LOW'
    },
    {
      label    : 'Risky or abused top-level domain detected',
      condition: (i) => (i.urlBehaviour?.flags || []).some(f => f.label?.includes('Risky top-level domain')),
      techniques: ['T1583.001'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'URL shortener — destination hidden',
      condition: (i) => (i.urlBehaviour?.flags || []).some(f => f.label?.includes('shortener')),
      techniques: ['T1204.001', 'T1566.002'],
      confidence: 'HIGH'
    },
    {
      label    : 'Typosquatting — brand impersonation detected',
      condition: (i) => (i.typosquatting || []).length > 0,
      techniques: ['T1566', 'T1598'],
      confidence: (i) => (i.typosquatting || []).some(t => t.confidence === 'HIGH') ? 'HIGH' : 'MEDIUM'
    },
    {
      label    : 'Credential harvesting keywords in URL',
      condition: (i) => (i.urlBehaviour?.flags || []).some(f => f.label?.includes('Credential harvesting')),
      techniques: ['T1056', 'T1566.002'],
      confidence: 'MEDIUM'
    }
  ],

  // ── IP SCANNER ───────────────────────────────
  ip: [
    {
      label    : 'IP reported for brute force attacks',
      condition: (i) => (i.abuseIPDB?.abuseScore || 0) > 50,
      techniques: ['T1110', 'T1595'],
      confidence: 'HIGH'
    },
    {
      label    : 'IP is a known Tor exit node',
      condition: (i) => i.abuseIPDB?.isTor === true,
      techniques: ['T1090.003'],
      confidence: 'HIGH'
    },
    {
      label    : 'IP used in DDoS or network attacks',
      condition: (i) => (i.abuseIPDB?.totalReports || 0) > 100,
      techniques: ['T1498', 'T1595'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'IP associated with C2 infrastructure',
      condition: (i) => (i.abuseIPDB?.abuseScore || 0) > 75 &&
                        (i.abuseIPDB?.usageType || '').toLowerCase().includes('data center'),
      techniques: ['T1071', 'T1583.003'],
      confidence: 'HIGH'
    },
    {
      label    : 'IP hosted in data centre with abuse reports',
      condition: (i) => (i.abuseIPDB?.abuseScore || 0) > 25 &&
                        (i.abuseIPDB?.usageType || '').toLowerCase().includes('data center'),
      techniques: ['T1583.003'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'Low-confidence abuse signals on IP',
      condition: (i) => (i.abuseIPDB?.abuseScore || 0) > 10 &&
                        (i.abuseIPDB?.abuseScore || 0) <= 25,
      techniques: ['T1595'],
      confidence: 'LOW'
    }
  ],

  // ── EMAIL SCANNER ────────────────────────────
  email: [
    {
      label    : 'Disposable or throwaway email address',
      condition: (i) => i.abstract?.isDisposable || i.builtIn?.isDisposable,
      techniques: ['T1585', 'T1566'],
      confidence: 'HIGH'
    },
    {
      label    : 'Email found in data breaches',
      condition: (i) => (i.abstract?.totalBreaches || 0) > 0,
      techniques: ['T1586', 'T1539'],
      confidence: 'HIGH'
    },
    {
      label    : 'Email address domain has high risk rating',
      condition: (i) => i.abstract?.domainRisk === 'high' || i.abstract?.addressRisk === 'high',
      techniques: ['T1566', 'T1598'],
      confidence: 'HIGH'
    },
    {
      label    : 'Email cannot be delivered (fake/inactive)',
      condition: (i) => i.abstract?.deliverability === 'UNDELIVERABLE',
      techniques: ['T1585'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'Suspicious username pattern detected',
      condition: (i) => i.abstract?.isSuspiciousUser === true,
      techniques: ['T1585', 'T1598'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'Domain IP has abuse reports',
      condition: (i) => (i.domainIP?.abuseScore || 0) > 30,
      techniques: ['T1583.003', 'T1584'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'Multiple breaches — possible credential compromise',
      condition: (i) => (i.abstract?.totalBreaches || 0) >= 3,
      techniques: ['T1586', 'T1110'],
      confidence: 'HIGH'
    }
  ],

  // ── EMAIL HEADER ANALYSER ────────────────────
  header: [
    {
      label    : 'SPF authentication failure detected',
      condition: (i) => i.authentication?.spf === 'fail' || i.authentication?.spf === 'softfail',
      techniques: ['T1566', 'T1584'],
      confidence: 'HIGH'
    },
    {
      label    : 'DKIM signature invalid or missing',
      condition: (i) => i.authentication?.dkim === 'fail',
      techniques: ['T1566.001', 'T1584'],
      confidence: 'HIGH'
    },
    {
      label    : 'DMARC policy violation detected',
      condition: (i) => i.authentication?.dmarc === 'fail',
      techniques: ['T1566', 'T1566.001'],
      confidence: 'HIGH'
    },
    {
      label    : 'Email spoofing indicators found',
      condition: (i) => i.spoofingDetected === true,
      techniques: ['T1566', 'T1598'],
      confidence: 'HIGH'
    },
    {
      label    : 'Sending IP has abuse history',
      condition: (i) => (i.ipReputation?.abuseScore || 0) > 30,
      techniques: ['T1583.003', 'T1071'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'Sending IP is a Tor node',
      condition: (i) => i.ipReputation?.isTor === true,
      techniques: ['T1090.003', 'T1566'],
      confidence: 'HIGH'
    },
    {
      label    : 'Phishing links detected in email body',
      condition: (i) => (i.phishingLinks || []).length > 0,
      techniques: ['T1566.002', 'T1204.001'],
      confidence: 'HIGH'
    },
    {
      label    : 'Critical phishing links in body',
      condition: (i) => (i.phishingLinks || []).some(l => l.risk === 'CRITICAL'),
      techniques: ['T1566.002', 'T1056', 'T1204.001'],
      confidence: 'HIGH'
    },
    {
      label    : 'All email authentication checks failed',
      condition: (i) => i.authentication?.spf !== 'pass' &&
                        i.authentication?.dkim !== 'pass' &&
                        i.authentication?.dmarc !== 'pass',
      techniques: ['T1566', 'T1598'],
      confidence: 'HIGH'
    }
  ],

  // ── FILE HASH SCANNER ────────────────────────
  hash: [
    {
      label    : 'File detected as malware by multiple AV engines',
      condition: (i) => (i.virusTotal?.malicious || 0) >= 5,
      techniques: ['T1204.002', 'T1588'],
      confidence: 'HIGH'
    },
    {
      label    : 'File detected as ransomware',
      condition: (i) => (i.virusTotal?.threatCategory || '').toLowerCase().includes('ransom') ||
                        (i.virusTotal?.threatLabels || []).some(l => l.toLowerCase().includes('ransom')),
      techniques: ['T1486', 'T1204.002'],
      confidence: 'HIGH'
    },
    {
      label    : 'File detected as trojan or backdoor',
      condition: (i) => (i.virusTotal?.threatCategory || '').toLowerCase().includes('trojan') ||
                        (i.virusTotal?.threatLabels || []).some(l =>
                          l.toLowerCase().includes('trojan') || l.toLowerCase().includes('backdoor')),
      techniques: ['T1204.002', 'T1059', 'T1219'],
      confidence: 'HIGH'
    },
    {
      label    : 'File detected as spyware or keylogger',
      condition: (i) => (i.virusTotal?.threatLabels || []).some(l =>
                          l.toLowerCase().includes('spyware') || l.toLowerCase().includes('keylog')),
      techniques: ['T1056', 'T1204.002'],
      confidence: 'HIGH'
    },
    {
      label    : 'File detected as downloader or dropper',
      condition: (i) => (i.virusTotal?.threatLabels || []).some(l =>
                          l.toLowerCase().includes('drop') || l.toLowerCase().includes('download')),
      techniques: ['T1204.002', 'T1588'],
      confidence: 'MEDIUM'
    },
    {
      label    : 'File suspicious but below malicious threshold',
      condition: (i) => (i.virusTotal?.suspicious || 0) > 3 &&
                        (i.virusTotal?.malicious || 0) < 5,
      techniques: ['T1204.002'],
      confidence: 'LOW'
    },
    {
      label    : 'File not seen before in VirusTotal',
      condition: (i) => i.virusTotal?.found === false,
      techniques: ['T1588'],
      confidence: 'LOW'
    }
  ]
};

// ─────────────────────────────────────────────
// MAIN EXPORT — mapToATTACK()
//
// scanType   : 'domain' | 'ip' | 'email' | 'header' | 'hash'
// intelligence: the intelligence object from the scanner
//
// Returns array of matched techniques, deduplicated,
// sorted by confidence (HIGH first)
// ─────────────────────────────────────────────

function mapToATTACK(scanType, intelligence) {
  const rules = MAPPING_RULES[scanType];
  if (!rules) return [];

  const matched  = new Map(); // techniqueId → best match
  const findings = [];        // human-readable triggered rules

  for (const rule of rules) {
    let triggered = false;
    try {
      triggered = rule.condition(intelligence);
    } catch {
      triggered = false;
    }

    if (!triggered) continue;

    findings.push({ label: rule.label, confidence: rule.confidence });

    // Resolve confidence — can be a string or a function
    const resolvedConfidence = typeof rule.confidence === 'function'
      ? rule.confidence(intelligence)
      : rule.confidence;

    for (const techId of rule.techniques) {
      const technique = TECHNIQUES[techId];
      if (!technique) continue;

      if (!matched.has(techId) || confidenceScore(resolvedConfidence) > confidenceScore(matched.get(techId).confidence)) {
        matched.set(techId, {
          ...technique,
          confidence    : resolvedConfidence,
          triggeredBy   : rule.label,
          colour        : TACTIC_COLOURS[technique.tactic] || TACTIC_COLOURS['Discovery']
        });
      }
    }
  }

  // Sort: HIGH first, then MEDIUM, then LOW
  const sorted = [...matched.values()].sort((a, b) =>
    confidenceScore(b.confidence) - confidenceScore(a.confidence)
  );

  return {
    techniques: sorted,
    findings,
    tacticsSummary: [...new Set(sorted.map(t => t.tactic))]
  };
}

function confidenceScore(c) {
  return c === 'HIGH' ? 3 : c === 'MEDIUM' ? 2 : 1;
}

module.exports = { mapToATTACK, TECHNIQUES, TACTIC_COLOURS };