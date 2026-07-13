// ─────────────────────────────────────────────
// asnIntelligence.js — ASN Risk & Hosting Classification
//
// Enriches IP scan results with:
//   - ASN lookup via ip-api.com (free, no key)
//   - Bulletproof hosting detection
//   - Hosting type classification
//   - ASN abuse reputation
// ─────────────────────────────────────────────

const axios = require('axios');

// ─────────────────────────────────────────────
// KNOWN BULLETPROOF HOSTING ASNs
// These providers are documented as hosting
// malicious infrastructure with little takedown
// Sources: Spamhaus ASN blocklist, abuse.ch
// ─────────────────────────────────────────────

const BULLETPROOF_ASNS = new Set([
  'AS60068',  // Datacamp Limited — frequent C2 hosting
  'AS209588', // Vultr Holdings — high abuse rate
  'AS46844',  // Sharktech — bulletproof hosting
  'AS35913',  // DediPath — known bulletproof
  'AS57043',  // Hostkey BV
  'AS204428', // SS-Net (Russia) — documented bulletproof
  'AS49505',  // Selectel — Russian hosting, high abuse
  'AS197695', // Reg.ru — Russian registrar/hosting
  'AS8075',   // Microsoft — note: legitimate but high volume abuse
  'AS20473',  // Choopa/Vultr
  'AS36352',  // ColoCrossing — frequent abuse reports
  'AS55286',  // B2 Net Solutions
  'AS133229', // Hostwinds
]);

// Known legitimate cloud providers (lower suspicion)
const LEGITIMATE_CLOUD = new Set([
  'AS15169',  // Google
  'AS16509',  // Amazon AWS
  'AS14618',  // Amazon AWS
  'AS8075',   // Microsoft Azure
  'AS13335',  // Cloudflare
  'AS54113',  // Fastly
  'AS20940',  // Akamai
  'AS32934',  // Facebook/Meta
  'AS36040',  // Google
  'AS396982', // Google Cloud
]);

// ─────────────────────────────────────────────
// HOSTING TYPE CLASSIFIER
// Based on ISP name and org name patterns
// ─────────────────────────────────────────────

function classifyHostingType(isp, org, usageType) {
  const text = `${isp} ${org} ${usageType}`.toLowerCase();

  if (text.includes('tor') || text.includes('anonymi'))
    return { type: 'Anonymisation Network', risk: 'CRITICAL', icon: '⚠' };

  if (text.includes('vpn'))
    return { type: 'VPN Provider', risk: 'HIGH', icon: '⚠' };

  if (text.includes('proxy'))
    return { type: 'Proxy Service', risk: 'HIGH', icon: '⚠' };

  if (text.includes('hosting') || text.includes('data center') || text.includes('datacenter') || usageType?.includes('Data Center'))
    return { type: 'Data Centre / Cloud', risk: 'MEDIUM', icon: '○' };

  if (text.includes('isp') || text.includes('broadband') || text.includes('telecom') || text.includes('cable') || usageType?.includes('Fixed Line'))
    return { type: 'Residential ISP', risk: 'LOW', icon: '✓' };

  if (text.includes('mobile') || text.includes('cellular') || usageType?.includes('Mobile'))
    return { type: 'Mobile Network', risk: 'LOW', icon: '✓' };

  if (text.includes('university') || text.includes('college') || text.includes('academic') || text.includes('.edu') || text.includes('.ac.uk'))
    return { type: 'Academic Institution', risk: 'LOW', icon: '✓' };

  if (text.includes('government') || text.includes('.gov'))
    return { type: 'Government Network', risk: 'LOW', icon: '✓' };

  return { type: 'Unknown / Commercial', risk: 'MEDIUM', icon: '○' };
}

// ─────────────────────────────────────────────
// ASN LOOKUP via ip-api.com
// Free, no key needed, returns ASN + org info
// ─────────────────────────────────────────────

async function lookupASN(ip) {
  try {
    const response = await axios.get(
      `http://ip-api.com/json/${ip}?fields=status,country,countryCode,regionName,city,isp,org,as,asname,mobile,proxy,hosting`,
      { timeout: 6000 }
    );

    const d = response.data;
    if (d.status !== 'success') throw new Error('ip-api lookup failed');

    const asnNumber   = d.as?.split(' ')[0] || null;   // e.g. "AS15169"
    const asnName     = d.asname || d.org || null;

    const isBulletproof = BULLETPROOF_ASNS.has(asnNumber);
    const isLegitCloud  = LEGITIMATE_CLOUD.has(asnNumber);
    const hosting       = classifyHostingType(d.isp, d.org, d.hosting ? 'Data Center' : '');

    return {
      source         : 'ip-api',
      asn            : asnNumber,
      asnName        : asnName,
      isp            : d.isp,
      org            : d.org,
      country        : d.country,
      countryCode    : d.countryCode,
      region         : d.regionName,
      city           : d.city,
      isProxy        : d.proxy,
      isMobile       : d.mobile,
      isDataCenter   : d.hosting,
      hostingType    : hosting.type,
      hostingRisk    : hosting.risk,
      isBulletproof  : isBulletproof,
      isLegitCloud   : isLegitCloud,
      riskFlags      : [
        isBulletproof && 'ASN associated with bulletproof hosting — low takedown compliance',
        d.proxy       && 'IP identified as proxy or VPN endpoint',
        d.hosting && !isLegitCloud && 'Hosted in data centre — common for malicious infrastructure',
        hosting.risk === 'CRITICAL' && 'Anonymisation network detected',
      ].filter(Boolean)
    };

  } catch (error) {
    console.error('[ASN] Lookup error:', error.message);
    return { source: 'ip-api', error: true, message: error.message };
  }
}

// ─────────────────────────────────────────────
// MALWARE FAMILY DESCRIPTION
// Maps common threat labels to descriptions
// Used by the File Hash Scanner tab
// ─────────────────────────────────────────────

const MALWARE_FAMILIES = {
  'wannacry'    : { name: 'WannaCry', type: 'Ransomware', desc: 'Notorious ransomware worm that exploited EternalBlue (MS17-010) to spread across networks, encrypting files and demanding Bitcoin ransom. Caused global disruption in May 2017.' },
  'emotet'      : { name: 'Emotet', type: 'Banking Trojan / Dropper', desc: 'Sophisticated modular banking trojan that evolved into a dropper for other malware. Distributed via phishing emails, capable of self-propagation across networks.' },
  'trickbot'    : { name: 'TrickBot', type: 'Banking Trojan', desc: 'Modular banking trojan often delivered by Emotet. Steals credentials, performs network reconnaissance, and frequently drops ransomware as a final payload.' },
  'ryuk'        : { name: 'Ryuk', type: 'Ransomware', desc: 'Enterprise-targeting ransomware typically delivered after TrickBot infection. Known for high ransom demands targeting hospitals and critical infrastructure.' },
  'mirai'       : { name: 'Mirai', type: 'Botnet / IoT Malware', desc: 'Botnet malware that infects IoT devices using default credentials. Infamous for launching massive DDoS attacks including the 2016 Dyn DNS attack.' },
  'remcos'      : { name: 'Remcos', type: 'Remote Access Trojan', desc: 'Commercial RAT repurposed by threat actors for unauthorised remote access. Capabilities include keylogging, screen capture, and webcam access.' },
  'nanocore'    : { name: 'NanoCore', type: 'Remote Access Trojan', desc: 'Cheap but capable RAT sold on criminal forums. Provides remote access, keylogging, and credential theft capabilities.' },
  'njrat'       : { name: 'njRAT', type: 'Remote Access Trojan', desc: 'Widely distributed RAT used heavily in Middle East and North Africa. Provides full remote access and is commonly distributed via phishing.' },
  'agent tesla' : { name: 'Agent Tesla', type: 'Infostealer / Keylogger', desc: 'Credential stealing malware that captures keystrokes, clipboard data, and credentials from browsers and email clients. Sold as malware-as-a-service.' },
  'formbook'    : { name: 'FormBook', type: 'Infostealer', desc: 'Infostealer that harvests credentials from web browsers and email clients. Distributed via phishing campaigns and sold as malware-as-a-service.' },
  'azorult'     : { name: 'AZORult', type: 'Infostealer', desc: 'Data stealer targeting browser credentials, cryptocurrency wallets, and desktop files. Often distributed alongside ransomware.' },
  'lokibot'     : { name: 'LokiBot', type: 'Infostealer', desc: 'Commodity infostealer targeting credentials from browsers, FTP clients, and email applications. One of the most commonly observed malware families.' },
  'redline'     : { name: 'RedLine', type: 'Infostealer', desc: 'Modern infostealer targeting browser credentials, cryptocurrency wallets, and VPN credentials. Sold as malware-as-a-service on criminal forums.' },
  'cobaltstrike': { name: 'Cobalt Strike', type: 'Post-Exploitation Framework', desc: 'Commercial penetration testing tool frequently abused by threat actors. Its beacon payload provides C2 communication for lateral movement and data exfiltration.' },
  'meterpreter' : { name: 'Meterpreter', type: 'Post-Exploitation Payload', desc: 'Metasploit payload providing in-memory code execution for post-exploitation. Commonly used for lateral movement and privilege escalation.' },
  'blackmatter' : { name: 'BlackMatter', type: 'Ransomware-as-a-Service', desc: 'RaaS operation targeting critical infrastructure. Claimed to be successor to DarkSide ransomware.' },
  'lockbit'     : { name: 'LockBit', type: 'Ransomware-as-a-Service', desc: 'Prolific RaaS operation known for fast encryption speed and data exfiltration prior to encryption. One of the most active ransomware groups.' },
  'generickd'   : { name: 'Generic.KD', type: 'Generic Threat', desc: 'Generic detection indicating a file matches known malicious behaviour patterns without matching a specific named family. Treat with caution.' },
  'msil'        : { name: 'MSIL Malware', type: '.NET Malware', desc: 'Malware written in .NET (Microsoft Intermediate Language). Common for RATs and infostealers due to cross-platform capability.' },
};

function getMalwareFamily(threatLabels, threatCategory) {
  if (!threatLabels?.length && !threatCategory) return null;

  const searchText = [...(threatLabels || []), threatCategory || ''].join(' ').toLowerCase();

  for (const [key, info] of Object.entries(MALWARE_FAMILIES)) {
    if (searchText.includes(key)) return info;
  }

  // Generic classification from category
  if (threatCategory) {
    if (threatCategory.toLowerCase().includes('ransom'))
      return { name: 'Ransomware', type: 'Ransomware', desc: 'File exhibits ransomware behaviour — encrypts files and demands payment for decryption keys. Immediate isolation of affected systems is recommended.' };
    if (threatCategory.toLowerCase().includes('trojan'))
      return { name: 'Trojan', type: 'Trojan', desc: 'File disguises itself as legitimate software while performing malicious actions in the background.' };
    if (threatCategory.toLowerCase().includes('backdoor'))
      return { name: 'Backdoor', type: 'Backdoor', desc: 'File installs a hidden access mechanism allowing remote unauthorised access to the system.' };
    if (threatCategory.toLowerCase().includes('exploit'))
      return { name: 'Exploit', type: 'Exploit', desc: 'File takes advantage of software vulnerabilities to execute malicious code.' };
  }

  return null;
}

module.exports = { lookupASN, classifyHostingType, getMalwareFamily, MALWARE_FAMILIES };