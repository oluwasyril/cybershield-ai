// ─────────────────────────────────────────────
// hashScanner.js — File Hash Threat Intelligence
//
// Queries VirusTotal's file report endpoint
// using an MD5, SHA1, or SHA256 hash.
//
// No file upload needed — we only send the hash.
// This is safe, private, and uses the same
// VirusTotal API key already in .env
// ─────────────────────────────────────────────

const axios = require('axios');

// ─────────────────────────────────────────────
// HASH TYPE DETECTOR
// Identifies MD5 / SHA1 / SHA256 by length
// ─────────────────────────────────────────────

function detectHashType(hash) {
  const clean = hash.trim().toLowerCase();
  if (/^[a-f0-9]{32}$/.test(clean))  return { type: 'MD5',    hash: clean };
  if (/^[a-f0-9]{40}$/.test(clean))  return { type: 'SHA1',   hash: clean };
  if (/^[a-f0-9]{64}$/.test(clean))  return { type: 'SHA256', hash: clean };
  return null;
}

// ─────────────────────────────────────────────
// VIRUSTOTAL FILE REPORT
// Uses the /files/{hash} endpoint which accepts
// MD5, SHA1, or SHA256 without needing to upload
// ─────────────────────────────────────────────

async function checkHash(hash) {
  try {
    const response = await axios.get(
      `https://www.virustotal.com/api/v3/files/${hash}`,
      {
        headers: {
          'x-apikey': process.env.VIRUSTOTAL_API_KEY,
          'Accept'  : 'application/json'
        },
        timeout: 15000
      }
    );

    const data  = response.data.data;
    const attrs = data.attributes;
    const stats = attrs.last_analysis_stats || {};

    // Extract top threat names from engine results
    const engines      = attrs.last_analysis_results || {};
    const threatLabels = Object.values(engines)
      .filter(e => e.category === 'malicious' && e.result)
      .map(e => e.result)
      .filter((v, i, a) => a.indexOf(v) === i) // deduplicate
      .slice(0, 10);

    // File names seen associated with this hash
    const fileNames = attrs.names || [];

    // Sandbox behaviours (if available)
    const behaviour = attrs.popular_threat_classification || null;

    return {
      source          : 'VirusTotal',
      found           : true,
      hash,

      // Detection stats
      malicious       : stats.malicious    || 0,
      suspicious      : stats.suspicious   || 0,
      harmless        : stats.harmless     || 0,
      undetected      : stats.undetected   || 0,
      timeout         : stats.timeout      || 0,
      totalEngines    : Object.keys(engines).length,
      detectionRatio  : `${stats.malicious || 0}/${Object.keys(engines).length}`,

      // File metadata
      fileType        : attrs.type_description  || attrs.magic || 'Unknown',
      fileSize        : attrs.size              || null,
      mimeType        : attrs.type_tag          || null,
      fileNames       : fileNames.slice(0, 5),

      // Timestamps
      firstSeen       : attrs.first_submission_date
        ? new Date(attrs.first_submission_date * 1000).toISOString()
        : null,
      lastSeen        : attrs.last_analysis_date
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : null,
      timesSubmitted  : attrs.times_submitted || 0,

      // Threat classification
      threatLabels,
      threatCategory  : behaviour?.suggested_threat_label || null,
      popularThreat   : behaviour?.popular_threat_name?.[0]?.value || null,

      // Reputation
      reputation      : attrs.reputation || 0,

      // Hashes (for display)
      hashes: {
        md5   : attrs.md5    || null,
        sha1  : attrs.sha1   || null,
        sha256: attrs.sha256 || null
      }
    };

  } catch (error) {
    if (error.response?.status === 404) {
      // Hash not found in VirusTotal — not necessarily malicious
      return {
        source   : 'VirusTotal',
        found    : false,
        hash,
        message  : 'Hash not found in VirusTotal database. This file has not been submitted before.'
      };
    }

    console.error('[HASH] VirusTotal error:', error.message);
    return {
      source : 'VirusTotal',
      found  : false,
      error  : true,
      hash,
      message: error.response?.data?.error?.message || error.message
    };
  }
}

// ─────────────────────────────────────────────
// RISK SCORE CALCULATOR
// Based on detection ratio and threat labels
// ─────────────────────────────────────────────

function calculateRisk(vtResult) {
  if (!vtResult.found || vtResult.error) return 0;

  const total     = vtResult.totalEngines || 70;
  const malicious = vtResult.malicious    || 0;
  const suspicious= vtResult.suspicious   || 0;

  if (malicious === 0 && suspicious === 0) return 5;

  // Base score from detection ratio
  const detectionPct = ((malicious + suspicious) / total) * 100;
  let score = Math.round(detectionPct * 0.8); // scale to 0-80

  // Bonus points for high severity
  if (malicious > 20)                    score += 15;
  else if (malicious > 10)              score += 10;
  else if (malicious > 5)               score += 5;

  // Threat category bonuses
  const label = (vtResult.threatCategory || '').toLowerCase();
  if (label.includes('ransomware'))     score += 10;
  if (label.includes('trojan'))         score += 5;
  if (label.includes('backdoor'))       score += 8;
  if (label.includes('spyware'))        score += 7;

  return Math.min(score, 100);
}

// ─────────────────────────────────────────────
// MAIN EXPORT — scanHash()
// ─────────────────────────────────────────────

async function scanHash(rawHash) {
  const detected = detectHashType(rawHash);

  if (!detected) {
    throw new Error('Invalid hash format. Please provide a valid MD5 (32), SHA1 (40), or SHA256 (64) character hash.');
  }

  console.log(`[HASH SCAN] Type: ${detected.type} — Hash: ${detected.hash.slice(0, 16)}...`);

  const vtResult  = await checkHash(detected.hash);
  const riskScore = calculateRisk(vtResult);

  console.log(`[HASH SCAN] Complete — Found: ${vtResult.found} — Risk: ${riskScore}`);

  return {
    hash         : detected.hash,
    hashType     : detected.type,
    riskScore,
    intelligence : {
      virusTotal : vtResult
    }
  };
}

module.exports = { scanHash, detectHashType };