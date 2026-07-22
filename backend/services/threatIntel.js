// ─────────────────────────────────────────────────────────────────
// threatIntel.js — Live Threat Intelligence Service
// CyberShield AI — MSc Cybersecurity, Roehampton 2026
//
// Sources:
//   1. CISA Known Exploited Vulnerabilities (KEV) catalog
//      https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//   2. NVD Recent CVEs (last 7 days)
//      https://services.nvd.nist.gov/rest/json/cves/2.0
//   3. The Hacker News RSS feed (cybersecurity news)
//      https://feeds.feedburner.com/TheHackersNews
//
// Flow:
//   - Fetch raw data from all three sources in parallel
//   - Pass top items through Groq LLaMA 3.3-70B for plain-English briefing
//   - Cache result for 6 hours to avoid hammering APIs
//   - Serve via GET /api/threat-intel
// ─────────────────────────────────────────────────────────────────

const Groq  = require('groq-sdk');
const https = require('https');

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ── In-memory cache ──
let cache = { data: null, fetchedAt: null };
const CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

// ── HTTP fetch helper ──
function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'CyberShieldAI/1.0' } }, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch (e) { reject(new Error(`JSON parse failed for ${url}: ${e.message}`)); }
      });
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

// ── RSS fetch helper (returns raw XML string) ──
function fetchText(url) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: { 'User-Agent': 'CyberShieldAI/1.0' } }, res => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve(body));
    });
    req.on('error', reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error('Timeout')); });
  });
}

// ── Parse RSS XML to items ──
function parseRss(xml) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let match;
  while ((match = itemRegex.exec(xml)) !== null) {
    const item = match[1];
    const title       = (item.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/) ||
                         item.match(/<title>(.*?)<\/title>/))?.[1] || '';
    const description = (item.match(/<description><!\[CDATA\[(.*?)\]\]><\/description>/) ||
                         item.match(/<description>(.*?)<\/description>/))?.[1] || '';
    const link        = (item.match(/<link>(.*?)<\/link>/))?.[1] || '';
    const pubDate     = (item.match(/<pubDate>(.*?)<\/pubDate>/))?.[1] || '';
    if (title) items.push({ title, description: description.replace(/<[^>]+>/g, '').slice(0, 300), link, pubDate });
  }
  return items.slice(0, 4);
}

// ── Fetch CISA KEV ──
async function fetchCisaKev() {
  try {
    const data = await fetchJson('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
    const vulns = (data.vulnerabilities || [])
      .sort((a, b) => new Date(b.dateAdded) - new Date(a.dateAdded))
      .slice(0, 3);
    return vulns.map(v => ({
      source     : 'CISA KEV',
      id         : v.cveID,
      title      : `${v.cveID} - ${v.vulnerabilityName}`,
      product    : v.product,
      vendor     : v.vendorProject,
      description: v.shortDescription || v.vulnerabilityName,
      dateAdded  : v.dateAdded,
      dueDate    : v.dueDate,
      type       : 'cve'
    }));
  } catch (e) {
    console.error('[ThreatIntel] CISA KEV fetch failed:', e.message);
    return [];
  }
}

// ── Fetch NVD Recent CVEs ──
async function fetchNvdCves() {
  try {
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
      .toISOString().split('.')[0] + '.000';
    const now = new Date().toISOString().split('.')[0] + '.000';
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${sevenDaysAgo}&pubEndDate=${now}&cvssV3Severity=CRITICAL&resultsPerPage=3`;
    const data = await fetchJson(url);
    return (data.vulnerabilities || []).map(v => {
      const cve   = v.cve;
      const desc  = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
      const score = cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ||
                    cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore || null;
      return {
        source     : 'NVD',
        id         : cve.id,
        title      : cve.id,
        description: desc.slice(0, 400),
        score,
        published  : cve.published,
        type       : 'cve'
      };
    });
  } catch (e) {
    console.error('[ThreatIntel] NVD fetch failed:', e.message);
    return [];
  }
}

// ── Fetch Hacker News RSS ──
async function fetchHackerNews() {
  try {
    const xml = await fetchText('https://feeds.feedburner.com/TheHackersNews');
    return parseRss(xml).map(item => ({ ...item, source: 'The Hacker News', type: 'news' }));
  } catch (e) {
    console.error('[ThreatIntel] Hacker News RSS failed:', e.message);
    return [];
  }
}

// ── Groq: write plain-English briefing ──
async function summariseWithGroq(items) {
  const prompt = items.map((item, i) => `
ITEM ${i + 1}:
Source: ${item.source}
Type: ${item.type}
Title: ${item.title}
${item.id ? `ID: ${item.id}` : ''}
${item.product ? `Product: ${item.vendor} ${item.product}` : ''}
${item.score ? `CVSS Score: ${item.score}` : ''}
Description: ${item.description}
${item.dateAdded ? `Date Added: ${item.dateAdded}` : ''}
${item.pubDate ? `Published: ${item.pubDate}` : ''}
`).join('\n---\n');

  const systemPrompt = `
You are a cybersecurity awareness writer for a platform used by non-technical small business staff.
Your job is to take raw CVE and threat intelligence data and write plain-English briefings that
anyone can understand and act on immediately.

For each item, return a JSON object in this exact structure:
{
  "id": "<CVE ID or short unique slug>",
  "source": "<source name>",
  "type": "<cve or news>",
  "severity": "<CRITICAL or HIGH or MEDIUM or LOW>",
  "headline": "<One punchy sentence, max 12 words, that explains the threat in plain English>",
  "what": "<2 sentences: what this threat is and what it does to victims>",
  "who": "<1 sentence: who is affected - be specific about software, systems, or industries>",
  "action": "<2 sentences: exactly what the user should do right now to protect themselves>",
  "date": "<date string>",
  "url": "<link if available, otherwise empty string>"
}

Return a JSON array containing one object per item. No markdown, no text outside the JSON array.
Severity rules: CVSS 9.0+ = CRITICAL, 7.0-8.9 = HIGH, 4.0-6.9 = MEDIUM, below 4.0 = LOW.
For news items without a CVSS score, use your judgement based on the content.
Write in plain English. No jargon. No acronyms without explanation.
The "action" field must be specific - tell them exactly what to click, update, block, or check.
`;

  try {
    const completion = await groq.chat.completions.create({
      model      : 'llama-3.3-70b-versatile',
      temperature: 0.2,
      max_tokens : 3000,
      messages   : [
        { role: 'system', content: systemPrompt },
        { role: 'user',   content: `Summarise these ${items.length} threat intelligence items:\n${prompt}` }
      ]
    });

    const raw  = completion.choices[0]?.message?.content || '[]';
    const clean = raw.replace(/```json|```/g, '').trim();
    return JSON.parse(clean);
  } catch (e) {
    console.error('[ThreatIntel] Groq summarise failed:', e.message);
    return [];
  }
}

// ── Main export: getThreatIntel ──
async function getThreatIntel() {
  // Return cached if fresh
  if (cache.data && cache.fetchedAt && (Date.now() - cache.fetchedAt) < CACHE_TTL_MS) {
    console.log('[ThreatIntel] Serving from cache');
    return cache.data;
  }

  console.log('[ThreatIntel] Fetching fresh data...');

  // Fetch all sources in parallel
  const [cisaItems, nvdItems, newsItems] = await Promise.allSettled([
    fetchCisaKev(),
    fetchNvdCves(),
    fetchHackerNews()
  ]);

  const rawItems = [
    ...(cisaItems.status  === 'fulfilled' ? cisaItems.value  : []),
    ...(nvdItems.status   === 'fulfilled' ? nvdItems.value   : []),
    ...(newsItems.status  === 'fulfilled' ? newsItems.value  : []),
  ].slice(0, 8);

  if (rawItems.length === 0) {
    console.error('[ThreatIntel] All sources failed');
    return cache.data || [];
  }

  // Summarise with Groq
  const briefings = await summariseWithGroq(rawItems);

  // Sort by severity
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  briefings.sort((a, b) => (order[a.severity] ?? 4) - (order[b.severity] ?? 4));

  // Update cache
  cache = { data: briefings, fetchedAt: Date.now() };
  console.log(`[ThreatIntel] Cached ${briefings.length} briefings`);

  return briefings;
}

module.exports = { getThreatIntel };