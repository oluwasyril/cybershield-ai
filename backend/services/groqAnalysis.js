// ─────────────────────────────────────────────
// groqAnalysis.js — AI Threat Assessment
// Uses Groq API (LLaMA 3) to analyse scanner
// intelligence and produce structured verdicts.
// MITRE ATT&CK mapping attached to every result.
// ─────────────────────────────────────────────

const Groq          = require('groq-sdk');
const { mapToATTACK } = require('./mitreMapper');

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const SYSTEM_PROMPT = `
You are an expert cybersecurity analyst inside an automated SOC threat detection platform.
Analyse threat intelligence data and produce a structured threat assessment.

RULES:
- Respond ONLY with valid JSON. No markdown, no text outside the JSON.
- Base verdict ONLY on the data provided.
- Be conservative: when uncertain, classify higher risk.

RESPONSE STRUCTURE (exactly):
{
  "verdict": "CLEAN" | "SUSPICIOUS" | "MALICIOUS",
  "riskScore": <integer 0-100>,
  "confidenceLevel": "HIGH" | "MEDIUM" | "LOW",
  "summary": "<2-7 sentence plain English explanation>",
  "recommendedAction": "ALLOW" | "MONITOR" | "BLOCK" | "ESCALATE",
  "keyIndicators": ["<indicator 1>", "<indicator 2>", "<indicator 3>"],
  "analystNotes": "<additional context for human analyst>",
  "threatCategory": "<e.g. Phishing, Malware, Spam, Clean, Unknown>"
}

SCORING — the riskScore MUST determine the verdict using these exact bands:
0-20:   verdict = "CLEAN"      (no credible threat indicators)
21-60:  verdict = "SUSPICIOUS" (some indicators present, not conclusive)
61-100: verdict = "MALICIOUS"  (multiple independent severe indicators present)

Do NOT under-call a verdict. If two or more of the following co-occur, the
riskScore MUST be 61 or higher and verdict MUST be "MALICIOUS":
- Brand impersonation / typosquatting / homoglyph substitution AND
- Multiple threat intelligence engine detections (VirusTotal, Safe Browsing,
  AbuseIPDB) OR a suspicious/free TLD (.tk, .ml, .ga, .cf, .xyz) OR a
  domain registered fewer than 30 days ago

A SUSPICIOUS verdict is reserved for cases with only ONE weak or ambiguous
indicator (e.g. a single low-confidence detection with no corroborating signal).
When in doubt between SUSPICIOUS and MALICIOUS with multiple corroborating
indicators present, choose MALICIOUS — this platform is conservative by design
and a false MALICIOUS is preferable to a missed threat.
`;

const analyseThreat = async (target, scanType, intelligenceData) => {
  try {
    const completion = await groq.chat.completions.create({
      model      : 'llama-3.3-70b-versatile',
      messages   : [
        { role: 'system', content: SYSTEM_PROMPT },
        {
          role   : 'user',
          content: `TARGET: ${target}\nSCAN TYPE: ${scanType.toUpperCase()}\nTIMESTAMP: ${new Date().toISOString()}\n\nINTELLIGENCE DATA:\n${JSON.stringify(intelligenceData, null, 2)}\n\nProvide your JSON assessment now.`
        }
      ],
      temperature: 0.1,
      max_tokens : 1024
    });

    const raw        = completion.choices[0]?.message?.content || '';
    const clean      = raw.replace(/```json/g, '').replace(/```/g, '').trim();
    const assessment = JSON.parse(clean);

    const required = ['verdict','riskScore','confidenceLevel','summary','recommendedAction','keyIndicators'];
    const missing  = required.filter(f => !(f in assessment));
    if (missing.length) throw new Error(`Missing fields: ${missing.join(', ')}`);

    // ── MITRE ATT&CK mapping ──────────────────
    // Runs AFTER the AI assessment is validated.
    // Uses the raw intelligenceData passed in.
    const intel = intelligenceData.intelligence || intelligenceData;
    const mitre = mapToATTACK(scanType, intel);
    // ─────────────────────────────────────────

    return {
      source          : 'GroqAI_LLaMA3',
      model           : 'llama-3.3-70b-versatile',
      ...assessment,
      mitre            // ← attached here, always present
    };

  } catch (error) {
    // ── Fallback on AI failure ────────────────
    // Still attempt MITRE mapping from raw data
    let mitre = { techniques: [], findings: [], tacticsSummary: [] };
    try {
      const intel = intelligenceData.intelligence || intelligenceData;
      mitre = mapToATTACK(scanType, intel);
    } catch { /* silent — mitre is optional */ }
    // ─────────────────────────────────────────

    return {
      source           : 'GroqAI_LLaMA3',
      error            : true,
      message          : error.message,
      verdict          : 'UNKNOWN',
      riskScore        : -1,
      confidenceLevel  : 'LOW',
      summary          : 'AI analysis could not be completed. Manual review required.',
      recommendedAction: 'MONITOR',
      keyIndicators    : [],
      analystNotes     : 'Automated analysis failed — escalate to human analyst.',
      threatCategory   : 'Unknown',
      mitre             // ← still attached even on AI failure
    };
  }
};

module.exports = { analyseThreat };