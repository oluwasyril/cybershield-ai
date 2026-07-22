// ─────────────────────────────────────────────
// groqAnalysis.js  -  AI Threat Assessment
// Uses Groq API (LLaMA 3) to analyse scanner
// intelligence and produce structured verdicts.
// MITRE ATT&CK mapping attached to every result.
// ─────────────────────────────────────────────

const Groq          = require('groq-sdk');
const { mapToATTACK } = require('./mitreMapper');

const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

const SYSTEM_PROMPT = `
You are an expert cybersecurity analyst inside an automated threat detection platform
used by non-technical staff at small businesses who have no security training.
Your job is to analyse threat intelligence data and explain the findings in plain,
human language that a non-specialist can understand and act on immediately.

RULES:
- Respond ONLY with valid JSON. No markdown, no text outside the JSON.
- Base verdict ONLY on the data provided.
- Be conservative: when uncertain, classify higher risk.
- Write as a real human analyst would speak to a colleague  -  clear, direct, no jargon.

RESPONSE STRUCTURE (exactly):
{
  "verdict": "CLEAN" | "SUSPICIOUS" | "MALICIOUS",
  "riskScore": <integer 0-100>,
  "confidenceLevel": "HIGH" | "MEDIUM" | "LOW",
  "summary": "<Write 4 to 6 sentences in plain English. First sentence: state clearly what this is and whether it is safe. Second sentence: explain the most important evidence that led to this conclusion. Third sentence: explain what this kind of threat does or why it matters to the user. Fourth sentence: tell the user exactly what they should do right now  -  whether that is nothing, to be cautious, or to act immediately. If MALICIOUS or SUSPICIOUS, be specific about the risk.>",
  "recommendedAction": "ALLOW" | "MONITOR" | "BLOCK" | "ESCALATE",
  "keyIndicators": ["<indicator 1>", "<indicator 2>", "<indicator 3>"],
  "analystNotes": "<Write 2 to 4 sentences of additional context. Explain the technical reasoning behind the verdict in a way that helps the user understand why this specific combination of signals triggered this classification. If the verdict is CLEAN, reassure the user and tell them what normal looks like. If SUSPICIOUS or MALICIOUS, explain what the attacker is likely trying to do and how to stay safe going forward.>",
  "threatCategory": "<e.g. Phishing, Malware, Spam, Clean, Unknown>"
}

SCORING  -  the riskScore MUST determine the verdict using these exact bands:
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
indicators present, choose MALICIOUS.

WRITING STYLE EXAMPLES:
- BAD: "The domain exhibits multiple threat indicators consistent with phishing activity."
- GOOD: "This domain is pretending to be PayPal but it is not. The name has been altered slightly to trick people into thinking it is real, and it was only registered 3 days ago which is a strong sign it was created specifically for fraud. Do not click any links from this domain, do not enter any passwords or payment details, and block it on your email system immediately."

- BAD: "IP address shows no malicious indicators across queried sources."
- GOOD: "This IP address looks safe. It belongs to Google's public DNS infrastructure, which is a trusted and widely used service. You do not need to take any action."
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
    let mitre = mapToATTACK(scanType, intel);
    // Only attach MITRE techniques for non-CLEAN verdicts
    if (assessment.verdict === 'CLEAN') {
      mitre = { techniques: [], findings: [], tacticsSummary: [] };
    }
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
    } catch { /* silent  -  mitre is optional */ }
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
      analystNotes     : 'Automated analysis failed  -  escalate to human analyst.',
      threatCategory   : 'Unknown',
      mitre             // ← still attached even on AI failure
    };
  }
};

module.exports = { analyseThreat };