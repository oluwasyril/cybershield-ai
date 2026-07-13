// ─────────────────────────────────────────────────────────────────
// alertService.js - Threat Alert Email Service
// CyberShield AI - MSc Cybersecurity
// University of Roehampton, London 2026
//
// Sends automated email alerts when a scan returns a
// MALICIOUS verdict, completing the detect-to-respond pipeline.
//
// Academic context:
//  - Implements the "Response" component of the platform title
//  - Maps to NIST CSF Respond function (RS.CO-3)
//  - Logs scan-to-alert latency for RQ3 evaluation:
//    "RQ3 is measured by logging the elapsed time from scan
//     completion to email alert delivery."
//
// Uses: SendGrid API (free tier: 100 emails/day)
// ─────────────────────────────────────────────────────────────────

const sgMail = require('@sendgrid/mail');
const { logAlertLatency } = require('../middleware/auditLog');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const FROM_EMAIL = process.env.EMAIL_FROM      || 'alerts@cybershieldai.com';
const FROM_NAME  = process.env.EMAIL_FROM_NAME || 'CyberShield AI';
const APP_URL    = process.env.FRONTEND_URL    || 'https://mycybershieldai.web.app';

// Verdict header colours - crimson for MALICIOUS, amber for SUSPICIOUS
const VERDICT_HEADER = {
  MALICIOUS : { bg: '#DC2626', text: '#FFFFFF' },
  SUSPICIOUS: { bg: '#D97706', text: '#FFFFFF' },
  CLEAN     : { bg: '#16A34A', text: '#FFFFFF' }
};

// Action badge colours
const ACTION_BADGE = {
  BLOCK   : { bg: '#FFF0F0', border: '#FECACA', text: '#DC2626' },
  ESCALATE: { bg: '#F5F3FF', border: '#DDD6FE', text: '#6D28D9' },
  MONITOR : { bg: '#FFFBEB', border: '#FDE68A', text: '#92400E' },
  ALLOW   : { bg: '#F0FDF4', border: '#BBF7D0', text: '#166534' }
};

// Risk bar colour
function riskColour(score) {
  if (score >= 61) return '#DC2626';
  if (score >= 30) return '#D97706';
  return '#16A34A';
}

// ─────────────────────────────────────────────
// buildAlertHTML
// ─────────────────────────────────────────────
function buildAlertHTML(scanType, target, assessment) {
  const verdict    = assessment.verdict    || 'UNKNOWN';
  const riskScore  = assessment.riskScore  || 0;
  const action     = assessment.recommendedAction || 'REVIEW';
  const vh         = VERDICT_HEADER[verdict] || VERDICT_HEADER.SUSPICIOUS;
  const ab         = ACTION_BADGE[action]   || { bg: '#F9FAFB', border: '#E5E7EB', text: '#374151' };
  const rc         = riskColour(riskScore);

  const scanTypeLabel = {
    domain: 'Domain and URL',
    ip    : 'IP Address',
    email : 'Email Address',
    header: 'Email Header',
    hash  : 'File Hash'
  }[scanType] || scanType.toUpperCase();

  const indicators = (assessment.keyIndicators || [])
    .slice(0, 5)
    .map(i => `
      <tr>
        <td style="padding:5px 0;font-size:13px;color:#444444;line-height:1.6;border-bottom:1px solid #F5F5F5;">
          <span style="color:#DC2626;margin-right:8px;font-weight:700;">+</span>${i}
        </td>
      </tr>`)
    .join('');

  const mitreItems = (assessment.mitre?.techniques || [])
    .slice(0, 3)
    .map(t => `
      <span style="display:inline-block;margin:3px 4px 3px 0;padding:4px 10px;background:#F9FAFB;border:1px solid #E5E5E5;border-radius:4px;font-size:11px;color:#555555;">
        <span style="color:#DC2626;font-weight:600;">${t.id}</span>
        <span style="color:#777777;margin-left:6px;">${t.name}</span>
      </span>`)
    .join('');

  return `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CyberShield AI - Threat Alert</title>
</head>
<body style="margin:0;padding:0;background:#F4F4F4;font-family:Arial,Helvetica,sans-serif;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F4F4F4;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;">

          <!-- Card -->
          <tr>
            <td style="background:#FFFFFF;border-radius:6px;border:1px solid #E5E5E5;overflow:hidden;">

              <!-- Top bar -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:#DC2626;height:4px;font-size:0;line-height:0;">&nbsp;</td>
                </tr>
              </table>

              <!-- Logo header -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:20px 28px 16px;border-bottom:1px solid #F0F0F0;">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="vertical-align:middle;">
                          <table cellpadding="0" cellspacing="0">
                            <tr>
                              <td style="background:#DC2626;border-radius:4px;width:26px;height:26px;text-align:center;vertical-align:middle;padding:0 6px;">
                                <span style="font-size:14px;color:#FFFFFF;font-weight:700;line-height:26px;">C</span>
                              </td>
                              <td style="padding-left:10px;vertical-align:middle;">
                                <span style="font-size:14px;font-weight:700;color:#111111;letter-spacing:0.01em;">CyberShield AI</span>
                              </td>
                            </tr>
                          </table>
                        </td>
                        <td align="right" style="vertical-align:middle;">
                          <span style="font-size:11px;font-weight:600;color:#DC2626;letter-spacing:0.06em;text-transform:uppercase;">Threat Alert</span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Verdict header -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:${vh.bg};padding:20px 28px;">
                    <table width="100%" cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="vertical-align:top;">
                          <div style="font-size:10px;color:rgba(255,255,255,0.75);letter-spacing:0.08em;text-transform:uppercase;margin-bottom:5px;">${scanTypeLabel} scan result</div>
                          <div style="font-size:22px;font-weight:700;color:#FFFFFF;line-height:1.1;">${verdict}</div>
                          <div style="font-size:12px;color:rgba(255,255,255,0.85);margin-top:5px;word-break:break-all;">${target}</div>
                        </td>
                        <td align="right" style="vertical-align:top;">
                          <div style="font-size:36px;font-weight:700;color:#FFFFFF;line-height:1;">${riskScore}</div>
                          <div style="font-size:10px;color:rgba(255,255,255,0.7);margin-top:2px;">/ 100 risk</div>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Body -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:24px 28px;">

                    <!-- Recommended action -->
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;padding-bottom:20px;border-bottom:1px solid #F0F0F0;">
                      <tr>
                        <td>
                          <div style="font-size:10px;color:#999999;letter-spacing:0.06em;text-transform:uppercase;font-weight:600;margin-bottom:8px;">Recommended action</div>
                          <span style="display:inline-block;padding:6px 16px;background:${ab.bg};border:1px solid ${ab.border};border-radius:4px;font-size:12px;font-weight:700;color:${ab.text};letter-spacing:0.04em;">${action}</span>
                        </td>
                      </tr>
                    </table>

                    <!-- AI Summary -->
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;padding-bottom:20px;border-bottom:1px solid #F0F0F0;">
                      <tr>
                        <td>
                          <div style="font-size:10px;color:#999999;letter-spacing:0.06em;text-transform:uppercase;font-weight:600;margin-bottom:8px;">AI analyst summary</div>
                          <p style="margin:0;font-size:13px;color:#444444;line-height:1.75;">${assessment.summary || 'No summary available.'}</p>
                        </td>
                      </tr>
                    </table>

                    <!-- Key indicators -->
                    ${indicators ? `
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;padding-bottom:20px;border-bottom:1px solid #F0F0F0;">
                      <tr>
                        <td>
                          <div style="font-size:10px;color:#999999;letter-spacing:0.06em;text-transform:uppercase;font-weight:600;margin-bottom:8px;">Key indicators</div>
                          <table width="100%" cellpadding="0" cellspacing="0">
                            ${indicators}
                          </table>
                        </td>
                      </tr>
                    </table>` : ''}

                    <!-- MITRE -->
                    ${mitreItems ? `
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:20px;padding-bottom:20px;border-bottom:1px solid #F0F0F0;">
                      <tr>
                        <td>
                          <div style="font-size:10px;color:#999999;letter-spacing:0.06em;text-transform:uppercase;font-weight:600;margin-bottom:8px;">MITRE ATT&CK techniques</div>
                          <div>${mitreItems}</div>
                        </td>
                      </tr>
                    </table>` : ''}

                    <!-- Risk score bar -->
                    <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px;">
                      <tr>
                        <td>
                          <div style="font-size:10px;color:#999999;letter-spacing:0.06em;text-transform:uppercase;font-weight:600;margin-bottom:8px;">Risk score</div>
                          <div style="background:#F0F0F0;border-radius:4px;height:6px;overflow:hidden;">
                            <div style="height:100%;width:${riskScore}%;background:${rc};border-radius:4px;"></div>
                          </div>
                          <div style="font-size:12px;color:${rc};font-weight:600;margin-top:5px;">${riskScore} / 100</div>
                        </td>
                      </tr>
                    </table>

                    <!-- CTA -->
                    <table cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="background:#DC2626;border-radius:5px;">
                          <a href="${APP_URL}"
                            style="display:inline-block;padding:13px 28px;font-size:14px;font-weight:600;color:#FFFFFF;text-decoration:none;border-radius:5px;letter-spacing:0.01em;">
                            View full report
                          </a>
                        </td>
                      </tr>
                    </table>

                  </td>
                </tr>
              </table>

              <!-- Footer -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:#FAFAFA;border-top:1px solid #F0F0F0;padding:18px 28px;text-align:center;">
                    <p style="margin:0;font-size:11px;color:#AAAAAA;line-height:1.8;">
                      CyberShield AI &nbsp;&middot;&nbsp; University of Roehampton &nbsp;&middot;&nbsp; 2026<br/>
                      This is an automated message, please do not reply.
                    </p>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <tr><td style="height:24px;"></td></tr>

        </table>
      </td>
    </tr>
  </table>

</body>
</html>`;
}

// ─────────────────────────────────────────────
// sendThreatAlert - main export
// ─────────────────────────────────────────────
async function sendThreatAlert(userEmail, scanType, target, assessment, req = null, scanCompletedAt = null) {
  if (!userEmail || assessment.verdict !== 'MALICIOUS') return;

  const scanTypeLabel = {
    domain: 'Domain and URL',
    ip    : 'IP Address',
    email : 'Email Address',
    header: 'Email Header',
    hash  : 'File Hash'
  }[scanType] || scanType.toUpperCase();

  try {
    await sgMail.send({
      to     : userEmail,
      from   : { email: FROM_EMAIL, name: FROM_NAME },
      subject: `Threat detected: ${scanTypeLabel} scan returned MALICIOUS for ${target.slice(0, 50)}`,
      html   : buildAlertHTML(scanType, target, assessment),
      text   : `
CyberShield AI - Threat Alert

Verdict      : ${assessment.verdict}
Type         : ${scanTypeLabel}
Target       : ${target}
Risk Score   : ${assessment.riskScore}/100
Action       : ${assessment.recommendedAction}

Summary:
${assessment.summary}

View full report: ${APP_URL}

CyberShield AI - University of Roehampton - 2026
This is an automated message, please do not reply.
      `.trim()
    });

    console.log(`[ALERT] Threat alert sent to ${userEmail} - ${scanType}: ${target} (${assessment.verdict})`);

    if (req && scanCompletedAt) {
      await logAlertLatency(req, scanType, target, scanCompletedAt, true);
    }

    return true;

  } catch (err) {
    console.error('[ALERT ERROR]', err.message);
    if (req && scanCompletedAt) {
      await logAlertLatency(req, scanType, target, scanCompletedAt, false);
    }
    return false;
  }
}

module.exports = { sendThreatAlert };