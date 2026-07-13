// ─────────────────────────────────────────────
// emailService.js - SendGrid branded emails
// CyberShield AI - MSc Cybersecurity
// University of Roehampton 2026
//
// Design: Professional white email
//   Background : #FFFFFF card on #F4F4F4
//   Accent bar : #DC2626 crimson (top strip)
//   Verify CTA : #16A34A green
//   Reset CTA  : #DC2626 crimson
//   Text       : #111111 / #444444 / #777777
// ─────────────────────────────────────────────

const sgMail = require('@sendgrid/mail');

sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const FROM = {
  email: process.env.EMAIL_FROM,
  name : process.env.EMAIL_FROM_NAME || 'CyberShield AI'
};

// ─────────────────────────────────────────────
// BASE TEMPLATE
// ─────────────────────────────────────────────

const baseTemplate = (content) => `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>CyberShield AI</title>
</head>
<body style="margin:0;padding:0;background:#F4F4F4;font-family:Arial,Helvetica,sans-serif;">

  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F4F4F4;padding:40px 20px;">
    <tr>
      <td align="center">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:540px;">

          <!-- Card -->
          <tr>
            <td style="background:#FFFFFF;border-radius:6px;border:1px solid #E5E5E5;overflow:hidden;">

              <!-- Crimson top bar -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:#DC2626;height:4px;font-size:0;line-height:0;">&nbsp;</td>
                </tr>
              </table>

              <!-- Logo header -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:28px 36px 20px;border-bottom:1px solid #F0F0F0;">
                    <table cellpadding="0" cellspacing="0">
                      <tr>
                        <td style="background:#DC2626;border-radius:5px;width:28px;height:28px;text-align:center;vertical-align:middle;">
                          <img src="https://mycybershieldai.web.app/favicon.ico" width="14" height="14" alt="CyberShield AI" style="display:block;margin:0 auto;" onerror="this.style.display='none'"/>
                        </td>
                        <td style="padding-left:10px;vertical-align:middle;">
                          <span style="font-size:15px;font-weight:700;color:#111111;letter-spacing:0.01em;">CyberShield AI</span>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
              </table>

              <!-- Body content -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="padding:32px 36px 28px;">
                    ${content}
                  </td>
                </tr>
              </table>

              <!-- Footer -->
              <table width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="background:#FAFAFA;border-top:1px solid #F0F0F0;padding:20px 36px;text-align:center;">
                    <p style="margin:0;font-size:11px;color:#AAAAAA;line-height:1.8;">
                      CyberShield AI &nbsp;&middot;&nbsp; University of Roehampton &nbsp;&middot;&nbsp; 2026<br/>
                      This is an automated message, please do not reply.
                    </p>
                  </td>
                </tr>
              </table>

            </td>
          </tr>

          <!-- Bottom spacer -->
          <tr><td style="height:24px;"></td></tr>

        </table>
      </td>
    </tr>
  </table>

</body>
</html>
`;

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────

const ctaButton = (text, url, color, textColor = '#FFFFFF') => `
  <table cellpadding="0" cellspacing="0" style="margin:24px 0 20px;">
    <tr>
      <td style="background:${color};border-radius:5px;">
        <a href="${url}"
          style="display:inline-block;padding:13px 28px;font-size:14px;font-weight:600;color:${textColor};text-decoration:none;border-radius:5px;letter-spacing:0.01em;">
          ${text}
        </a>
      </td>
    </tr>
  </table>
`;

const noteBox = (boldText, boldColor, bodyText) => `
  <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:12px;">
    <tr>
      <td style="background:#FAFAFA;border:1px solid #EEEEEE;border-radius:5px;padding:12px 16px;">
        <p style="margin:0;font-size:12px;color:#666666;line-height:1.7;">
          ${boldText ? `<strong style="color:${boldColor};">${boldText}</strong> ` : ''}${bodyText}
        </p>
      </td>
    </tr>
  </table>
`;

const divider = () => `<table width="100%" cellpadding="0" cellspacing="0" style="margin:20px 0;"><tr><td style="border-top:1px solid #F0F0F0;font-size:0;line-height:0;">&nbsp;</td></tr></table>`;

// ─────────────────────────────────────────────
// SEND HELPER
// ─────────────────────────────────────────────

const send = async ({ to, subject, html }) => {
  try {
    await sgMail.send({ from: FROM, to, subject, html });
    console.log(`[EMAIL] Sent "${subject}" to ${to}`);
    return { success: true };
  } catch (error) {
    const msg = error.response?.body?.errors?.[0]?.message || error.message;
    console.error(`[EMAIL ERROR] ${msg}`);
    return { success: false, error: msg };
  }
};

// ─────────────────────────────────────────────
// VERIFICATION EMAIL
// Green CTA - confirms safe, positive action
// ─────────────────────────────────────────────

const sendVerificationEmail = async ({ to, firstName, verificationLink }) => {
  const content = `
    <h1 style="margin:0 0 14px;font-size:22px;font-weight:700;color:#111111;line-height:1.2;">
      Welcome, ${firstName}.
    </h1>

    <p style="margin:0 0 10px;font-size:14px;color:#444444;line-height:1.75;">
      Thanks for creating your CyberShield AI account. To get started, please verify your email address.
    </p>

    <p style="margin:0;font-size:13px;color:#777777;line-height:1.75;">
      Click the button below. This link is valid for 24 hours.
    </p>

    ${ctaButton('Verify email address', verificationLink, '#16A34A')}

    ${noteBox('Didn\'t create an account?', '#DC2626', 'You can safely ignore this email. No action is needed and your email will not be added to any mailing list.')}

    ${divider()}

    <p style="margin:0;font-size:11px;color:#AAAAAA;line-height:1.7;">
      If the button above does not work, copy and paste this link into your browser:<br/>
      <span style="color:#999999;word-break:break-all;">${verificationLink}</span>
    </p>
  `;

  return send({
    to,
    subject: `Verify your email address, ${firstName}`,
    html   : baseTemplate(content)
  });
};

// ─────────────────────────────────────────────
// PASSWORD RESET EMAIL
// Crimson CTA - signals urgency and security
// ─────────────────────────────────────────────

const sendPasswordResetEmail = async ({ to, firstName, resetLink }) => {
  const content = `
    <h1 style="margin:0 0 14px;font-size:22px;font-weight:700;color:#111111;line-height:1.2;">
      Password reset request.
    </h1>

    <p style="margin:0 0 10px;font-size:14px;color:#444444;line-height:1.75;">
      We received a request to reset the password for your CyberShield AI account associated with this email address.
    </p>

    <p style="margin:0;font-size:13px;color:#777777;line-height:1.75;">
      Click below to set a new password. This link expires in 1 hour.
    </p>

    ${ctaButton('Reset my password', resetLink, '#DC2626')}

    ${noteBox('Security notice:', '#92400E', 'Never share this link with anyone. CyberShield AI staff will never ask for this link or your password.')}

    ${noteBox('Didn\'t request this?', '#DC2626', 'Your password has not been changed. You can safely ignore this email.')}

    ${divider()}

    <p style="margin:0;font-size:11px;color:#AAAAAA;line-height:1.7;">
      If the button above does not work, copy and paste this link into your browser:<br/>
      <span style="color:#999999;word-break:break-all;">${resetLink}</span>
    </p>
  `;

  return send({
    to,
    subject: `Reset your CyberShield AI password`,
    html   : baseTemplate(content)
  });
};

module.exports = { sendVerificationEmail, sendPasswordResetEmail };