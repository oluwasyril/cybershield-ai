// ─────────────────────────────────────────────────────────────────
// auditLog.js — Audit Logging Middleware
// CyberShield AI — MSc Cybersecurity
// University of Roehampton, London 2026
//
// Academic reference:
//  - ISO/IEC 27001:2022 Control A.8.15 — Logging
//  - GDPR Article 30 — Records of processing activities
//  - NIST SP 800-92 — Guide to Computer Security Log Management
//
// Logs every significant platform action to Firestore:
//  - Scan requests (all scanner types)
//  - Profile updates
//  - Scan deletions
//
// LATENCY TRACKING (added for proposal RQ3):
//  "RQ3 is measured by logging the elapsed time from scan
//   completion to email alert delivery."
//  logScan() now accepts an optional scanStartTime and the
//  alert delivery promise resolution time is captured separately
//  in alertService.js, then merged into the same log entry.
// ─────────────────────────────────────────────────────────────────

const { db } = require('../services/firebase');

// ─────────────────────────────────────────────
// Core log writer — writes to Firestore
// Non-blocking: uses .catch() so a Firestore
// write failure never breaks the scan response
// ─────────────────────────────────────────────
async function writeAuditLog(entry) {
  try {
    await db.collection('auditLogs').add({
      ...entry,
      timestamp: new Date().toISOString(),
      createdAt: new Date()
    });
  } catch (err) {
    console.error('[AUDIT LOG ERROR]', err.message);
  }
}

// ─────────────────────────────────────────────
// Helper — extract real IP from request
// ─────────────────────────────────────────────
function getClientIP(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.connection?.remoteAddress ||
    'unknown'
  );
}

// ─────────────────────────────────────────────
// logScan — logs a completed scan
//
// scanStartTime: Date.now() captured at the start of the route
// handler — used to compute scan duration in milliseconds.
// This is the "scan completion" half of the RQ3 latency metric.
// ─────────────────────────────────────────────
async function logScan(req, scanType, target, verdict, riskScore, status = 'SUCCESS', scanStartTime = null) {
  const userId       = req.user?.uid || 'anonymous';
  const scanDuration = scanStartTime ? (Date.now() - scanStartTime) : null;

  await writeAuditLog({
    userId,
    action       : `SCAN_${scanType.toUpperCase()}`,
    target       : target || 'unknown',
    verdict      : verdict || null,
    riskScore    : riskScore || null,
    scanDurationMs: scanDuration,
    ip           : getClientIP(req),
    userAgent    : req.headers['user-agent'] || 'unknown',
    status
  });

  // Return the log timestamp so alertService can reference it
  // for scan-to-alert latency calculation
  return { scanCompletedAt: Date.now(), scanDurationMs: scanDuration };
}

// ─────────────────────────────────────────────
// logAlertLatency — logs the gap between scan
// completion and alert email delivery (RQ3 metric)
//
// Called from alertService.js after sgMail.send() resolves.
// ─────────────────────────────────────────────
async function logAlertLatency(req, scanType, target, scanCompletedAt, alertSent = true) {
  const userId      = req.user?.uid || 'anonymous';
  const alertSentAt = Date.now();
  const latencyMs    = scanCompletedAt ? (alertSentAt - scanCompletedAt) : null;

  await writeAuditLog({
    userId,
    action        : 'ALERT_LATENCY',
    target        : target || 'unknown',
    scanType,
    alertSent,
    latencyMs,
    ip            : getClientIP(req),
    status        : alertSent ? 'SUCCESS' : 'FAILED'
  });

  if (latencyMs !== null) {
    console.log(`[LATENCY] Scan-to-alert: ${latencyMs}ms — ${scanType}: ${target}`);
  }

  return latencyMs;
}

// ─────────────────────────────────────────────
// logAction — logs any other platform action
// ─────────────────────────────────────────────
async function logAction(req, action, target = null, status = 'SUCCESS') {
  const userId = req.user?.uid || 'anonymous';
  await writeAuditLog({
    userId,
    action,
    target   : target || null,
    verdict  : null,
    riskScore: null,
    ip       : getClientIP(req),
    userAgent: req.headers['user-agent'] || 'unknown',
    status
  });
}

module.exports = { logScan, logAction, logAlertLatency, writeAuditLog };