// ─────────────────────────────────────────────
// routes/auditLog.js — Audit Log API
// CyberShield AI — MSc Cybersecurity
// University of Roehampton, London 2026
// ─────────────────────────────────────────────

const express          = require('express');
const router           = express.Router();
const { authenticate } = require('../middleware/authenticate');
const { db }           = require('../services/firebase');

// ─────────────────────────────────────────────
// GET /api/audit/logs
// Returns the last 100 audit log entries
// for the authenticated user — sorted in JS
// to avoid composite index requirement
// ─────────────────────────────────────────────
router.get('/logs', authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;

    // Query without orderBy to avoid composite index requirement
    // Sort in JavaScript instead
    const snapshot = await db.collection('auditLogs')
      .where('userId', '==', userId)
      .limit(100)
      .get();

    const logs = snapshot.docs
      .map(doc => ({
        id       : doc.id,
        ...doc.data(),
        createdAt: doc.data().createdAt?.toDate?.()?.toISOString() || doc.data().timestamp
      }))
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({ success: true, logs, count: logs.length });

  } catch (err) {
    console.error('[AUDIT LOG GET ERROR]', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ─────────────────────────────────────────────
// GET /api/audit/summary
// ─────────────────────────────────────────────
router.get('/summary', authenticate, async (req, res) => {
  try {
    const userId = req.user.uid;

    const snapshot = await db.collection('auditLogs')
      .where('userId', '==', userId)
      .limit(500)
      .get();

    const logs = snapshot.docs
      .map(doc => doc.data())
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    const scanLogs   = logs.filter(l => l.action?.startsWith('SCAN_'));
    const deleteLogs = logs.filter(l => l.action === 'DELETE_SCAN');
    const updateLogs = logs.filter(l => l.action === 'UPDATE_PROFILE');

    const typeCounts = {};
    scanLogs.forEach(l => {
      const type = l.action.replace('SCAN_', '').toLowerCase();
      typeCounts[type] = (typeCounts[type] || 0) + 1;
    });

    const mostScanned = Object.entries(typeCounts)
      .sort((a, b) => b[1] - a[1])[0]?.[0] || null;

    res.json({
      success: true,
      summary: {
        totalScans  : scanLogs.length,
        totalDeletes: deleteLogs.length,
        totalUpdates: updateLogs.length,
        typeCounts,
        mostScanned,
        lastActive  : logs[0]?.timestamp || null
      }
    });
  } catch (err) {
    console.error('[AUDIT SUMMARY ERROR]', err.message);
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;