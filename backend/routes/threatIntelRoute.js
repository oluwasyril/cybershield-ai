// ─────────────────────────────────────────────
// routes/threatIntel.js
// GET /api/threat-intel
// Returns live threat intelligence briefings
// ─────────────────────────────────────────────

const express          = require('express');
const router           = express.Router();
const { getThreatIntel } = require('../services/threatIntel');

router.get('/', async (req, res) => {
  try {
    const briefings = await getThreatIntel();
    res.json({
      success   : true,
      count     : briefings.length,
      cachedAt  : new Date().toISOString(),
      briefings
    });
  } catch (err) {
    console.error('[ThreatIntel Route]', err.message);
    res.status(500).json({ success: false, error: 'Failed to fetch threat intelligence' });
  }
});

module.exports = router;