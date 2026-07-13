const express = require('express');
const router  = express.Router();
const { db, admin }  = require('../services/firebase');
const { authenticate } = require('../middleware/authenticate');

router.post('/save', authenticate, async (req, res) => {
  const uid  = req.user.uid;
  const scan = req.body;

  if (!scan || !scan.target) {
    return res.status(400).json({ success: false, error: 'Invalid scan payload.' });
  }

  try {
    const ref = await db.collection('scans').add({
      uid,
      ...scan,
      savedAt: new Date().toISOString()
    });

    await db.collection('users').doc(uid).update({
      scanCount : admin.firestore.FieldValue.increment(1),
      lastScanAt: new Date().toISOString()
    });

    res.status(200).json({ success: true, scanId: ref.id });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

module.exports = router;