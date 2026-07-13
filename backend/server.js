// ─────────────────────────────────────────────────────────────────
// server.js — CyberShield AI Backend Entry Point
// MSc Cybersecurity — University of Roehampton 2026
// ─────────────────────────────────────────────────────────────────

const express    = require('express');
const cors       = require('cors');
const rateLimit  = require('express-rate-limit');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─────────────────────────────────────────────
// TRUST PROXY — required for Render deployment
//
// Render sits behind a reverse proxy and passes
// the real client IP via X-Forwarded-For headers.
// Without this, express-rate-limit throws a
// ValidationError on every request and the real
// client IP is never captured in audit logs.
//
// '1' means trust the first proxy hop (Render's
// load balancer) — the correct setting for a
// single-hop cloud deployment.
// ─────────────────────────────────────────────
app.set('trust proxy', 1);

// ─────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────
app.use(cors({
  origin: process.env.FRONTEND_URL || 'https://mycybershieldai.web.app',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '2mb' }));

// ─────────────────────────────────────────────
// RATE LIMITING — OWASP A04 Control
//
// Three tiers:
//  1. Global   — 200 requests per 15 min per IP
//  2. Scan     — 30 scan requests per 15 min per IP
//  3. Auth     — 10 requests per 15 min per IP
// ─────────────────────────────────────────────
const globalLimiter = rateLimit({
  windowMs  : 15 * 60 * 1000,
  max       : 200,
  standardHeaders: true,
  legacyHeaders  : false,
  message: {
    success: false,
    error  : 'Too many requests — please wait 15 minutes before trying again.',
    code   : 'RATE_LIMIT_GLOBAL'
  }
});

const scanLimiter = rateLimit({
  windowMs  : 15 * 60 * 1000,
  max       : 30,
  standardHeaders: true,
  legacyHeaders  : false,
  message: {
    success: false,
    error  : 'Scan limit reached — you can run 30 scans per 15 minutes. Please wait before scanning again.',
    code   : 'RATE_LIMIT_SCAN'
  }
});

const authLimiter = rateLimit({
  windowMs  : 15 * 60 * 1000,
  max       : 10,
  standardHeaders: true,
  legacyHeaders  : false,
  message: {
    success: false,
    error  : 'Too many authentication attempts — please wait 15 minutes.',
    code   : 'RATE_LIMIT_AUTH'
  }
});

app.use(globalLimiter);

// ─────────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status   : 'ok',
    service  : 'CyberShield AI Backend',
    version  : '2.0.0',
    timestamp: new Date().toISOString()
  });
});

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────
const scanRoutes = require('./routes/scan');
app.use('/api', scanLimiter, scanRoutes);

const userRoutes = require('./routes/user');
app.use('/api/user', userRoutes);

const saveScanRoutes = require('./routes/saveScan');
app.use('/api/scans', saveScanRoutes);

const auditRoutes = require('./routes/auditLog');
app.use('/api/audit', auditRoutes);

const bulkScanRoutes = require('./routes/bulkScan');
app.use('/api/bulk', scanLimiter, bulkScanRoutes);

// ─────────────────────────────────────────────
// GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('[SERVER ERROR]', err.message);
  res.status(500).json({
    success: false,
    error  : 'An internal server error occurred.',
    code   : 'INTERNAL_ERROR'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error  : `Route not found: ${req.method} ${req.path}`,
    code   : 'NOT_FOUND'
  });
});

// ─────────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n╔════════════════════════════════════════╗`);
  console.log(`║   CyberShield AI Backend — v2.0.0      ║`);
  console.log(`║   Port: ${PORT}                            ║`);
  console.log(`║   Rate limiting: ACTIVE                ║`);
  console.log(`║   Trust proxy: ENABLED (Render)        ║`);
  console.log(`║   CORS origin: ${(process.env.FRONTEND_URL || 'https://mycybershieldai.web.app').slice(0,22)}  ║`);
  console.log(`╚════════════════════════════════════════╝\n`);
});