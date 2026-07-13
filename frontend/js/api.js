// ─────────────────────────────────────────────
// api.js — All communication with the backend
// lives here. The UI never talks to the backend
// directly — it goes through these functions.
// This is the "service layer" pattern.
// ─────────────────────────────────────────────

const API_BASE = 'https://cybershield-backend-irzr.onrender.com/api';

// ─────────────────────────────────────────────
// scanUrl()
// Sends a URL to the backend for threat analysis
// Returns the full response object or throws
// ─────────────────────────────────────────────

async function scanUrl(url) {
  const response = await fetch(`${API_BASE}/scan-url`, {
    method : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body   : JSON.stringify({ url })
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error || 'URL scan request failed');
  }

  return response.json();
}

// ─────────────────────────────────────────────
// scanIp()
// Sends an IP address to the backend
// ─────────────────────────────────────────────

async function scanIp(ip) {
  const response = await fetch(`${API_BASE}/scan-ip`, {
    method : 'POST',
    headers: { 'Content-Type': 'application/json' },
    body   : JSON.stringify({ ip })
  });

  if (!response.ok) {
    const err = await response.json();
    throw new Error(err.error || 'IP scan request failed');
  }

  return response.json();
}