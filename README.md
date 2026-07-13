# CyberShield AI

AI-powered cyber threat detection and response platform built as an MSc Cybersecurity dissertation project at the University of Roehampton, London (2026).

**Live platform:** https://mycybershieldai.web.app

---

## Overview

CyberShield AI automates the detection and triage of cyber threats for small and medium-sized organisations that do not have dedicated security teams. It accepts indicators of compromise (IOCs) across five scanner types, queries multiple threat intelligence APIs in parallel, and uses the LLaMA 3.3-70B large language model to produce a structured verdict with plain-English reasoning. Confirmed MALICIOUS verdicts trigger an automated email alert, closing the detect-to-respond loop without specialist intervention.

---

## Features

- **Domain and URL Intelligence** - VirusTotal, Google Safe Browsing, TLS certificate analysis, RDAP domain registration, typosquatting detection (Levenshtein distance + homoglyph normalisation against 45 known brands)
- **IP Reputation Scanner** - AbuseIPDB confidence scoring, ASN lookup, bulletproof hosting detection
- **Email Address Scanner** - AbstractAPI Email Reputation, disposable email detection, breach history, domain IP abuse check
- **File Hash Scanner** - VirusTotal file report via MD5, SHA1, or SHA256 hash (no file upload required)
- **Email Header Analyser** - SPF, DKIM, DMARC authentication analysis, spoofing detection, embedded URL extraction
- **Bulk IOC Scanner** - Up to 10 simultaneous IOC submissions with automatic type detection
- **AI Classification** - LLaMA 3.3-70B via Groq API producing MALICIOUS, SUSPICIOUS, or CLEAN verdicts with reasoning summaries and MITRE ATT&CK technique mappings
- **Automated Alerts** - SendGrid email alerts on every MALICIOUS verdict (NIST CSF RS.CO-3)
- **Audit Logging** - ISO 27001 A.8.15 compliant logging to Firestore with scan-to-alert latency tracking
- **SOC Dashboard** - Live threat ticker, 7-day risk trend chart, environment posture grid, verdict-filtered scan history

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML, Alpine.js 3, Tailwind CSS |
| Backend | Node.js 20, Express 4 |
| Database | Google Firestore |
| Authentication | Firebase Auth |
| AI Inference | Groq API, LLaMA 3.3-70B |
| Threat Intelligence | VirusTotal v3, AbuseIPDB v2, Google Safe Browsing v4, AbstractAPI |
| Email | SendGrid |
| Hosting | Firebase Hosting (frontend), Render (backend) |

---

## Security Controls

- Token-based authentication via Firebase Auth on all routes (OWASP A07)
- Server-side input validation for all IOC types (OWASP A03)
- Three-tier rate limiting: 200/15min global, 30/15min scan, 10/15min auth (OWASP A04)
- All API keys stored as server-side environment variables, never transmitted to client (OWASP A02)
- Firestore audit logging with non-repudiation (ISO 27001 A.8.15)
- CORS restricted to Firebase Hosting origin only

---

## Project Structure

```
cybershield-ai/
  frontend/
    index.html          - Sign in page
    signup.html         - Registration page
    action.html         - Email verification and password reset handler
    dashboard.html      - Main SOC dashboard (all five scanners)
    404.html            - Error page
    css/
      style.css         - Platform design system and component styles
      tailwind.css      - Compiled Tailwind utility classes
    js/
      auth.js           - Firebase authentication logic
      api.js            - Backend API service layer
      app.js            - Alpine.js application state
      firebase-config.js - Firebase project configuration
  backend/
    server.js           - Express entry point, rate limiting, CORS
    routes/
      scan.js           - Individual scanner route handlers
      bulkScan.js       - Bulk IOC scanner with auto type detection
      saveScan.js       - Scan persistence to Firestore
      user.js           - Profile management and email routes
      auditLog.js       - Audit log API endpoints
    middleware/
      authenticate.js   - Firebase token verification
      validateInput.js  - Server-side IOC format validation
      auditLog.js       - Firestore audit logging with RQ3 latency tracking
    services/
      groqAnalysis.js   - LLaMA 3.3-70B classification engine
      domainScanner.js  - Domain and URL intelligence (4 sources parallel)
      emailScanner.js   - Email address reputation scanner
      hashScanner.js    - File hash threat intelligence
      headerAnalyser.js - Email header authentication analyser
      alertService.js   - SendGrid threat alert emails
      emailService.js   - SendGrid verification and reset emails
      mitreMapper.js    - MITRE ATT&CK Enterprise v14 technique mapping
      ruleBasedClassifier.js - Rule-based baseline classifier (evaluation)
      urlAnalyser.js    - Typosquatting and URL behaviour analysis
      asnIntelligence.js - ASN lookup and bulletproof hosting detection
      threatEnricher.js - Post-classification enrichment
```

---

## Environment Variables

The following environment variables must be configured on Render (backend) and are never committed to this repository:

```
GROQ_API_KEY
VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY
GOOGLE_SAFE_BROWSING_API_KEY
ABSTRACT_API_KEY
SENDGRID_API_KEY
EMAIL_FROM
EMAIL_FROM_NAME
FRONTEND_URL
FIREBASE_SERVICE_ACCOUNT
```

---

## Academic Context

This platform was built as the primary artefact for an MSc Cybersecurity dissertation at the University of Roehampton (2026), following the Design Science Research (DSR) methodology. The evaluation compares the LLM-based classification engine against a rule-based baseline across 70 labelled samples spanning all five scanner types, measuring precision, recall, and F1-score.

**Supervisor:** Liam Harcourt, University of Roehampton

**Research questions addressed:**
- RQ1: Can an LLM-driven classification engine produce threat verdicts comparable in accuracy to a rule-based baseline?
- RQ2: What architectural patterns best support real-time threat detection within free-tier infrastructure constraints?
- RQ3: To what extent can automated alerting reduce elapsed time between threat detection and operator awareness?
- RQ4: How should threat intelligence outputs be presented so non-specialist users can act on them?

---

## Frameworks and Standards

- NIST Cybersecurity Framework 2.0 (Detect and Respond functions)
- OWASP Top 10 (2021)
- MITRE ATT&CK Enterprise v14
- ISO/IEC 27001:2022 Annex A.8.15

---

*MSc Cybersecurity - University of Roehampton, London - 2026*
