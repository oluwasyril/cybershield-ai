# CyberShield AI

> AI-powered automated cyber threat detection and response platform for small and medium-sized organisations.

[![Live Platform](https://img.shields.io/badge/Live%20Platform-mycybershieldai.web.app-DC2626?style=flat-square)](https://mycybershieldai.web.app)
[![Backend](https://img.shields.io/badge/Backend-Render-0A0A0A?style=flat-square)](https://cybershield-backend-irzr.onrender.com)
[![Status](https://img.shields.io/badge/Status-Live-16A34A?style=flat-square)](#)
[![Node](https://img.shields.io/badge/Node.js-20-339933?style=flat-square)](#)
[![AI](https://img.shields.io/badge/AI-LLaMA%203.3--70B-7C3AED?style=flat-square)](#)

---

## What is CyberShield AI?

CyberShield AI gives small businesses access to enterprise-grade threat intelligence without requiring a dedicated security team. Analysts and non-specialists alike can submit any suspicious indicator — a domain, IP address, email address, file hash, or raw email headers — and receive a structured verdict within seconds, backed by multiple threat intelligence APIs and a large language model.

When a confirmed threat is detected, an automated alert is dispatched immediately, closing the detect-to-respond loop without any manual intervention.

**The platform is live and fully operational at [mycybershieldai.web.app](https://mycybershieldai.web.app)**

---

## Key Features

### Five Threat Intelligence Scanners

| Scanner | What It Does |
|---|---|
| Domain & URL Intelligence | VirusTotal, Google Safe Browsing, TLS/SSL certificate grading, WHOIS registration, typosquatting detection against 45 known brands |
| IP Reputation | AbuseIPDB confidence scoring, geolocation, ASN lookup, bulletproof hosting detection, Tor exit node identification |
| Email Address | Breach history lookup, disposable email detection, deliverability analysis, DMARC/SPF/DKIM policy checks, domain IP abuse scoring |
| File Hash | VirusTotal scan across 70+ AV engines via MD5, SHA1, or SHA256 — no file upload required |
| Email Header Analyser | SPF, DKIM, DMARC authentication parsing, sender IP reputation, spoofing detection, embedded phishing URL extraction |

### AI Classification Engine
- **Model:** LLaMA 3.3-70B via Groq API
- **Output:** Structured verdict (MALICIOUS / SUSPICIOUS / CLEAN) with confidence level, plain-English reasoning, recommended action, and key indicators
- **MITRE ATT&CK:** Automatic technique mapping against Enterprise v14 with reasoning for each mapped technique
- **Risk Scoring:** 0–100 risk score with breakdown of every contributing factor

### Bulk IOC Scanner
- Submit up to 10 indicators in one request
- Automatic type detection — mix domains, IPs, emails, and hashes in the same batch
- Summary dashboard showing verdict distribution across the batch
- Exportable as CSV or full PDF report

### SOC Dashboard
- Live threat intelligence ticker with paginated briefings
- 7-day scan activity and risk trend charts with daily, weekly, monthly, and custom date ranges
- Environment posture grid showing average risk score and active threat count
- Verdict-filtered scan history with expand-in-place full report view

### Automated Response
- SendGrid email alerts dispatched on every MALICIOUS verdict (NIST CSF RS.CO-3)
- Scan-to-alert latency tracked and logged for performance evaluation
- Alerts include full verdict details, risk score, recommended action, and key indicators

### PDF Threat Reports
- Downloadable branded PDF report for every scan
- Includes verdict, risk breakdown, AI summary, MITRE ATT&CK mappings, and all scanner-specific intelligence
- Bulk scan reports exported as A4 landscape summary tables

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, Alpine.js 3, Tailwind CSS, Chart.js |
| Backend | Node.js 20, Express 4 |
| Database | Google Firestore |
| Authentication | Firebase Auth |
| Hosting | Firebase Hosting (frontend), Render (backend) |
| AI Inference | Groq API — LLaMA 3.3-70B |
| Threat Intelligence | VirusTotal v3, AbuseIPDB v2, Google Safe Browsing v4, AbstractAPI |
| Email | SendGrid |

---

## Security Architecture

| Control | Implementation |
|---|---|
| Authentication | Firebase Auth JWT token verification on every backend route |
| Input Validation | Server-side IOC format validation for all five scanner types (OWASP A03) |
| Rate Limiting | Three-tier: 200 req/15min global, 30 req/15min scan, 10 req/15min auth (OWASP A04) |
| Secret Management | All API keys as server-side environment variables, never exposed to client (OWASP A02) |
| Audit Logging | Immutable Firestore audit log with timestamp, user ID, scan type, verdict, and latency (ISO 27001 A.8.15) |
| CORS | Restricted to Firebase Hosting origin only |
| Trust Proxy | Configured for accurate client IP extraction behind Render's reverse proxy |

---

## Project Structure

```
cybershield-ai/
├── frontend/
│   ├── index.html                  Sign-in page
│   ├── signup.html                 Registration page
│   ├── dashboard.html              Main SOC dashboard — all five scanners
│   ├── action.html                 Email verification and password reset handler
│   ├── 404.html                    Error page
│   ├── css/
│   │   ├── style.css               Platform design system and component styles
│   │   └── tailwind.css            Compiled Tailwind utility classes
│   └── js/
│       ├── auth.js                 Firebase authentication logic
│       ├── api.js                  Backend API service layer
│       └── firebase-config.js      Firebase project configuration
│
└── backend/
    ├── server.js                   Express entry point, rate limiting, CORS, trust proxy
    ├── routes/
    │   ├── scan.js                 Individual scanner route handlers
    │   ├── bulkScan.js             Bulk IOC scanner with automatic type detection
    │   ├── saveScan.js             Scan persistence to Firestore
    │   ├── user.js                 Profile management and scan history routes
    │   └── auditLog.js             Audit log API endpoints
    ├── middleware/
    │   ├── authenticate.js         Firebase token verification middleware
    │   ├── validateInput.js        Server-side IOC format validation
    │   └── auditLog.js             Firestore audit logging with latency tracking
    └── services/
        ├── groqAnalysis.js         LLaMA 3.3-70B classification engine
        ├── domainScanner.js        Domain and URL intelligence — 4 sources in parallel
        ├── emailScanner.js         Email address reputation scanner
        ├── hashScanner.js          File hash threat intelligence
        ├── headerAnalyser.js       Email header authentication analyser
        ├── alertService.js         SendGrid threat alert emails
        ├── emailService.js         SendGrid account verification and reset emails
        ├── mitreMapper.js          MITRE ATT&CK Enterprise v14 technique mapping
        ├── ruleBasedClassifier.js  Rule-based baseline classifier for evaluation
        ├── urlAnalyser.js          Typosquatting and URL behaviour analysis
        ├── asnIntelligence.js      ASN lookup and bulletproof hosting detection
        └── threatEnricher.js       Post-classification enrichment pipeline
```

---

## Getting Started

### Prerequisites
- Node.js 20+
- Firebase project with Firestore and Authentication enabled
- API keys for VirusTotal, AbuseIPDB, Google Safe Browsing, AbstractAPI, Groq, and SendGrid

### Backend Setup

```bash
git clone https://github.com/oluwasyril/cybershield-ai.git
cd cybershield-ai/backend
npm install
```

Create a `.env` file in the backend directory:

```env
GROQ_API_KEY=your_key
VIRUSTOTAL_API_KEY=your_key
ABUSEIPDB_API_KEY=your_key
GOOGLE_SAFE_BROWSING_API_KEY=your_key
ABSTRACT_API_KEY=your_key
SENDGRID_API_KEY=your_key
EMAIL_FROM=alerts@yourdomain.com
EMAIL_FROM_NAME=CyberShield AI
FRONTEND_URL=https://mycybershieldai.web.app
FIREBASE_SERVICE_ACCOUNT={"type":"service_account",...}
```

```bash
npm start
```

### Frontend Setup

```bash
cd ../frontend
```

Update `js/firebase-config.js` with your Firebase project credentials, then deploy:

```bash
firebase deploy
```

---

## Environment Variables

All secrets are stored server-side and never committed to this repository.

| Variable | Purpose |
|---|---|
| `GROQ_API_KEY` | LLaMA 3.3-70B inference via Groq |
| `VIRUSTOTAL_API_KEY` | Domain, URL, and file hash scanning |
| `ABUSEIPDB_API_KEY` | IP reputation and abuse scoring |
| `GOOGLE_SAFE_BROWSING_API_KEY` | Malware and phishing URL detection |
| `ABSTRACT_API_KEY` | Email reputation and breach history |
| `SENDGRID_API_KEY` | Threat alert and account emails |
| `EMAIL_FROM` | Sender address for outbound emails |
| `EMAIL_FROM_NAME` | Display name for outbound emails |
| `FRONTEND_URL` | CORS origin whitelist |
| `FIREBASE_SERVICE_ACCOUNT` | Firestore and Firebase Admin SDK credentials |

---

## Evaluation Results

Evaluated against a labelled dataset of 70 samples across all five scanner types, comparing the LLM-based classifier against a rule-based baseline.

| Scanner | Samples | AI F1 | Baseline F1 | Delta |
|---|---|---|---|---|
| Email Header | 11 | 90.3% | 90.3% | Tied |
| IP Reputation | 14 | 76.2% | 58.2% | +18.0pp |
| Domain & URL | 24 | 66.7% | 59.2% | +7.5pp |
| File Hash | 10 | 66.7% | 66.7% | Tied |
| Email Address | 11 | 47.2% | 54.5% | -7.3pp |

The IP scanner showed the strongest improvement (+18pp). The email address scanner underperformed the baseline — an honest finding documented transparently in the dissertation. The header analyser achieved 90.3% on both approaches, reflecting the deterministic nature of SPF/DKIM/DMARC authentication.

---

## Compliance and Standards

| Standard | Application |
|---|---|
| NIST Cybersecurity Framework 2.0 | Detect (DE.AE, DE.CM) and Respond (RS.CO-3) functions |
| OWASP Top 10 2021 | A02 Cryptographic Failures, A03 Injection, A04 Insecure Design, A07 Authentication |
| MITRE ATT&CK Enterprise v14 | Automated technique mapping on every scan verdict |
| ISO/IEC 27001:2022 | A.8.15 Logging and monitoring via Firestore audit trail |

---

## Roadmap

- [ ] Mobile-responsive dashboard layout
- [ ] Webhook integration for SIEM platforms
- [ ] Scheduled IOC monitoring with recurring automated scans
- [ ] Multi-user organisation accounts with role-based access
- [ ] REST API for programmatic IOC submission
- [ ] Threat hunting query builder

---

## Academic Context

CyberShield AI was built as the primary artefact for an MSc Cybersecurity dissertation at the University of Roehampton, London (2026), following the Design Science Research (DSR) methodology.

**Supervisor:** Liam Harcourt, University of Roehampton

**Research Questions:**
- **RQ1** — Can an LLM-driven classification engine produce threat verdicts comparable in accuracy to a rule-based baseline across multiple IOC types?
- **RQ2** — What architectural patterns best support real-time threat detection within free-tier infrastructure constraints?
- **RQ3** — To what extent can automated alerting reduce elapsed time between threat detection and operator notification?
- **RQ4** — How should threat intelligence outputs be structured so that non-specialist users can act on them without security training?

---

## Author

**Lekan Akinsanya**
MSc Cybersecurity — University of Roehampton, London, 2026
GitHub: [@oluwasyril](https://github.com/oluwasyril)

---

*CyberShield AI — AI-Powered Cyber Threat Detection and Response — University of Roehampton, 2026*