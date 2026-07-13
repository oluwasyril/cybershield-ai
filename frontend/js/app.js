// ─────────────────────────────────────────────
// app.js — Alpine.js application state and logic
//
// HOW ALPINE.js WORKS:
// cyberShieldApp() returns a plain JavaScript
// object. Alpine reads this object and makes
// every property reactive — meaning any change
// to a property automatically updates the HTML
// elements that reference it via x-data, x-model,
// x-show, x-text, etc.
// ─────────────────────────────────────────────

function cyberShieldApp() {
  return {

    // ─────────────────────────────
    // APPLICATION STATE
    // These are your reactive variables.
    // Change any of these and the UI
    // updates instantly — no DOM
    // manipulation needed.
    // ─────────────────────────────

    activeView   : 'dashboard',   // Controls which panel is visible
    urlInput     : '',            // Bound to the URL input field via x-model
    ipInput      : '',            // Bound to the IP input field via x-model
    isScanning   : false,         // Disables the scan button while loading
    currentResult: null,          // Holds the last scan result object
    errorMessage : '',            // Holds any error text to display
    scanHistory  : [],            // Array of all scans in this session
    currentTime  : '',            // Live clock in the header

    // ─────────────────────────────
    // NAVIGATION ITEMS
    // Drives the sidebar via x-for
    // ─────────────────────────────

    navItems: [
      { id: 'dashboard',   label: 'Dashboard',   icon: '[#]' },
      { id: 'url-scanner', label: 'URL Scanner',  icon: '[U]' },
      { id: 'ip-scanner',  label: 'IP Scanner',   icon: '[I]' },
      { id: 'history',     label: 'Scan History', icon: '[H]' },
    ],

    // ─────────────────────────────
    // COMPUTED: nav title + subtitle
    // ─────────────────────────────

    get currentViewTitle() {
      const titles = {
        'dashboard'  : 'Threat Operations Dashboard',
        'url-scanner': 'URL Threat Scanner',
        'ip-scanner' : 'IP Reputation Scanner',
        'history'    : 'Scan History',
      };
      return titles[this.activeView] || 'CyberShield AI';
    },

    get currentViewSubtitle() {
      const subs = {
        'dashboard'  : 'Platform overview and intelligence sources',
        'url-scanner': 'Analyse URLs against VirusTotal, Safe Browsing, and AI reasoning',
        'ip-scanner' : 'Check IP reputation via AbuseIPDB and AI analysis',
        'history'    : 'All scans performed in this session',
      };
      return subs[this.activeView] || '';
    },

    // ─────────────────────────────
    // DASHBOARD STATS
    // Dynamically computed from
    // the scan history array
    // ─────────────────────────────

    get dashboardStats() {
      const total     = this.scanHistory.length;
      const malicious = this.scanHistory.filter(s => s.assessment.verdict === 'MALICIOUS').length;
      const suspicious= this.scanHistory.filter(s => s.assessment.verdict === 'SUSPICIOUS').length;
      const clean     = this.scanHistory.filter(s => s.assessment.verdict === 'CLEAN').length;

      return [
        { label: 'TOTAL SCANS',    value: total,      color: 'text-cyber-accent',  sub: 'This session' },
        { label: 'CLEAN',          value: clean,      color: 'text-cyber-green',   sub: 'No threat detected' },
        { label: 'SUSPICIOUS',     value: suspicious, color: 'text-cyber-yellow',  sub: 'Requires monitoring' },
        { label: 'MALICIOUS',      value: malicious,  color: 'text-cyber-red',     sub: 'Immediate action' },
      ];
    },

    // ─────────────────────────────
    // LIFECYCLE: init()
    // Called automatically by Alpine
    // when the component mounts
    // ─────────────────────────────

    init() {
      // Start the live clock
      this.updateClock();
      setInterval(() => this.updateClock(), 1000);
    },

    updateClock() {
      this.currentTime = new Date().toLocaleTimeString('en-GB', {
        hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit'
      }) + ' UTC';
    },

    // ─────────────────────────────
    // SCAN ACTIONS
    // ─────────────────────────────

    async scanUrl() {
      if (!this.urlInput.trim() || this.isScanning) return;

      this.isScanning    = true;
      this.errorMessage  = '';
      this.currentResult = null;

      try {
        // [1] Call the API service function
        const result = await scanUrl(this.urlInput.trim());

        // [2] Store result — reactive update triggers UI render
        this.currentResult = result;

        // [3] Add to history
        this.scanHistory.push(result);

      } catch (error) {
        this.errorMessage = `Scan failed: ${error.message}`;
      } finally {
        // [4] Always re-enable the button
        this.isScanning = false;
      }
    },

    async scanIp() {
      if (!this.ipInput.trim() || this.isScanning) return;

      this.isScanning    = true;
      this.errorMessage  = '';
      this.currentResult = null;

      try {
        const result = await scanIp(this.ipInput.trim());
        this.currentResult = result;
        this.scanHistory.push(result);
      } catch (error) {
        this.errorMessage = `Scan failed: ${error.message}`;
      } finally {
        this.isScanning = false;
      }
    },

    // ─────────────────────────────
    // RESULT RENDERER
    // Builds the result card HTML
    // from the scan result object
    // ─────────────────────────────

    renderResult(result) {
      if (!result || !result.assessment) return '';

      const a = result.assessment;

      // Verdict colour mapping
      const verdictColors = {
        'CLEAN'     : 'text-cyber-green  border-cyber-green/30  bg-cyber-green/5',
        'SUSPICIOUS': 'text-cyber-yellow border-cyber-yellow/30 bg-cyber-yellow/5',
        'MALICIOUS' : 'text-cyber-red    border-cyber-red/30    bg-cyber-red/5',
        'UNKNOWN'   : 'text-gray-400     border-gray-600        bg-gray-800/30',
      };

      const actionColors = {
        'ALLOW'    : 'bg-cyber-green/20  text-cyber-green',
        'MONITOR'  : 'bg-cyber-yellow/20 text-cyber-yellow',
        'BLOCK'    : 'bg-cyber-red/20    text-cyber-red',
        'ESCALATE' : 'bg-purple-500/20   text-purple-400',
      };

      const riskColor = a.riskScore <= 20
        ? 'text-cyber-green'
        : a.riskScore <= 60
          ? 'text-cyber-yellow'
          : 'text-cyber-red';

      // Build key indicators list
      const indicators = (a.keyIndicators || [])
        .map(i => `<li class="text-xs font-mono text-gray-400 flex items-start gap-2">
                     <span class="text-cyber-accent mt-0.5">›</span>${i}
                   </li>`)
        .join('');

      return `
        <div class="bg-cyber-panel border ${verdictColors[a.verdict] || verdictColors['UNKNOWN']} rounded-xl p-6 space-y-5">

          <!-- Header row -->
          <div class="flex items-start justify-between">
            <div>
              <div class="text-xs font-mono text-cyber-muted mb-1">THREAT ASSESSMENT</div>
              <div class="font-mono text-2xl font-bold ${verdictColors[a.verdict]?.split(' ')[0] || 'text-gray-400'}">
                ${a.verdict}
              </div>
              <div class="text-xs text-cyber-muted mt-1 font-mono">
                Target: ${result.target} &nbsp;·&nbsp; ${result.scanType.toUpperCase()} scan
              </div>
            </div>
            <div class="text-right">
              <div class="font-mono text-4xl font-bold ${riskColor}">${a.riskScore}</div>
              <div class="text-xs text-cyber-muted font-mono">/ 100 RISK SCORE</div>
              <div class="text-xs text-cyber-muted mt-1">Confidence: ${a.confidenceLevel}</div>
            </div>
          </div>

          <!-- Recommended action -->
          <div class="flex items-center gap-3">
            <span class="text-xs font-mono text-cyber-muted">RECOMMENDED ACTION</span>
            <span class="px-3 py-1 rounded-full text-xs font-mono font-bold ${actionColors[a.recommendedAction] || ''}">
              ${a.recommendedAction}
            </span>
          </div>

          <!-- AI Summary -->
          <div class="border-t border-cyber-border pt-4">
            <div class="text-xs font-mono text-cyber-muted mb-2">AI ANALYST SUMMARY</div>
            <p class="text-sm text-gray-300 leading-relaxed">${a.summary}</p>
          </div>

          <!-- Key Indicators -->
          ${indicators ? `
          <div class="border-t border-cyber-border pt-4">
            <div class="text-xs font-mono text-cyber-muted mb-2">KEY INDICATORS</div>
            <ul class="space-y-1">${indicators}</ul>
          </div>` : ''}

          <!-- Analyst Notes -->
          ${a.analystNotes ? `
          <div class="border-t border-cyber-border pt-4">
            <div class="text-xs font-mono text-cyber-muted mb-2">ANALYST NOTES</div>
            <p class="text-xs text-gray-400 font-mono leading-relaxed">${a.analystNotes}</p>
          </div>` : ''}

          <!-- Timestamp -->
          <div class="text-xs text-cyber-muted font-mono border-t border-cyber-border pt-3">
            Scan completed: ${new Date(result.timestamp).toLocaleString('en-GB')}
            &nbsp;·&nbsp; Engine: ${a.model || 'LLaMA 3'}
          </div>
        </div>
      `;
    }

  }; // end return
} // end cyberShieldApp