/**
 * PhishGuard AI — Content Script (3-Level Security Warning & Notification System)
 * Manages exactly ONE PhishGuard UI element on the page at any time:
 * - Level 1 (SAFE): Bottom-Right floating banner (#phishguard-security-notification)
 * - Level 2 (SUSPICIOUS): Bottom-Right floating banner (#phishguard-security-notification)
 * - Level 3 (DANGEROUS): Full-screen security warning overlay (#phishguard-danger-overlay)
 */

(function () {
  let notificationHost = null;
  let notificationRoot = null;
  let dangerOverlayHost = null;
  let dangerOverlayRoot = null;

  let activeScanId = null;
  let activeScanUrl = null;
  const bypassedScans = new Set();
  const bypassedUrls = new Set();

  function safeGetURL(path) {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
        return chrome.runtime.getURL(path);
      }
    } catch (e) {}
    return '';
  }

  function safeSendMessage(payload, callback) {
    try {
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.id) {
        chrome.runtime.sendMessage(payload, (response) => {
          try {
            const err = chrome.runtime.lastError;
            if (err) return;
            if (callback) callback(response);
          } catch (e) {}
        });
      }
    } catch (e) {}
  }

  function escapeHTML(str) {
    return String(str ?? '').replace(/[&<>"']/g, match => {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[match];
    });
  }

  function normalizeUrl(url) {
    if (window.PhishGuardNormalizer && window.PhishGuardNormalizer.normalizeUrlForComparison) {
      return window.PhishGuardNormalizer.normalizeUrlForComparison(url);
    }
    if (!url || typeof url !== 'string') return '';
    const trimmed = url.trim().toLowerCase();
    const withProto = (trimmed.startsWith('http://') || trimmed.startsWith('https://')) ? trimmed : 'https://' + trimmed;
    try {
      const u = new URL(withProto);
      const host = u.hostname.replace(/^www\./, '');
      const pathname = (u.pathname || '').replace(/\/+$/, '');
      return host + (pathname ? pathname : '');
    } catch (e) {
      return trimmed.replace(/^https?:\/\//, '').replace(/^www\./, '').split('?')[0].split('#')[0].replace(/\/+$/, '');
    }
  }

  // ── OBSOLETE & LEGACY UI CLEANUP ──────────────────────────────────────────
  function removeAllPhishGuardUI() {
    const ids = [
      'phishguard-security-notification',
      'phishguard-danger-overlay',
      'phishguard-shadow-host',
      'phishguard-security-banner',
      'phishguard-banner-host'
    ];
    ids.forEach(id => {
      const el = document.getElementById(id);
      if (el) el.remove();
    });
    notificationHost = null;
    notificationRoot = null;
    dangerOverlayHost = null;
    dangerOverlayRoot = null;
  }

  function removeNotificationHost() {
    const el = document.getElementById('phishguard-security-notification');
    if (el) el.remove();
    const legacy = document.getElementById('phishguard-security-banner');
    if (legacy) legacy.remove();
    const legacyOld = document.getElementById('phishguard-banner-host');
    if (legacyOld) legacyOld.remove();
    notificationHost = null;
    notificationRoot = null;
  }

  function removeDangerOverlayHost() {
    const el = document.getElementById('phishguard-danger-overlay');
    if (el) el.remove();
    const legacy = document.getElementById('phishguard-shadow-host');
    if (legacy) legacy.remove();
    dangerOverlayHost = null;
    dangerOverlayRoot = null;
  }

  // ── MASTER 3-LEVEL UI RENDERER ────────────────────────────────────────────
  function renderSecurityUI(rawData) {
    if (!rawData) return;
    const data = (window.PhishGuardNormalizer ? window.PhishGuardNormalizer.normalizeScanResult(rawData) : rawData);
    if (!data) return;
    if (!data.url) data.url = location.href;

    // Strict Stale-Result Protection: Ensure scan result URL matches current page location (bypassed in demo mode)
    const isDemo = Boolean(data.is_demo || data.isDemo);
    const normResultUrl = normalizeUrl(data.url);
    const normCurrentUrl = normalizeUrl(location.href);
    if (!isDemo && normResultUrl && normCurrentUrl && normResultUrl !== normCurrentUrl) {
      console.log(`[PhishGuard] STALE_RESULT_IGNORED: Result URL (${data.url}) !== Current URL (${location.href})`);
      return;
    }

    activeScanId = data.scanId || ('scan_' + Date.now());
    activeScanUrl = data.url;

    // Resolve 3-Level Security Classification
    const level = window.PhishGuardNormalizer
      ? window.PhishGuardNormalizer.resolveSecurityLevel(data)
      : (() => {
          const score = data.riskScore !== null && data.riskScore !== undefined ? data.riskScore : (data.risk_score || 0);
          const v = String(data.verdict || data.prediction || '').toUpperCase();
          const t = String(data.threatLevel || data.threat_level || '').toUpperCase();
          if (v === 'PHISHING' || v === 'MALICIOUS' || t === 'CRITICAL' || t === 'HIGH' || score >= 70.0) return 'DANGEROUS';
          if (v === 'SUSPICIOUS' || t === 'MEDIUM' || score > 30.0) return 'SUSPICIOUS';
          return 'SAFE';
        })();

    if (level === 'DANGEROUS') {
      // Check if user clicked "Continue Anyway" on this scan/URL
      if (bypassedScans.has(activeScanId) || bypassedUrls.has(normCurrentUrl)) {
        console.log(`[PhishGuard] LEVEL 3 OVERLAY BYPASSED by user choice on ${data.url}`);
        removeDangerOverlayHost();
        return;
      }
      removeNotificationHost();
      renderLevel3DangerOverlay(data);
    } else if (level === 'SUSPICIOUS') {
      removeDangerOverlayHost();
      renderBottomRightBanner(data, 'SUSPICIOUS');
    } else {
      // SAFE (Level 1)
      removeDangerOverlayHost();
      renderBottomRightBanner(data, 'SAFE');
    }
  }

  // ── LEVEL 1 & LEVEL 2: BOTTOM-RIGHT NOTIFICATION BANNER ──────────────────
  function renderBottomRightBanner(data, level) {
    const isSuspicious = level === 'SUSPICIOUS';
    const scoreVal = data.riskScore !== null && data.riskScore !== undefined ? data.riskScore : (data.risk_score || 0);

    let themeColor = '#10b981'; // Emerald Green
    let themeBg = 'rgba(16, 185, 129, 0.08)';
    let themeBorder = 'rgba(16, 185, 129, 0.35)';
    let iconSymbol = '✓';
    let titleText = 'Safe Website';
    let subMessage = data.reason || 'Verified safe — URL structure and domain records match legitimate patterns.';
    let threatText = `${scoreVal}% Threat`;
    let actionText = '';

    if (isSuspicious) {
      themeColor = '#f59e0b'; // Amber Yellow
      themeBg = 'rgba(245, 158, 11, 0.08)';
      themeBorder = 'rgba(245, 158, 11, 0.35)';
      iconSymbol = '⚠';
      titleText = 'Suspicious Website';
      threatText = `${scoreVal}% Threat`;
      actionText = 'Proceed with caution';

      // Extract actual threat explanation from backend dynamic reason or signals
      if (data.reason) {
        subMessage = data.reason;
      } else if (Array.isArray(data.signals) && data.signals.length > 0) {
        const topSignal = data.signals.find(s => s.severity === 'medium' || s.severity === 'high' || s.severity === 'critical') || data.signals[0];
        subMessage = topSignal.description || topSignal.signal || 'Suspicious URL characteristics detected';
      } else {
        subMessage = 'Suspicious URL pattern detected by AI model';
      }
    }

    // Extract domain for display
    let domainStr = 'example.com';
    if (data.url) {
      try {
        const u = new URL(data.url);
        domainStr = u.hostname || data.url;
      } catch (e) {
        domainStr = data.url;
      }
    }

    const targetParent = document.documentElement || document.body;
    const hostStyleCss = 'all: initial !important; position: fixed !important; right: 20px !important; bottom: 20px !important; left: auto !important; top: auto !important; z-index: 2147483647 !important; pointer-events: none !important; width: auto !important; height: auto !important; margin: 0 !important; padding: 0 !important; display: block !important; transform: none !important; filter: none !important; perspective: none !important; contain: none !important;';

    // Check if host already exists for single-element update
    notificationHost = document.getElementById('phishguard-security-notification');
    if (!notificationHost) {
      notificationHost = document.createElement('div');
      notificationHost.id = 'phishguard-security-notification';
      notificationHost.style.cssText = hostStyleCss;
      notificationRoot = notificationHost.attachShadow({ mode: 'open' });

      if (targetParent) {
        targetParent.appendChild(notificationHost);
      }
    } else {
      notificationHost.style.cssText = hostStyleCss;
      if (targetParent && notificationHost.parentNode !== targetParent) {
        targetParent.appendChild(notificationHost);
      }
      notificationRoot = notificationHost.shadowRoot || notificationHost.attachShadow({ mode: 'open' });
    }

    const htmlContent = `
      <style>
        :host {
          all: initial !important;
          position: fixed !important;
          right: 20px !important;
          bottom: 20px !important;
          left: auto !important;
          top: auto !important;
          z-index: 2147483647 !important;
          pointer-events: none !important;
          width: auto !important;
          height: auto !important;
          margin: 0 !important;
          padding: 0 !important;
          display: block !important;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
        }
        @media (max-width: 480px) {
          :host {
            right: 12px !important;
            bottom: 12px !important;
            left: auto !important;
          }
        }
        .security-banner-container {
          pointer-events: auto !important;
          position: relative !important;
          width: 340px !important;
          max-width: calc(100vw - 40px) !important;
          background: #ffffff !important;
          border: 1.5px solid ${themeBorder} !important;
          border-radius: 16px !important;
          box-shadow: 0 16px 40px -8px rgba(0, 0, 0, 0.14), 0 4px 12px rgba(0, 0, 0, 0.06) !important;
          padding: 14px 16px !important;
          box-sizing: border-box !important;
          color: #0f172a !important;
          overflow: hidden !important;
          cursor: default !important;
          user-select: none !important;
          animation: bannerSlideIn 0.35s cubic-bezier(0.16, 1, 0.3, 1) forwards !important;
          transition: transform 0.25s ease, box-shadow 0.25s ease !important;
        }
        .security-banner-container:hover {
          transform: translateY(-2px) !important;
          box-shadow: 0 20px 48px -10px rgba(0, 0, 0, 0.18), 0 6px 16px rgba(0, 0, 0, 0.08) !important;
        }
        @keyframes bannerSlideIn {
          from { opacity: 0; transform: translateY(20px) scale(0.95); }
          to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .banner-header {
          display: flex !important;
          align-items: center !important;
          justify-content: space-between !important;
          margin-bottom: 6px !important;
        }
        .header-title-group {
          display: flex !important;
          align-items: center !important;
          gap: 8px !important;
        }
        .status-icon-box {
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          width: 28px !important;
          height: 28px !important;
          background: ${themeBg} !important;
          border-radius: 8px !important;
          font-size: 16px !important;
          color: ${themeColor} !important;
          font-weight: bold !important;
          flex-shrink: 0 !important;
        }
        .banner-title {
          font-size: 14px !important;
          font-weight: 700 !important;
          color: #0f172a !important;
          line-height: 1.2 !important;
        }
        .close-btn {
          background: transparent !important;
          border: none !important;
          color: #94a3b8 !important;
          font-size: 16px !important;
          cursor: pointer !important;
          padding: 2px 6px !important;
          line-height: 1 !important;
          border-radius: 6px !important;
          transition: color 0.2s ease !important;
        }
        .close-btn:hover {
          color: #0f172a !important;
          background: #f1f5f9 !important;
        }

        .banner-info-row {
          display: flex !important;
          align-items: center !important;
          justify-content: space-between !important;
          font-size: 12px !important;
          color: #475569 !important;
          margin-top: 4px !important;
        }
        .threat-tag {
          font-weight: 700 !important;
          color: ${themeColor} !important;
          background: ${themeBg} !important;
          padding: 2px 8px !important;
          border-radius: 6px !important;
          font-size: 11px !important;
        }
        .action-text {
          font-size: 11px !important;
          color: #d97706 !important;
          font-weight: 600 !important;
        }
        .sub-message {
          font-size: 11px !important;
          color: #64748b !important;
          margin-top: 6px !important;
          display: flex !important;
          align-items: center !important;
          justify-content: space-between !important;
        }
        .details-btn {
          background: none !important;
          border: none !important;
          color: #3b82f6 !important;
          font-size: 11px !important;
          cursor: pointer !important;
          padding: 0 !important;
          text-decoration: underline !important;
        }
        .details-drawer {
          display: none !important;
          margin-top: 8px !important;
          padding-top: 8px !important;
          border-top: 1px solid #e2e8f0 !important;
          font-size: 11px !important;
          color: #64748b !important;
        }
        .details-drawer.open {
          display: block !important;
        }
        .details-grid {
          display: grid !important;
          grid-template-columns: 1fr 1fr !important;
          gap: 4px 12px !important;
        }
      </style>

      <div class="security-banner-container">
        <div class="banner-header">
          <div class="header-title-group">
            <div class="status-icon-box">${iconSymbol}</div>
            <span class="banner-title">${escapeHTML(titleText)}${(data.is_demo || data.isDemo) ? ' <span style="font-size:9px;background:rgba(56,189,248,0.2);color:#38bdf8;padding:2px 6px;border-radius:4px;margin-left:6px;border:1px solid rgba(56,189,248,0.3);font-family:monospace;">DEMO</span>' : ''}</span>
          </div>
          <button class="close-btn" id="btn-banner-close" title="Dismiss">✕</button>
        </div>

        <div class="banner-info-row">
          <span class="threat-tag">${escapeHTML(threatText)}</span>
          ${actionText ? `<span class="action-text">${escapeHTML(actionText)}</span>` : `<span style="font-size:11px;color:#94a3b8;">${escapeHTML(domainStr)}</span>`}
        </div>

        <div class="sub-message">
          <span>${escapeHTML(subMessage)}</span>
          <button class="details-btn" id="btn-toggle-details">Details</button>
        </div>

        <div class="details-drawer" id="details-drawer">
          <div class="details-grid">
            <div>SSL: <strong>${escapeHTML(data.ssl_status || data.sslStatus || (data.ssl ? 'Valid SSL' : 'Missing SSL'))}</strong></div>
            <div>Domain Age: <strong>${escapeHTML(data.domain_age || data.domainAge || 'Unable to verify')}</strong></div>
            <div>Redirects: <strong>${escapeHTML(data.redirect_status || data.redirectStatus || (data.redirects || 0) + ' redirects')}</strong></div>
            <div>Blacklist: <strong>${escapeHTML(data.blacklist_status || data.blacklistStatus || (data.blacklisted ? 'Listed' : 'Clean'))}</strong></div>
            <div>Model: <strong>${escapeHTML(data.modelDisplay || 'DL Ensemble')}</strong></div>
            <div>Confidence: <strong>${data.confidence ?? 99}%</strong></div>
          </div>
        </div>
      </div>
    `;

    notificationRoot.innerHTML = htmlContent;

    // Event Handlers
    const closeBtn = notificationRoot.getElementById('btn-banner-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        removeNotificationHost();
      });
    }

    const toggleBtn = notificationRoot.getElementById('btn-toggle-details');
    const drawer = notificationRoot.getElementById('details-drawer');
    if (toggleBtn && drawer) {
      toggleBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = drawer.classList.contains('open');
        if (isOpen) {
          drawer.classList.remove('open');
          toggleBtn.textContent = 'Details';
        } else {
          drawer.classList.add('open');
          toggleBtn.textContent = 'Hide';
        }
      });
    }
  }

  // ── LEVEL 3: FULL-SCREEN DANGEROUS OVERLAY ────────────────────────────────
  function renderLevel3DangerOverlay(data) {
    const rawScore = data.riskScore !== null && data.riskScore !== undefined ? data.riskScore : (data.risk_score !== null && data.risk_score !== undefined ? data.risk_score : null);
    const scoreVal = rawScore !== null ? Math.round(rawScore) : 88;
    const confidenceVal = (data.confidence !== null && data.confidence !== undefined) ? data.confidence : 98.5;
    const threatLevelStr = escapeHTML(data.threatLevel || data.threat_level || 'CRITICAL');

    const targetParent = document.documentElement || document.body;
    dangerOverlayHost = document.getElementById('phishguard-danger-overlay');
    if (!dangerOverlayHost) {
      dangerOverlayHost = document.createElement('div');
      dangerOverlayHost.id = 'phishguard-danger-overlay';
      dangerOverlayHost.style.cssText = 'all: initial !important; position: fixed !important; top: 0 !important; left: 0 !important; width: 100vw !important; height: 100vh !important; z-index: 2147483647 !important; pointer-events: auto !important; margin: 0 !important; padding: 0 !important; display: block !important; transform: none !important; filter: none !important; perspective: none !important; contain: none !important;';
      dangerOverlayRoot = dangerOverlayHost.attachShadow({ mode: 'open' });

      if (targetParent) {
        targetParent.appendChild(dangerOverlayHost);
      }
    } else {
      dangerOverlayHost.style.cssText = 'all: initial !important; position: fixed !important; top: 0 !important; left: 0 !important; width: 100vw !important; height: 100vh !important; z-index: 2147483647 !important; pointer-events: auto !important; margin: 0 !important; padding: 0 !important; display: block !important; transform: none !important; filter: none !important; perspective: none !important; contain: none !important;';
      if (targetParent && dangerOverlayHost.parentNode !== targetParent) {
        targetParent.appendChild(dangerOverlayHost);
      }
      dangerOverlayRoot = dangerOverlayHost.shadowRoot || dangerOverlayHost.attachShadow({ mode: 'open' });
    }

    const modalLogoUrl = safeGetURL('icons/icon128.png');
    const modalImgTag = modalLogoUrl
      ? `<img src="${escapeHTML(modalLogoUrl)}" class="shield-icon-img" alt="PhishGuard Shield" onerror="this.style.display='none'; if(this.nextElementSibling) this.nextElementSibling.style.display='inline-block';"><span style="display:none;font-size:72px;">🛡️</span>`
      : `<span style="font-size:72px;">🛡️</span>`;

    const htmlContent = `
      <style>
        :host {
          all: initial !important;
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
        }
        .overlay-backdrop {
          position: fixed !important;
          top: 0 !important; left: 0 !important; right: 0 !important; bottom: 0 !important;
          width: 100vw !important; height: 100vh !important;
          background: rgba(10, 15, 29, 0.97) !important;
          backdrop-filter: blur(20px) !important;
          -webkit-backdrop-filter: blur(20px) !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          padding: 24px !important;
          box-sizing: border-box !important;
          color: #f8fafc !important;
          z-index: 2147483647 !important;
          pointer-events: auto !important;
        }
        .modal-card {
          background: rgba(23, 32, 54, 0.96) !important;
          border: 1.5px solid rgba(239, 68, 68, 0.5) !important;
          border-radius: 24px !important;
          max-width: 640px !important;
          width: 100% !important;
          padding: 40px 36px !important;
          box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.4), 0 0 90px rgba(239, 68, 68, 0.2) !important;
          text-align: center !important;
          box-sizing: border-box !important;
        }
        .shield-icon-container {
          display: flex !important;
          justify-content: center !important;
          align-items: center !important;
          margin-bottom: 16px !important;
        }
        .shield-icon-img {
          width: 72px !important;
          height: 72px !important;
          object-fit: contain !important;
          filter: drop-shadow(0 0 25px rgba(239, 68, 68, 0.6)) !important;
        }
        .threat-badge {
          display: inline-flex !important;
          align-items: center !important;
          gap: 8px !important;
          background: rgba(239, 68, 68, 0.15) !important;
          border: 1px solid rgba(239, 68, 68, 0.4) !important;
          color: #ef4444 !important;
          font-size: 12px !important;
          font-weight: 800 !important;
          padding: 6px 16px !important;
          border-radius: 9999px !important;
          text-transform: uppercase !important;
          letter-spacing: 1px !important;
          margin-bottom: 18px !important;
        }
        .title {
          font-size: 26px !important;
          font-weight: 800 !important;
          color: #ffffff !important;
          margin: 0 0 12px 0 !important;
          letter-spacing: -0.5px !important;
        }
        .description {
          font-size: 15px !important;
          color: #94a3b8 !important;
          line-height: 1.5 !important;
          margin: 0 0 20px 0 !important;
        }
        .url-box {
          background: rgba(15, 23, 42, 0.8) !important;
          border: 1px dashed rgba(239, 68, 68, 0.4) !important;
          border-radius: 12px !important;
          padding: 10px 16px !important;
          font-family: monospace !important;
          font-size: 13px !important;
          color: #f87171 !important;
          word-break: break-all !important;
          margin-bottom: 20px !important;
        }
        .metrics-grid {
          display: grid !important;
          grid-template-columns: repeat(3, 1fr) !important;
          gap: 12px !important;
          margin-bottom: 24px !important;
        }
        .metric-box {
          background: rgba(15, 23, 42, 0.6) !important;
          border: 1px solid rgba(255, 255, 255, 0.08) !important;
          border-radius: 14px !important;
          padding: 12px !important;
        }
        .metric-val {
          font-size: 20px !important;
          font-weight: 800 !important;
          color: #ef4444 !important;
        }
        .metric-lbl {
          font-size: 11px !important;
          color: #64748b !important;
          text-transform: uppercase !important;
          font-weight: 700 !important;
          margin-top: 4px !important;
        }
        .actions {
          display: flex !important;
          gap: 14px !important;
          justify-content: center !important;
        }
        .btn-primary {
          background: #ef4444 !important;
          color: #ffffff !important;
          border: none !important;
          padding: 14px 28px !important;
          border-radius: 12px !important;
          font-size: 14px !important;
          font-weight: 800 !important;
          cursor: pointer !important;
          box-shadow: 0 4px 20px rgba(239, 68, 68, 0.4) !important;
          transition: all 0.2s ease !important;
        }
        .btn-primary:hover {
          background: #dc2626 !important;
          transform: translateY(-1px) !important;
        }
        .btn-secondary {
          background: transparent !important;
          color: #94a3b8 !important;
          border: 1px solid rgba(255, 255, 255, 0.18) !important;
          padding: 14px 24px !important;
          border-radius: 12px !important;
          font-size: 14px !important;
          font-weight: 700 !important;
          cursor: pointer !important;
          transition: all 0.2s ease !important;
        }
        .btn-secondary:hover {
          color: #ffffff !important;
          background: rgba(255, 255, 255, 0.08) !important;
        }
      </style>

      <div class="overlay-backdrop">
        <div class="modal-card">
          <div class="shield-icon-container">${modalImgTag}</div>
          <div class="threat-badge">
            <span>${(data.is_demo || data.isDemo) ? '⚠️ [DEMO DATA] PHISHGUARD AI SECURITY INTERSTITIAL' : '⚠️ PHISHGUARD AI SECURITY INTERSTITIAL'}</span>
          </div>
          <h1 class="title">DANGEROUS WEBSITE</h1>
          <p class="description">
            ${escapeHTML(data.reason || 'CRITICAL WARNING: PhishGuard AI deep neural ensemble detected high-confidence phishing indicators. Do NOT enter passwords, banking credentials, or personal information.')}
          </p>

          <div class="url-box">${escapeHTML(data.url)}</div>

          <div class="metrics-grid">
            <div class="metric-box">
              <div class="metric-val" style="color:#ef4444;">${scoreVal}%</div>
              <div class="metric-lbl">Actual Threat</div>
            </div>
            <div class="metric-box">
              <div class="metric-val" style="color:#f59e0b;">${confidenceVal}%</div>
              <div class="metric-lbl">DL Confidence</div>
            </div>
            <div class="metric-box">
              <div class="metric-val" style="color:#ef4444;">${threatLevelStr}</div>
              <div class="metric-lbl">Threat Level</div>
            </div>
          </div>

          <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:20px;font-size:11px;background:rgba(15,23,42,0.6);border:1px solid rgba(255,255,255,0.08);border-radius:12px;padding:10px;text-align:center;">
            <div>
              <div style="color:#64748b;font-weight:700;text-transform:uppercase;font-size:10px;">SSL Status</div>
              <div style="color:${(data.ssl_status === 'Valid SSL' || data.ssl) ? '#10b981' : '#ef4444'};font-weight:700;margin-top:2px;">${escapeHTML(data.ssl_status || data.sslStatus || (data.ssl ? 'Valid SSL' : 'Missing SSL'))}</div>
            </div>
            <div>
              <div style="color:#64748b;font-weight:700;text-transform:uppercase;font-size:10px;">Domain Age</div>
              <div style="color:#e2e8f0;font-weight:700;margin-top:2px;">${escapeHTML(data.domain_age || data.domainAge || 'Unable to verify')}</div>
            </div>
            <div>
              <div style="color:#64748b;font-weight:700;text-transform:uppercase;font-size:10px;">Redirects</div>
              <div style="color:#e2e8f0;font-weight:700;margin-top:2px;">${escapeHTML(data.redirect_status || data.redirectStatus || (data.redirects || 0) + ' redirects')}</div>
            </div>
            <div>
              <div style="color:#64748b;font-weight:700;text-transform:uppercase;font-size:10px;">Blacklist</div>
              <div style="color:${(data.blacklist_status === 'Listed' || data.blacklisted) ? '#ef4444' : '#10b981'};font-weight:700;margin-top:2px;">${escapeHTML(data.blacklist_status || data.blacklistStatus || (data.blacklisted ? 'Listed' : 'Clean'))}</div>
            </div>
          </div>

          <div class="actions">
            <button class="btn-primary" id="btn-safety">Go Back to Safety</button>
            <button class="btn-secondary" id="btn-proceed">Continue Anyway</button>
          </div>
        </div>
      </div>
    `;

    dangerOverlayRoot.innerHTML = htmlContent;

    // Button Handlers
    const safetyBtn = dangerOverlayRoot.getElementById('btn-safety');
    if (safetyBtn) {
      safetyBtn.addEventListener('click', () => {
        if (data.is_demo || data.isDemo) {
          removeDangerOverlayHost();
          return;
        }
        if (window.history.length > 1) {
          window.history.back();
        } else {
          window.location.href = 'https://google.com';
        }
      });
    }

    const proceedBtn = dangerOverlayRoot.getElementById('btn-proceed');
    if (proceedBtn) {
      proceedBtn.addEventListener('click', () => {
        if (activeScanId) bypassedScans.add(activeScanId);
        if (activeScanUrl) bypassedUrls.add(normalizeUrl(activeScanUrl));
        removeDangerOverlayHost();
      });
    }
  }

  // Backward compatibility alias functions
  window.createSecurityBanner = renderSecurityUI;
  window.createShadowOverlay = renderSecurityUI;

  // ── BACKGROUND & WINDOW MESSAGE LISTENERS ─────────────────────────────────
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        try {
          console.log("[PhishGuard] Content script received:", message);
          const scanResult = message.result || message.data;

          if (message.type === 'PHISHGUARD_SCAN_COMPLETE' || message.action === 'SHOW_RESULT_BANNER' || message.action === 'SHOW_SAFE_BANNER' || message.action === 'SHOW_THREAT_WARNING') {
            renderSecurityUI(scanResult);
            sendResponse({ status: 'ui_rendered' });
          } else if (message.action === 'CLEAR_THREAT_WARNING' || message.action === 'CLEAR_SAFE_BANNER') {
            removeAllPhishGuardUI();
            sendResponse({ status: 'ui_cleared' });
          }
        } catch (e) {
          console.error("[PhishGuard] Error rendering UI from content script:", e);
        }
      });
    }
  } catch (e) {}

  window.addEventListener('message', (event) => {
    try {
      if (!event.data) return;
      if (event.data.type === 'PHISHGUARD_PING') {
        window.postMessage({ type: 'PHISHGUARD_PONG', installed: true, version: '2.0.0', timestamp: Date.now() }, '*');
        return;
      }
      if (event.data.type === 'PHISHGUARD_TRIGGER_SCAN' && event.data.url) {
        safeSendMessage({ action: 'PERFORM_SCAN', url: event.data.url }, (resp) => {
          if (resp && resp.result) {
            window.postMessage({ type: 'PHISHGUARD_SCAN_RESPONSE', result: resp.result }, '*');
          }
        });
        return;
      }
      if (event.data.phishguardMsg) {
        const message = event.data.phishguardMsg;
        const scanResult = message.result || message.data;
        renderSecurityUI(scanResult);
      }
    } catch (e) {}
  });

  // ── SPA ROUTE MUTATION & NAVIGATION MONITOR ──────────────────────────────
  let lastObservedUrl = location.href;
  let urlCheckTimer = null;

  function handleUrlChange() {
    try {
      const currentUrl = location.href;
      if (currentUrl !== lastObservedUrl) {
        lastObservedUrl = currentUrl;
        console.log("[PhishGuard] SPA URL Changed:", currentUrl);
        removeAllPhishGuardUI();
        safeSendMessage({ action: 'URL_CHANGED', url: currentUrl });
      }
    } catch (e) {}
  }

  function debouncedHandleUrlChange() {
    if (urlCheckTimer) clearTimeout(urlCheckTimer);
    urlCheckTimer = setTimeout(() => {
      handleUrlChange();
    }, 100);
  }

  // Intercept pushState & replaceState
  const rawPushState = history.pushState;
  history.pushState = function () {
    rawPushState.apply(this, arguments);
    debouncedHandleUrlChange();
  };

  const rawReplaceState = history.replaceState;
  history.replaceState = function () {
    rawReplaceState.apply(this, arguments);
    debouncedHandleUrlChange();
  };

  window.addEventListener('popstate', debouncedHandleUrlChange);

  // MutationObserver for SPA framework navigation (e.g. YouTube)
  new MutationObserver(() => {
    debouncedHandleUrlChange();
  }).observe(document.documentElement || document, { subtree: true, childList: true });

  // ── ON CONTENT SCRIPT INITIALIZATION ─────────────────────────────────────
  function initTabScanState() {
    safeSendMessage({ action: 'GET_CURRENT_SCAN_STATE', url: location.href }, (state) => {
      if (state && state.status === 'SUCCESS') {
        renderSecurityUI(state);
      } else {
        safeSendMessage({ action: 'URL_CHANGED', url: location.href });
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTabScanState);
  } else {
    initTabScanState();
  }

})();
