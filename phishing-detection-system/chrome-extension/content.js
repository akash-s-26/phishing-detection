/**
 * PhishGuard AI — Content Script (Shadow DOM Threat Overlay & Bottom-Right Result Banner)
 * Mounts an isolated, non-bypassable full-screen warning interstitial when a PHISHING threat is validated,
 * and renders a compact, non-blocking floating result banner in the bottom-right corner for SAFE, SUSPICIOUS, and DANGEROUS results.
 */

(function () {
  let shadowHost = null;
  let shadowRoot = null;
  let currentScanId = null;

  let bannerHost = null;
  let bannerRoot = null;
  let bannerDismissTimer = null;
  let currentBannerScanId = null;

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

  function removeExistingOverlay() {
    const existing = document.getElementById('phishguard-shadow-host');
    if (existing) {
      existing.remove();
    }
    shadowHost = null;
    shadowRoot = null;
    currentScanId = null;
  }

  function removeSecurityBanner() {
    if (bannerDismissTimer) {
      clearInterval(bannerDismissTimer);
      bannerDismissTimer = null;
    }
    const existingOld = document.getElementById('phishguard-banner-host');
    if (existingOld) existingOld.remove();

    const existingNew = document.getElementById('phishguard-security-banner');
    if (existingNew) existingNew.remove();

    bannerHost = null;
    bannerRoot = null;
    currentBannerScanId = null;
  }

  // ── 1. BOTTOM-RIGHT FLOATING SECURITY BANNER ──────────────────────────────
  function createSecurityBanner(rawData) {
    if (!rawData) return;
    console.log("[PhishGuard] Creating security banner for result:", rawData);

    const data = (window.PhishGuardNormalizer ? window.PhishGuardNormalizer.normalizeScanResult(rawData) : rawData);
    if (!data) return;

    // Prevent duplicate creating if same exact scan ID is currently actively displayed
    removeSecurityBanner();

    currentBannerScanId = data.scanId || ('scan_' + Date.now());

    // Create fixed host element appended to document.body
    bannerHost = document.createElement('div');
    bannerHost.id = 'phishguard-security-banner';
    bannerHost.style.cssText = 'all: initial !important; position: fixed !important; right: 20px !important; bottom: 20px !important; z-index: 2147483647 !important; pointer-events: none !important; width: auto !important; height: auto !important; display: block !important;';

    bannerRoot = bannerHost.attachShadow({ mode: 'closed' });

    const verdict = String(data.verdict || 'SAFE').toUpperCase();
    const isSafe = verdict === 'SAFE' || verdict === 'LOW';
    const isSuspicious = verdict === 'SUSPICIOUS' || verdict === 'MEDIUM';
    const isPhishing = verdict === 'PHISHING' || verdict === 'HIGH' || verdict === 'CRITICAL' || verdict === 'DANGEROUS';

    let themeColor = '#10b981'; // Emerald Green
    let themeBg = 'rgba(16, 185, 129, 0.08)';
    let themeBorder = 'rgba(16, 185, 129, 0.35)';
    let iconSymbol = '🛡️';
    let titleText = 'Website Safe';
    let subMessage = 'No phishing or malicious threats detected.';
    const scoreVal = data.riskScore !== null && data.riskScore !== undefined ? data.riskScore : (data.risk_score || 0);
    let metricText = `${Math.round(data.confidence ?? (100 - scoreVal))}% Safe`;

    if (isSuspicious) {
      themeColor = '#f59e0b'; // Amber Yellow
      themeBg = 'rgba(245, 158, 11, 0.08)';
      themeBorder = 'rgba(245, 158, 11, 0.35)';
      iconSymbol = '⚠️';
      titleText = 'Suspicious Website';
      subMessage = 'Potential security threat detected.';
      metricText = `${scoreVal}% Risk`;
    } else if (isPhishing) {
      themeColor = '#ef4444'; // Crimson Red
      themeBg = 'rgba(239, 68, 68, 0.08)';
      themeBorder = 'rgba(239, 68, 68, 0.4)';
      iconSymbol = '🚨';
      titleText = 'Phishing Threat Detected';
      subMessage = 'This website may be dangerous.';
      metricText = `${scoreVal}% Threat`;
    }

    // Domain display extraction
    let domainStr = 'example.com';
    if (data.url) {
      try {
        const u = new URL(data.url);
        domainStr = u.hostname || data.url;
      } catch (e) {
        domainStr = data.url;
      }
    }

    const style = document.createElement('style');
    style.textContent = `
      :host {
        all: initial !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
      }
      .security-banner-container {
        pointer-events: auto !important;
        position: relative !important;
        width: 360px !important;
        max-width: calc(100vw - 40px) !important;
        background: #ffffff !important;
        border: 1.5px solid ${themeBorder} !important;
        border-radius: 16px !important;
        box-shadow: 0 16px 40px -8px rgba(0, 0, 0, 0.14), 0 4px 12px rgba(0, 0, 0, 0.06) !important;
        padding: 16px 18px !important;
        box-sizing: border-box !important;
        color: #0f172a !important;
        overflow: hidden !important;
        cursor: default !important;
        user-select: none !important;
        animation: bannerSlideIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) forwards !important;
        transition: transform 0.25s ease, box-shadow 0.25s ease !important;
      }
      .security-banner-container:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 20px 48px -10px rgba(0, 0, 0, 0.18), 0 6px 16px rgba(0, 0, 0, 0.08) !important;
      }
      .security-banner-container.dismissing {
        animation: bannerSlideOut 0.35s cubic-bezier(0.7, 0, 0.84, 0) forwards !important;
      }
      @keyframes bannerSlideIn {
        from { opacity: 0; transform: translateX(120%) scale(0.95); }
        to { opacity: 1; transform: translateX(0) scale(1); }
      }
      @keyframes bannerSlideOut {
        from { opacity: 1; transform: translateX(0) scale(1); }
        to { opacity: 0; transform: translateX(120%) scale(0.95); }
      }

      .banner-header {
        display: flex !important;
        align-items: center !important;
        justify-content: space-between !important;
        margin-bottom: 8px !important;
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
        width: 32px !important;
        height: 32px !important;
        background: ${themeBg} !important;
        border-radius: 10px !important;
        font-size: 18px !important;
        flex-shrink: 0 !important;
      }
      .banner-title {
        font-size: 15px !important;
        font-weight: 700 !important;
        color: #0f172a !important;
        line-height: 1.2 !important;
        letter-spacing: -0.2px !important;
      }

      .close-btn {
        background: transparent !important;
        border: none !important;
        color: #94a3b8 !important;
        font-size: 18px !important;
        font-weight: 600 !important;
        cursor: pointer !important;
        width: 28px !important;
        height: 28px !important;
        border-radius: 8px !important;
        display: flex !important;
        align-items: center !important;
        justify-content: center !important;
        padding: 0 !important;
        line-height: 1 !important;
        transition: all 0.15s ease !important;
      }
      .close-btn:hover {
        color: #0f172a !important;
        background: #f1f5f9 !important;
      }

      .banner-message {
        font-size: 13px !important;
        color: #475569 !important;
        line-height: 1.4 !important;
        margin-bottom: 8px !important;
        font-weight: 450 !important;
      }

      .domain-tag {
        display: inline-block !important;
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
        font-size: 11.5px !important;
        color: #64748b !important;
        background: #f8fafc !important;
        border: 1px solid #e2e8f0 !important;
        padding: 3px 8px !important;
        border-radius: 6px !important;
        word-break: break-all !important;
        margin-bottom: 10px !important;
      }

      .banner-meta-row {
        display: flex !important;
        align-items: center !important;
        justify-content: space-between !important;
        padding-top: 8px !important;
        border-top: 1px solid #f1f5f9 !important;
        margin-top: 4px !important;
      }
      .badge-group {
        display: flex !important;
        align-items: center !important;
        gap: 6px !important;
        font-size: 12px !important;
      }
      .score-badge {
        font-weight: 700 !important;
        color: ${themeColor} !important;
        background: ${themeBg} !important;
        padding: 2px 7px !important;
        border-radius: 6px !important;
      }
      .protected-label {
        color: #94a3b8 !important;
        font-weight: 500 !important;
        font-size: 11px !important;
      }

      .btn-view-details {
        background: #f8fafc !important;
        border: 1px solid #cbd5e1 !important;
        color: #334155 !important;
        font-size: 12px !important;
        font-weight: 600 !important;
        padding: 5px 12px !important;
        border-radius: 8px !important;
        cursor: pointer !important;
        transition: all 0.15s ease !important;
      }
      .btn-view-details:hover {
        background: #f1f5f9 !important;
        color: #0f172a !important;
        border-color: #94a3b8 !important;
      }

      .details-drawer {
        display: none;
        margin-top: 12px !important;
        padding-top: 10px !important;
        border-top: 1px dashed #e2e8f0 !important;
        font-size: 11px !important;
        color: #64748b !important;
      }
      .details-drawer.open {
        display: block !important;
      }
      .details-grid {
        display: grid !important;
        grid-template-columns: 1fr 1fr !important;
        gap: 6px !important;
        margin-bottom: 8px !important;
      }
      .details-item {
        background: #f8fafc !important;
        padding: 6px 8px !important;
        border-radius: 6px !important;
      }
      .details-val {
        font-weight: 700 !important;
        color: #1e293b !important;
      }

      .progress-bar-track {
        position: absolute !important;
        bottom: 0 !important;
        left: 0 !important;
        right: 0 !important;
        height: 3px !important;
        background: rgba(0,0,0,0.05) !important;
      }
      .progress-bar-fill {
        height: 100% !important;
        background: ${themeColor} !important;
        width: 100% !important;
        transition: width 0.1s linear !important;
      }
    `;

    const bannerContainer = document.createElement('div');
    bannerContainer.className = 'security-banner-container';
    bannerContainer.innerHTML = `
      <div class="banner-header">
        <div class="header-title-group">
          <div class="status-icon-box">${iconSymbol}</div>
          <span class="banner-title">${escapeHTML(titleText)}</span>
        </div>
        <button class="close-btn" id="btn-banner-close" title="Dismiss">✕</button>
      </div>

      <div class="banner-message">${escapeHTML(subMessage)}</div>
      <div class="domain-tag">${escapeHTML(domainStr)}</div>

      <div class="banner-meta-row">
        <div class="badge-group">
          <span class="score-badge">${escapeHTML(metricText)}</span>
          <span class="protected-label">• Protected by PhishGuard AI</span>
        </div>
        <button class="btn-view-details" id="btn-view-details">View Details</button>
      </div>

      <div class="details-drawer" id="details-drawer">
        <div class="details-grid">
          <div class="details-item">Model: <span class="details-val">${escapeHTML(data.modelDisplay || 'DL Ensemble')}</span></div>
          <div class="details-item">Latency: <span class="details-val">${data.inferenceTimeMs ? data.inferenceTimeMs + 'ms' : 'Fast'}</span></div>
          <div class="details-item">Risk Score: <span class="details-val">${scoreVal}/100</span></div>
          <div class="details-item">Confidence: <span class="details-val">${data.confidence ?? 99}%</span></div>
        </div>
      </div>

      <div class="progress-bar-track">
        <div class="progress-bar-fill" id="progress-bar-fill"></div>
      </div>
    `;

    shadowRoot.appendChild(style);
    shadowRoot.appendChild(bannerContainer);

    // Append to document.body (or fallback document.documentElement)
    const targetParent = document.body || document.documentElement;
    if (targetParent) {
      targetParent.appendChild(bannerHost);
    }

    // Dismiss handler
    let isDismissed = false;
    const dismissBanner = () => {
      if (isDismissed) return;
      isDismissed = true;
      if (bannerDismissTimer) {
        clearInterval(bannerDismissTimer);
        bannerDismissTimer = null;
      }
      if (bannerContainer) {
        bannerContainer.classList.add('dismissing');
        setTimeout(() => removeSecurityBanner(), 350);
      } else {
        removeSecurityBanner();
      }
    };

    // Close button listener
    const closeBtn = shadowRoot.getElementById('btn-banner-close');
    if (closeBtn) {
      closeBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        dismissBanner();
      });
    }

    // Details Drawer toggle
    let detailsOpen = false;
    const detailsBtn = shadowRoot.getElementById('btn-view-details');
    const detailsDrawer = shadowRoot.getElementById('details-drawer');
    if (detailsBtn && detailsDrawer) {
      detailsBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        detailsOpen = !detailsOpen;
        if (detailsOpen) {
          detailsDrawer.classList.add('open');
          detailsBtn.textContent = 'Hide Details';
          isPaused = true;
        } else {
          detailsDrawer.classList.remove('open');
          detailsBtn.textContent = 'View Details';
          isPaused = false;
        }
      });
    }

    // 5-Second Auto-Hide Timer with Progress Bar & Mouse Hover Pause
    const totalMs = 5000;
    let remainingMs = totalMs;
    let isPaused = false;
    const progressFill = shadowRoot.getElementById('progress-bar-fill');

    bannerContainer.addEventListener('mouseenter', () => { isPaused = true; });
    bannerContainer.addEventListener('mouseleave', () => { if (!detailsOpen) isPaused = false; });

    bannerDismissTimer = setInterval(() => {
      if (!isPaused) {
        remainingMs -= 100;
        if (progressFill) {
          const pct = Math.max(0, (remainingMs / totalMs) * 100);
          progressFill.style.width = pct + '%';
        }
        if (remainingMs <= 0) {
          dismissBanner();
        }
      }
    }, 100);
  }

  // Alias for backward compatibility
  const createResultBanner = createSecurityBanner;

  // ── 2. FULL-SCREEN THREAT WARNING OVERLAY (PHISHING) ──────────────────────
  function createShadowOverlay(rawData) {
    if (!rawData) return;
    const data = (window.PhishGuardNormalizer ? window.PhishGuardNormalizer.normalizeScanResult(rawData) : rawData);
    if (!data || !data.url) return;

    if (shadowHost && currentScanId === data.scanId) {
      return;
    }

    removeExistingOverlay();
    currentScanId = data.scanId;

    shadowHost = document.createElement('div');
    shadowHost.id = 'phishguard-shadow-host';
    shadowHost.style.cssText = 'all: initial !important; position: fixed !important; top: 0 !important; left: 0 !important; width: 100vw !important; height: 100vh !important; z-index: 2147483647 !important; pointer-events: auto !important; margin: 0 !important; padding: 0 !important; display: block !important;';

    shadowRoot = shadowHost.attachShadow({ mode: 'closed' });

    const style = document.createElement('style');
    style.textContent = `
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
      }
      .modal-card {
        background: rgba(23, 32, 54, 0.96) !important;
        border: 1px solid rgba(239, 68, 68, 0.5) !important;
        border-radius: 24px !important;
        max-width: 680px !important;
        width: 100% !important;
        padding: 44px !important;
        box-shadow: 0 25px 50px -12px rgba(239, 68, 68, 0.4), 0 0 90px rgba(239, 68, 68, 0.2) !important;
        text-align: center !important;
        box-sizing: border-box !important;
      }
      .shield-icon-container {
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
        margin-bottom: 18px !important;
      }
      .shield-icon-img {
        width: 80px !important;
        height: 80px !important;
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
        font-size: 13px !important;
        font-weight: 800 !important;
        padding: 6px 16px !important;
        border-radius: 9999px !important;
        text-transform: uppercase !important;
        letter-spacing: 1px !important;
        margin-bottom: 20px !important;
      }
      .title {
        font-size: 28px !important;
        font-weight: 800 !important;
        color: #ffffff !important;
        margin: 0 0 14px 0 !important;
        letter-spacing: -0.5px !important;
      }
      .description {
        font-size: 15px !important;
        color: #94a3b8 !important;
        line-height: 1.6 !important;
        margin: 0 0 24px 0 !important;
      }
      .url-box {
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px dashed rgba(239, 68, 68, 0.4) !important;
        border-radius: 12px !important;
        padding: 12px 18px !important;
        font-family: monospace !important;
        font-size: 14px !important;
        color: #f87171 !important;
        word-break: break-all !important;
        margin-bottom: 24px !important;
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
        padding: 14px !important;
      }
      .metric-val {
        font-size: 22px !important;
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
      .signals-list {
        display: flex !important;
        flex-direction: column !important;
        gap: 8px !important;
        margin-bottom: 32px !important;
        text-align: left !important;
        max-height: 120px !important;
        overflow-y: auto !important;
      }
      .signal-item {
        display: flex !important;
        align-items: center !important;
        gap: 10px !important;
        background: rgba(15, 23, 42, 0.4) !important;
        padding: 10px 14px !important;
        border-radius: 10px !important;
        font-size: 13px !important;
        color: #cbd5e1 !important;
      }
      .actions {
        display: flex !important;
        gap: 16px !important;
        justify-content: center !important;
      }
      .btn-primary {
        background: #ef4444 !important;
        color: #ffffff !important;
        border: none !important;
        padding: 16px 32px !important;
        border-radius: 14px !important;
        font-size: 15px !important;
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
        padding: 16px 26px !important;
        border-radius: 14px !important;
        font-size: 14px !important;
        font-weight: 700 !important;
        cursor: pointer !important;
        transition: all 0.2s ease !important;
      }
      .btn-secondary:hover {
        color: #ffffff !important;
        background: rgba(255, 255, 255, 0.08) !important;
      }
    `;

    const modalLogoUrl = safeGetURL('icons/icon128.png');
    const modalImgTag = modalLogoUrl
      ? `<img src="${escapeHTML(modalLogoUrl)}" class="shield-icon-img" alt="PhishGuard Shield">`
      : `<span style="font-size:72px;">🛡️</span>`;

    const modalContainer = document.createElement('div');
    modalContainer.className = 'overlay-backdrop';
    modalContainer.innerHTML = `
      <div class="modal-card">
        <div class="shield-icon-container">${modalImgTag}</div>
        <div class="threat-badge">
          <span>⚠️ PHISHGUARD AI SECURITY INTERSTITIAL</span>
        </div>
        <h1 class="title">Critical Phishing Threat Intercepted</h1>
        <p class="description">
          PhishGuard AI's real-time PyTorch Deep Learning Ensemble detected severe credential harvesting and phishing anomaly patterns on this website.
        </p>

        <div class="url-box">${escapeHTML(data.url)}</div>

        <div class="metrics-grid">
          <div class="metric-box">
            <div class="metric-val">${data.riskScore ?? data.risk_score ?? 0}%</div>
            <div class="metric-lbl">Risk Score</div>
          </div>
          <div class="metric-box">
            <div class="metric-val" style="color:#f59e0b;">${data.confidence ?? 99.0}%</div>
            <div class="metric-lbl">DL Confidence</div>
          </div>
          <div class="metric-box">
            <div class="metric-val" style="color:#ef4444;">${escapeHTML(data.threatLevel ?? data.threat_level ?? 'CRITICAL')}</div>
            <div class="metric-lbl">Threat Level</div>
          </div>
        </div>

        <div class="signals-list">
          ${(Array.isArray(data.signals) ? data.signals : []).map(s => `
            <div class="signal-item">
              <span>🚨</span>
              <span><strong>${escapeHTML(s.signal || s.name || 'Suspicious Signal')}:</strong> ${escapeHTML(s.description || s.details || '')}</span>
            </div>
          `).join('') || '<div class="signal-item"><span>🚨</span><span>High-risk neural network sequence anomaly detected</span></div>'}
        </div>

        <div class="actions">
          <button class="btn-primary" id="btn-safety">GO BACK TO SAFETY</button>
          <button class="btn-secondary" id="btn-proceed">CONTINUE AT MY OWN RISK</button>
        </div>
      </div>
    `;

    shadowRoot.appendChild(style);
    shadowRoot.appendChild(modalContainer);

    const targetParent = document.body || document.documentElement;
    if (targetParent) {
      targetParent.appendChild(shadowHost);
    }

    // Event Handlers
    shadowRoot.getElementById('btn-safety').addEventListener('click', () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        window.location.href = 'https://google.com';
      }
    });

    shadowRoot.getElementById('btn-proceed').addEventListener('click', () => {
      removeExistingOverlay();
    });
  }

  function escapeHTML(str) {
    return String(str ?? '').replace(/[&<>"']/g, match => {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[match];
    });
  }

  // ── BACKGROUND MESSAGE LISTENER ───────────────────────────────────────────
  try {
    if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
      chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        try {
          console.log("[PhishGuard] Content script received:", message);
          const scanResult = message.result || message.data;

          if (message.type === 'PHISHGUARD_SCAN_COMPLETE' || message.action === 'SHOW_RESULT_BANNER' || message.action === 'SHOW_SAFE_BANNER') {
            createSecurityBanner(scanResult);
            sendResponse({ status: 'banner_rendered' });
          } else if (message.action === 'SHOW_THREAT_WARNING') {
            createShadowOverlay(scanResult);
            createSecurityBanner(scanResult);
            sendResponse({ status: 'warning_rendered' });
          } else if (message.action === 'CLEAR_THREAT_WARNING' || message.action === 'CLEAR_SAFE_BANNER') {
            removeExistingOverlay();
            removeSecurityBanner();
            sendResponse({ status: 'overlays_cleared' });
          }
        } catch (e) {
          console.error("[PhishGuard] Error rendering notification from content script:", e);
        }
      });
    }
  } catch (e) {}

  // Window message fallback listener for web app integration, test harness & in-page events
  window.addEventListener('message', (event) => {
    try {
      if (!event.data) return;

      // Web App Integration Handshake Ping
      if (event.data.type === 'PHISHGUARD_PING') {
        window.postMessage({
          type: 'PHISHGUARD_PONG',
          installed: true,
          version: '2.0.0',
          timestamp: Date.now()
        }, '*');
        return;
      }

      // Web App Trigger Scan Request
      if (event.data.type === 'PHISHGUARD_TRIGGER_SCAN' && event.data.url) {
        safeSendMessage({ action: 'PERFORM_SCAN', url: event.data.url }, (resp) => {
          if (resp && resp.result) {
            window.postMessage({
              type: 'PHISHGUARD_SCAN_RESPONSE',
              result: resp.result
            }, '*');
          }
        });
        return;
      }

      if (event.data.phishguardMsg) {
        const message = event.data.phishguardMsg;
        console.log("[PhishGuard] Content script received (window.postMessage):", message);
        const scanResult = message.result || message.data;
        if (message.type === 'PHISHGUARD_SCAN_COMPLETE' || message.action === 'SHOW_RESULT_BANNER' || message.action === 'SHOW_SAFE_BANNER') {
          createSecurityBanner(scanResult);
        } else if (message.action === 'SHOW_THREAT_WARNING') {
          createShadowOverlay(scanResult);
          createSecurityBanner(scanResult);
        }
      }
    } catch (e) {}
  });

  // ── SPA ROUTE MUTATION & NAVIGATION MONITOR ──────────────────────────────
  let lastObservedUrl = location.href;

  function handleUrlChange() {
    try {
      const currentUrl = location.href;
      if (currentUrl !== lastObservedUrl) {
        lastObservedUrl = currentUrl;
        removeExistingOverlay();
        removeSecurityBanner();
        safeSendMessage({ action: 'URL_CHANGED', url: currentUrl });
      }
    } catch (e) {}
  }

  // Intercept pushState & replaceState
  const rawPushState = history.pushState;
  history.pushState = function () {
    rawPushState.apply(this, arguments);
    handleUrlChange();
  };

  const rawReplaceState = history.replaceState;
  history.replaceState = function () {
    rawReplaceState.apply(this, arguments);
    handleUrlChange();
  };

  window.addEventListener('popstate', handleUrlChange);

  // MutationObserver fallback for single-page apps
  new MutationObserver(() => {
    handleUrlChange();
  }).observe(document, { subtree: true, childList: true });

  // ── ON CONTENT SCRIPT INITIALIZATION ─────────────────────────────────────
  function initTabScanState() {
    safeSendMessage({ action: 'GET_CURRENT_SCAN_STATE', url: location.href }, (state) => {
      if (state && state.status === 'SUCCESS') {
        if (state.verdict === 'PHISHING' || (state.riskScore !== null && (state.riskScore >= 71.0 || state.risk_score >= 71.0))) {
          createShadowOverlay(state);
        }
        createSecurityBanner(state);
      }
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initTabScanState);
  } else {
    initTabScanState();
  }

})();
