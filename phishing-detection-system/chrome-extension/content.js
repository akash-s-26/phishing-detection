/**
 * content.js — PhishGuard AI Content Script (Stitch UI Design System)
 *
 * Renders UI purely from the `result` object background.js forwards,
 * which is the exact JSON shape returned by Flask's /predict endpoint:
 *   { prediction: 'safe'|'suspicious'|'phishing',
 *     risk_score: number, confidence: number,
 *     signals: [{ signal, severity, description }], ... }
 *
 *   phishing   -> full-page blocking overlay (Leave / Continue / Re-scan / Report)
 *   suspicious -> slide-in top banner (auto-dismiss after 8s)
 *   safe       -> small toast bottom-right (auto-dismiss after 4s)
 */

(function () {
  'use strict';

  if (window.__phishguardLoaded) return; // avoid double injection
  window.__phishguardLoaded = true;

  let overlayActive = false;

  // Listen for the SCAN_COMPLETE push from background.js so the overlay /
  // banner / toast appears in real time once /predict returns.
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'SCAN_COMPLETE') handleResult(msg.result, msg.url);
    sendResponse({ ok: true });
  });

  // ─── Self-init: pull the latest scan result for this tab ───────────────────
  function requestScanIfNeeded(attempt) {
    chrome.runtime.sendMessage({ type: 'GET_SCAN_FOR_TAB' }, (resp) => {
      if (chrome.runtime.lastError) return;
      if (resp && resp.result) {
        handleResult(resp.result, resp.url);
        return;
      }
      if (attempt < 2) {
        setTimeout(() => requestScanIfNeeded(attempt + 1), 2000);
      } else {
        chrome.runtime.sendMessage({ type: 'SCAN_URL', url: window.location.href }, () => {});
      }
    });
  }
  requestScanIfNeeded(0);

  function handleResult(result, url) {
    if (!result) return;

    const currentUrl = window.location.href;
    const targetUrl = url || result.url || '';
    if (targetUrl && !samePage(targetUrl, currentUrl)) {
      return;
    }

    const prediction = (result.prediction || 'safe').toLowerCase();

    if (prediction !== 'phishing') {
      removeExisting('pg-overlay');
      overlayActive = false;
    }

    if (prediction === 'phishing') {
      if (!overlayActive || !document.getElementById('pg-overlay')) {
        showPhishingOverlay(result, targetUrl || currentUrl);
        overlayActive = true;
      }
    } else if (prediction === 'suspicious') {
      showSuspiciousBanner(result, targetUrl || currentUrl);
    } else if (prediction === 'safe') {
      showSafeToast(result);
    }
  }

  function samePage(u1, u2) {
    try {
      const p1 = new URL(u1);
      const p2 = new URL(u2);
      return (p1.origin + p1.pathname).replace(/\/$/, '') === (p2.origin + p2.pathname).replace(/\/$/, '');
    } catch (_) {
      return u1 === u2;
    }
  }

  // ─── 1. PHISHING — full-page overlay (Strict Flex Alignment) ───────────────

  function showPhishingOverlay(result, url) {
    removeExisting('pg-overlay');

    const rawSignals = result.signals || [];
    const signals = rawSignals.length > 0 ? rawSignals : [
      { signal: 'High Threat Probability', severity: 'critical', description: 'ML classification model flagged suspicious URL/domain structural indicators.' }
    ];
    const riskScore = result.risk_score || 0;
    const C = 2 * Math.PI * 38;
    const offset = C - (riskScore / 100) * C;

    const overlay = document.createElement('div');
    overlay.id = 'pg-overlay';
    overlay.innerHTML = `
      <style>
        #pg-overlay {
          position: fixed !important;
          inset: 0 !important;
          z-index: 2147483647 !important;
          background: rgba(6, 10, 18, 0.95) !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif !important;
          backdrop-filter: blur(16px) !important;
          animation: pgFade 0.3s cubic-bezier(0.16, 1, 0.3, 1) !important;
          padding: 20px !important;
          margin: 0 !important;
        }
        @keyframes pgFade { from { opacity: 0; } to { opacity: 1; } }
        #pg-overlay * { box-sizing: border-box !important; margin: 0; padding: 0; }
        
        .pg-box {
          background: linear-gradient(180deg, #111827 0%, #0b1120 100%) !important;
          border: 1px solid rgba(244, 63, 94, 0.3) !important;
          border-radius: 24px !important;
          padding: 32px !important;
          max-width: 520px !important;
          width: 92vw !important;
          max-height: 90vh !important;
          overflow-y: auto !important;
          display: flex !important;
          flex-direction: column !important;
          align-items: center !important;
          text-align: center !important;
          box-shadow: 0 0 0 1px rgba(244, 63, 94, 0.1), 0 30px 80px rgba(0, 0, 0, 0.85), 0 0 45px rgba(244, 63, 94, 0.15) !important;
          animation: pgScale 0.35s cubic-bezier(0.34, 1.56, 0.64, 1) !important;
          position: relative !important;
        }
        .pg-box::-webkit-scrollbar { width: 4px; }
        .pg-box::-webkit-scrollbar-thumb { background: rgba(244, 63, 94, 0.3); border-radius: 4px; }
        @keyframes pgScale { from { transform: scale(0.92); opacity: 0; } to { transform: scale(1); opacity: 1; } }

        .pg-badge-header {
          display: inline-flex !important;
          align-items: center !important;
          justify-content: center !important;
          gap: 8px !important;
          background: rgba(244, 63, 94, 0.1) !important;
          border: 1px solid rgba(244, 63, 94, 0.25) !important;
          border-radius: 30px !important;
          padding: 6px 14px !important;
          margin: 0 auto 16px !important;
          color: #f43f5e !important;
          font-size: 0.72rem !important;
          font-weight: 700 !important;
          letter-spacing: 1.2px !important;
          text-transform: uppercase !important;
        }

        .pg-shield-icon {
          width: 64px !important;
          height: 64px !important;
          margin: 0 auto 14px !important;
          background: radial-gradient(circle, rgba(244, 63, 94, 0.18) 0%, rgba(244, 63, 94, 0.04) 100%) !important;
          border: 1px solid rgba(244, 63, 94, 0.3) !important;
          border-radius: 20px !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          color: #f43f5e !important;
          box-shadow: 0 0 30px rgba(244, 63, 94, 0.22) !important;
          animation: pgGlow 2.5s ease-in-out infinite !important;
        }
        @keyframes pgGlow {
          0%, 100% { transform: scale(1); box-shadow: 0 0 20px rgba(244, 63, 94, 0.2); }
          50% { transform: scale(1.05); box-shadow: 0 0 34px rgba(244, 63, 94, 0.4); }
        }

        .pg-title {
          font-size: 1.45rem !important;
          font-weight: 800 !important;
          color: #f8fafc !important;
          letter-spacing: -0.3px !important;
          margin: 0 auto 6px !important;
          line-height: 1.25 !important;
          text-align: center !important;
          width: 100% !important;
        }
        .pg-title-red {
          color: #f43f5e !important;
        }
        .pg-sub {
          font-size: 0.85rem !important;
          color: #94a3b8 !important;
          margin: 0 auto 20px !important;
          line-height: 1.45 !important;
          text-align: center !important;
          width: 100% !important;
        }

        .pg-url-card {
          background: rgba(15, 23, 42, 0.7) !important;
          border: 1px solid rgba(255, 255, 255, 0.08) !important;
          border-radius: 12px !important;
          padding: 10px 14px !important;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
          font-size: 0.75rem !important;
          color: #e2e8f0 !important;
          word-break: break-all !important;
          margin: 0 auto 22px !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          gap: 10px !important;
          width: 100% !important;
        }
        .pg-url-text {
          overflow: hidden !important;
          text-overflow: ellipsis !important;
          white-space: nowrap !important;
          max-width: 100% !important;
        }

        .pg-mid {
          display: flex !important;
          align-items: center !important;
          gap: 18px !important;
          margin: 0 auto 24px !important;
          text-align: left !important;
          background: rgba(15, 23, 42, 0.5) !important;
          border: 1px solid rgba(255, 255, 255, 0.06) !important;
          border-radius: 16px !important;
          padding: 16px !important;
          width: 100% !important;
        }
        .pg-gauge-wrap {
          width: 84px !important;
          height: 84px !important;
          flex-shrink: 0 !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
        }
        .pg-svg {
          width: 100% !important;
          height: 100% !important;
        }

        .pg-signals-wrap {
          flex: 1 !important;
          min-width: 0 !important;
          display: flex !important;
          flex-direction: column !important;
          gap: 6px !important;
        }
        .pg-sl-ttl {
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
          font-size: 0.64rem !important;
          color: #64748b !important;
          letter-spacing: 1.5px !important;
          text-transform: uppercase !important;
          margin-bottom: 4px !important;
          font-weight: 700 !important;
        }
        .pg-sig {
          display: flex !important;
          align-items: flex-start !important;
          gap: 8px !important;
          padding: 8px 10px !important;
          background: rgba(255, 255, 255, 0.025) !important;
          border-left: 3px solid #f43f5e !important;
          border-radius: 6px !important;
        }
        .pg-sig.critical { border-left-color: #f43f5e !important; background: rgba(244, 63, 94, 0.06) !important; }
        .pg-sig.high { border-left-color: #f97316 !important; background: rgba(249, 115, 22, 0.06) !important; }
        .pg-sig.medium { border-left-color: #eab308 !important; background: rgba(234, 179, 8, 0.06) !important; }
        .pg-sig.low { border-left-color: #38bdf8 !important; background: rgba(56, 189, 248, 0.06) !important; }

        .pg-sn {
          font-size: 0.78rem !important;
          font-weight: 600 !important;
          color: #f8fafc !important;
          margin-bottom: 2px !important;
          line-height: 1.3 !important;
        }
        .pg-sd {
          font-size: 0.68rem !important;
          color: #94a3b8 !important;
          line-height: 1.4 !important;
        }

        .pg-btns {
          display: flex !important;
          gap: 12px !important;
          margin: 0 auto 18px !important;
          width: 100% !important;
        }
        .pg-leave {
          flex: 1 1 50% !important;
          height: 46px !important;
          padding: 0 16px !important;
          background: linear-gradient(135deg, #e11d48, #f43f5e) !important;
          border: none !important;
          border-radius: 12px !important;
          color: #ffffff !important;
          font-size: 0.85rem !important;
          font-weight: 700 !important;
          cursor: pointer !important;
          box-shadow: 0 4px 20px rgba(244, 63, 94, 0.35) !important;
          transition: transform 0.2s ease, box-shadow 0.2s ease !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          gap: 8px !important;
          white-space: nowrap !important;
          min-width: 0 !important;
          overflow: hidden !important;
          text-overflow: ellipsis !important;
        }
        .pg-leave:hover {
          transform: translateY(-2px) !important;
          box-shadow: 0 6px 26px rgba(244, 63, 94, 0.55) !important;
        }
        .pg-stay {
          flex: 1 1 50% !important;
          height: 46px !important;
          padding: 0 16px !important;
          background: rgba(255, 255, 255, 0.04) !important;
          border: 1px solid rgba(255, 255, 255, 0.12) !important;
          border-radius: 12px !important;
          color: #94a3b8 !important;
          font-size: 0.82rem !important;
          font-weight: 600 !important;
          cursor: pointer !important;
          transition: background 0.2s ease, color 0.2s ease, border-color 0.2s ease !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          white-space: nowrap !important;
          min-width: 0 !important;
          overflow: hidden !important;
          text-overflow: ellipsis !important;
        }
        .pg-stay:hover {
          background: rgba(255, 255, 255, 0.09) !important;
          color: #f8fafc !important;
          border-color: rgba(255, 255, 255, 0.2) !important;
        }

        .pg-links {
          display: flex !important;
          gap: 16px !important;
          justify-content: center !important;
          align-items: center !important;
          padding-top: 12px !important;
          border-top: 1px solid rgba(255, 255, 255, 0.06) !important;
          width: 100% !important;
        }
        .pg-link {
          background: none !important;
          border: none !important;
          font-size: 0.72rem !important;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
          cursor: pointer !important;
          transition: color 0.2s ease, background 0.2s ease !important;
          padding: 5px 12px !important;
          border-radius: 8px !important;
        }
        .pg-rescan { color: #38bdf8 !important; }
        .pg-rescan:hover { color: #ffffff !important; background: rgba(56, 189, 248, 0.15) !important; }
        .pg-report { color: #eab308 !important; }
        .pg-report:hover { color: #ffffff !important; background: rgba(234, 179, 8, 0.15) !important; }
      </style>
      <div class="pg-box">
        <div class="pg-badge-header">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          PhishGuard Security Engine
        </div>
        <div class="pg-shield-icon">
          <svg xmlns="http://www.w3.org/2000/svg" width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
        </div>
        <div class="pg-title"><span class="pg-title-red">Phishing Site</span> Detected</div>
        <div class="pg-sub">PhishGuard AI identified severe security risks on this website</div>
        <div class="pg-url-card">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20"/><path d="M2 12h20"/></svg>
          <span class="pg-url-text">${esc(url)}</span>
        </div>
        <div class="pg-mid">
          <div class="pg-gauge-wrap">
            <svg class="pg-svg" viewBox="0 0 90 90">
              <circle cx="45" cy="45" r="38" fill="none" stroke="rgba(255,255,255,.05)" stroke-width="7"/>
              <circle cx="45" cy="45" r="38" fill="none" stroke="#f43f5e" stroke-width="7"
                stroke-dasharray="${C.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"
                stroke-linecap="round" transform="rotate(-90 45 45)" style="filter:drop-shadow(0 0 8px #f43f5e)"/>
              <text x="45" y="42" text-anchor="middle" fill="#f43f5e" font-size="16" font-weight="800" font-family="ui-monospace, monospace">${riskScore}%</text>
              <text x="45" y="55" text-anchor="middle" fill="rgba(255,255,255,.4)" font-size="5.5" font-family="ui-monospace, monospace" letter-spacing="1.5">THREAT</text>
            </svg>
          </div>
          <div class="pg-signals-wrap">
            <div class="pg-sl-ttl">DETECTION SIGNALS</div>
            ${signals.slice(0, 3).map(s => `
              <div class="pg-sig ${s.severity || 'critical'}">
                <div style="min-width:0;">
                  <div class="pg-sn">${esc(s.signal)}</div>
                  <div class="pg-sd">${esc(s.description)}</div>
                </div>
              </div>`).join('')}
          </div>
        </div>
        <div class="pg-btns">
          <button class="pg-leave" id="pg-leave-btn">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
            Leave Website Now
          </button>
          <button class="pg-stay" id="pg-stay-btn">Continue Anyway</button>
        </div>
        <div class="pg-links">
          <button class="pg-link pg-rescan" id="pg-rescan-btn">↺ Re-Scan Page</button>
          <button class="pg-link pg-report" id="pg-report-btn">⚑ Report False Positive</button>
        </div>
      </div>`;

    document.body.appendChild(overlay);

    document.getElementById('pg-leave-btn').onclick = () => {
      chrome.runtime.sendMessage({ type: 'LEAVE_SITE' });
    };
    document.getElementById('pg-stay-btn').onclick = () => {
      overlay.style.transition = 'opacity .3s';
      overlay.style.opacity = '0';
      setTimeout(() => { overlay.remove(); overlayActive = false; }, 300);
    };
    document.getElementById('pg-rescan-btn').onclick = () => {
      overlay.remove();
      overlayActive = false;
      chrome.runtime.sendMessage({ type: 'SCAN_URL', url: window.location.href });
    };
    document.getElementById('pg-report-btn').onclick = () => {
      chrome.runtime.sendMessage({ type: 'REPORT_FALSE_POSITIVE', url }, (res) => {
        const btn = document.getElementById('pg-report-btn');
        if (btn) btn.textContent = res && res.success ? '✓ Reported — Thank you' : '✗ Could not reach server';
      });
    };
  }

  // ─── 2. SUSPICIOUS — top banner (Stitch UI Design) ───────────────────────────

  function showSuspiciousBanner(result, url) {
    removeExisting('pg-banner');
    const topSignal = result.signals && result.signals[0];

    const banner = document.createElement('div');
    banner.id = 'pg-banner';
    banner.innerHTML = `
      <style>
        #pg-banner {
          position: fixed !important;
          top: 0 !important; left: 0 !important; right: 0 !important;
          z-index: 2147483646 !important;
          background: linear-gradient(180deg, #1e1b18 0%, #15120e 100%) !important;
          border-bottom: 2px solid rgba(234, 179, 8, 0.5) !important;
          box-shadow: 0 4px 30px rgba(234, 179, 8, 0.2) !important;
          display: flex !important;
          align-items: center !important;
          gap: 14px !important;
          padding: 12px 22px !important;
          font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif !important;
          animation: pgSlide 0.4s cubic-bezier(0.16, 1, 0.3, 1) !important;
        }
        @keyframes pgSlide { from { transform: translateY(-100%); } to { transform: translateY(0); } }
        #pg-banner * { box-sizing: border-box !important; }
        .pgb-icon {
          width: 32px !important;
          height: 32px !important;
          border-radius: 8px !important;
          background: rgba(234, 179, 8, 0.15) !important;
          border: 1px solid rgba(234, 179, 8, 0.3) !important;
          color: #eab308 !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          flex-shrink: 0 !important;
        }
        .pgb-text { flex: 1 !important; min-width: 0 !important; }
        .pgb-title { font-size: 0.88rem !important; font-weight: 700 !important; color: #eab308 !important; margin-bottom: 2px !important; letter-spacing: 0.2px !important; }
        .pgb-sub { font-size: 0.74rem !important; color: #cbd5e1 !important; overflow: hidden !important; text-overflow: ellipsis !important; white-space: nowrap !important; }
        .pgb-score {
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
          font-size: 1.25rem !important;
          font-weight: 700 !important;
          color: #eab308 !important;
          flex-shrink: 0 !important;
          background: rgba(234, 179, 8, 0.1) !important;
          padding: 4px 10px !important;
          border-radius: 8px !important;
          border: 1px solid rgba(234, 179, 8, 0.25) !important;
        }
        .pgb-close {
          background: rgba(255, 255, 255, 0.05) !important;
          border: 1px solid rgba(255, 255, 255, 0.12) !important;
          border-radius: 8px !important;
          color: #94a3b8 !important;
          font-size: 0.75rem !important;
          padding: 6px 14px !important;
          cursor: pointer !important;
          flex-shrink: 0 !important;
          transition: all 0.2s !important;
        }
        .pgb-close:hover { background: rgba(255, 255, 255, 0.12) !important; color: #fff !important; }
      </style>
      <div class="pgb-icon">
        <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      </div>
      <div class="pgb-text">
        <div class="pgb-title">PhishGuard AI — Suspicious Site</div>
        <div class="pgb-sub">${topSignal ? esc(topSignal.signal) + ' — ' + esc(topSignal.description) : esc(url)}</div>
      </div>
      <span class="pgb-score">${result.risk_score}%</span>
      <button class="pgb-close" id="pgb-close">Dismiss ✕</button>`;

    document.body.appendChild(banner);
    document.getElementById('pgb-close').onclick = () => dismissBanner(banner);
    setTimeout(() => { if (document.getElementById('pg-banner')) dismissBanner(banner); }, 8000);
  }

  function dismissBanner(banner) {
    banner.style.transition = 'transform .3s, opacity .3s';
    banner.style.transform = 'translateY(-100%)';
    banner.style.opacity = '0';
    setTimeout(() => banner.remove(), 300);
  }

  // ─── 3. SAFE — bottom-right toast (Stitch UI Design) ─────────────────────────

  function showSafeToast(result) {
    removeExisting('pg-toast');
    const toast = document.createElement('div');
    toast.id = 'pg-toast';
    toast.innerHTML = `
      <style>
        #pg-toast {
          position: fixed !important;
          bottom: 24px !important; right: 24px !important;
          z-index: 2147483646 !important;
          background: linear-gradient(180deg, #062016 0%, #03150d 100%) !important;
          border: 1px solid rgba(16, 185, 129, 0.4) !important;
          border-radius: 14px !important;
          padding: 12px 18px !important;
          display: flex !important;
          align-items: center !important;
          gap: 12px !important;
          box-shadow: 0 8px 30px rgba(0, 0, 0, 0.6), 0 0 20px rgba(16, 185, 129, 0.15) !important;
          font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Segoe UI', Roboto, sans-serif !important;
          animation: pgToastIn 0.4s cubic-bezier(0.16, 1, 0.3, 1) !important;
          max-width: 320px !important;
        }
        @keyframes pgToastIn { from { transform: translateX(120%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        #pg-toast * { box-sizing: border-box !important; }
        .pgt-icon {
          width: 28px !important;
          height: 28px !important;
          border-radius: 50% !important;
          background: rgba(16, 185, 129, 0.15) !important;
          border: 1px solid rgba(16, 185, 129, 0.3) !important;
          color: #10b981 !important;
          display: flex !important;
          align-items: center !important;
          justify-content: center !important;
          flex-shrink: 0 !important;
        }
        .pgt-text { flex: 1 !important; min-width: 0 !important; }
        .pgt-title { font-size: 0.82rem !important; font-weight: 700 !important; color: #10b981 !important; margin-bottom: 2px !important; }
        .pgt-sub { font-size: 0.7rem !important; color: #94a3b8 !important; }
        .pgt-score {
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace !important;
          font-size: 1.1rem !important;
          font-weight: 700 !important;
          color: #10b981 !important;
          flex-shrink: 0 !important;
          background: rgba(16, 185, 129, 0.1) !important;
          padding: 2px 8px !important;
          border-radius: 6px !important;
          border: 1px solid rgba(16, 185, 129, 0.25) !important;
        }
      </style>
      <div class="pgt-icon">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>
      </div>
      <div class="pgt-text">
        <div class="pgt-title">PhishGuard AI — Site is Safe</div>
        <div class="pgt-sub">No threat indicators detected</div>
      </div>
      <span class="pgt-score">${result.risk_score}%</span>`;

    document.body.appendChild(overlay);
    setTimeout(() => {
      if (document.getElementById('pg-toast')) {
        toast.style.transition = 'transform .4s, opacity .4s';
        toast.style.transform = 'translateX(120%)';
        toast.style.opacity = '0';
        setTimeout(() => toast.remove(), 400);
      }
    }, 4000);
  }

  // ─── Helpers ─────────────────────────────────────────────────────────────────

  function removeExisting(id) {
    const el = document.getElementById(id);
    if (el) el.remove();
  }

  function esc(s) {
    const d = document.createElement('div');
    d.textContent = String(s || '');
    return d.innerHTML;
  }

})();
