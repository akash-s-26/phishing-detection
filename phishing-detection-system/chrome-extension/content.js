/**
 * content.js — PhishGuard AI Content Script
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

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === 'SCAN_COMPLETE') handleResult(msg.result, msg.url);
    sendResponse({ ok: true });
  });

  function handleResult(result, url) {
    if (!result) return;
    const { prediction } = result;
    if (prediction === 'phishing' && !overlayActive) {
      showPhishingOverlay(result, url);
      overlayActive = true;
    } else if (prediction === 'suspicious') {
      showSuspiciousBanner(result, url);
    } else if (prediction === 'safe') {
      showSafeToast(result);
    }
  }

  // ─── 1. PHISHING — full-page overlay ────────────────────────────────────────

  function showPhishingOverlay(result, url) {
    removeExisting('pg-overlay');

    const signals = result.signals || [];
    const riskScore = result.risk_score || 0;
    const C = 2 * Math.PI * 36;
    const offset = C - (riskScore / 100) * C;

    const overlay = document.createElement('div');
    overlay.id = 'pg-overlay';
    overlay.innerHTML = `
      <style>
        #pg-overlay{position:fixed;inset:0;z-index:2147483647;background:rgba(4,7,14,.97);
          display:flex;align-items:center;justify-content:center;font-family:'Segoe UI',system-ui,sans-serif;
          backdrop-filter:blur(10px);animation:pgFade .35s ease}
        @keyframes pgFade{from{opacity:0}to{opacity:1}}
        #pg-overlay *{box-sizing:border-box;margin:0;padding:0}
        .pg-box{background:linear-gradient(145deg,#0d1520,#080e1a);border:1px solid rgba(255,34,68,.4);
          border-radius:20px;padding:40px 44px;max-width:560px;width:92vw;text-align:center;
          box-shadow:0 0 0 1px rgba(255,34,68,.12),0 40px 80px rgba(0,0,0,.85),0 0 70px rgba(255,34,68,.18);
          animation:pgPop .45s cubic-bezier(.34,1.56,.64,1)}
        @keyframes pgPop{from{transform:scale(.82);opacity:0}to{transform:scale(1);opacity:1}}
        .pg-icon-wrap{position:relative;width:84px;height:84px;margin:0 auto 22px;display:flex;align-items:center;justify-content:center}
        .pg-ring{position:absolute;inset:0;border-radius:50%;border:2px solid rgba(255,34,68,.4);animation:pgRing 1.6s ease-out infinite}
        .pg-ring:nth-child(2){animation-delay:.53s}.pg-ring:nth-child(3){animation-delay:1.06s}
        @keyframes pgRing{0%{transform:scale(.7);opacity:.9}100%{transform:scale(1.9);opacity:0}}
        .pg-shield{font-size:3rem;filter:drop-shadow(0 0 18px #ff2244);z-index:1;animation:pgShake .6s ease .4s both}
        @keyframes pgShake{0%{transform:rotate(-10deg)}25%{transform:rotate(10deg)}50%{transform:rotate(-6deg)}75%{transform:rotate(6deg)}100%{transform:rotate(0)}}
        .pg-title{font-size:1.55rem;font-weight:800;color:#ff2244;text-shadow:0 0 24px rgba(255,34,68,.6);letter-spacing:1px;margin-bottom:6px}
        .pg-sub{font-size:.85rem;color:rgba(255,255,255,.4);margin-bottom:22px}
        .pg-url{background:rgba(255,34,68,.07);border:1px solid rgba(255,34,68,.2);border-radius:8px;padding:8px 14px;
          font-family:monospace;font-size:.75rem;color:rgba(255,255,255,.45);word-break:break-all;margin-bottom:22px}
        .pg-mid{display:flex;align-items:center;gap:18px;margin-bottom:24px;text-align:left}
        .pg-svg{width:90px;height:90px;flex-shrink:0}
        .pg-sl-ttl{font-size:.6rem;color:rgba(255,255,255,.3);letter-spacing:2px;text-transform:uppercase;margin-bottom:7px}
        .pg-sig{display:flex;align-items:flex-start;gap:7px;padding:6px 9px;background:rgba(255,255,255,.03);
          border-left:3px solid rgba(255,34,68,.5);border-radius:4px;margin-bottom:5px}
        .pg-sig.med{border-left-color:rgba(255,170,0,.5)}.pg-sig.low{border-left-color:rgba(100,180,255,.5)}
        .pg-sn{font-size:.75rem;font-weight:600;color:rgba(255,255,255,.8);margin-bottom:2px}
        .pg-sd{font-size:.68rem;color:rgba(255,255,255,.35);line-height:1.4}
        .pg-btns{display:flex;gap:10px;margin-bottom:14px}
        .pg-leave{flex:1;padding:13px 0;background:linear-gradient(135deg,#cc0022,#ff2244);border:none;border-radius:10px;
          color:#fff;font-size:.9rem;font-weight:700;cursor:pointer;box-shadow:0 0 22px rgba(255,34,68,.45);transition:.2s;letter-spacing:.5px}
        .pg-leave:hover{transform:translateY(-2px);box-shadow:0 6px 28px rgba(255,34,68,.65)}
        .pg-stay{padding:13px 18px;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);
          border-radius:10px;color:rgba(255,255,255,.4);font-size:.82rem;cursor:pointer;transition:.2s}
        .pg-stay:hover{background:rgba(255,255,255,.09);color:rgba(255,255,255,.7)}
        .pg-links{display:flex;gap:18px;justify-content:center}
        .pg-link{background:none;border:none;font-size:.7rem;cursor:pointer;text-decoration:underline;transition:.2s}
        .pg-rescan{color:rgba(77,159,255,.7)}.pg-rescan:hover{color:rgba(77,159,255,1)}
        .pg-report{color:rgba(255,180,0,.6)}.pg-report:hover{color:rgba(255,180,0,.9)}
      </style>
      <div class="pg-box">
        <div class="pg-icon-wrap">
          <div class="pg-ring"></div><div class="pg-ring"></div><div class="pg-ring"></div>
          <span class="pg-shield">🛡</span>
        </div>
        <div class="pg-title">⚠ PHISHING SITE DETECTED</div>
        <div class="pg-sub">PhishGuard AI identified this as a phishing threat</div>
        <div class="pg-url">${esc(url)}</div>
        <div class="pg-mid">
          <svg class="pg-svg" viewBox="0 0 90 90">
            <circle cx="45" cy="45" r="36" fill="none" stroke="rgba(255,255,255,.05)" stroke-width="8"/>
            <circle cx="45" cy="45" r="36" fill="none" stroke="#ff2244" stroke-width="8"
              stroke-dasharray="${C.toFixed(2)}" stroke-dashoffset="${offset.toFixed(2)}"
              stroke-linecap="round" transform="rotate(-90 45 45)" style="filter:drop-shadow(0 0 8px #ff2244)"/>
            <text x="45" y="41" text-anchor="middle" fill="#ff2244" font-size="16" font-weight="700" font-family="monospace">${riskScore}%</text>
            <text x="45" y="53" text-anchor="middle" fill="rgba(255,255,255,.3)" font-size="5.5" font-family="monospace" letter-spacing="1">RISK</text>
          </svg>
          <div style="flex:1">
            <div class="pg-sl-ttl">Detection Signals</div>
            ${signals.slice(0, 4).map(s => `
              <div class="pg-sig ${s.severity === 'medium' ? 'med' : s.severity === 'low' ? 'low' : ''}">
                <div><div class="pg-sn">${esc(s.signal)}</div><div class="pg-sd">${esc(s.description)}</div></div>
              </div>`).join('')}
          </div>
        </div>
        <div class="pg-btns">
          <button class="pg-leave" id="pg-leave-btn">🚫 Leave Website Now</button>
          <button class="pg-stay" id="pg-stay-btn">Continue Anyway</button>
        </div>
        <div class="pg-links">
          <button class="pg-link pg-rescan" id="pg-rescan-btn">↺ Re-Scan</button>
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

  // ─── 2. SUSPICIOUS — top banner ──────────────────────────────────────────────

  function showSuspiciousBanner(result, url) {
    removeExisting('pg-banner');
    const topSignal = result.signals && result.signals[0];

    const banner = document.createElement('div');
    banner.id = 'pg-banner';
    banner.innerHTML = `
      <style>
        #pg-banner{position:fixed;top:0;left:0;right:0;z-index:2147483646;
          background:linear-gradient(135deg,#1a1200,#2a1e00);border-bottom:2px solid rgba(255,170,0,.5);
          box-shadow:0 4px 30px rgba(255,170,0,.2);display:flex;align-items:center;gap:14px;padding:12px 20px;
          font-family:'Segoe UI',system-ui,sans-serif;animation:pgSlide .4s cubic-bezier(.34,1.56,.64,1)}
        @keyframes pgSlide{from{transform:translateY(-100%)}to{transform:translateY(0)}}
        #pg-banner *{box-sizing:border-box}
        .pgb-icon{font-size:1.5rem;filter:drop-shadow(0 0 8px #ffaa00);flex-shrink:0}
        .pgb-text{flex:1}.pgb-title{font-size:.88rem;font-weight:700;color:#ffaa00;margin-bottom:2px}
        .pgb-sub{font-size:.72rem;color:rgba(255,220,100,.55)}
        .pgb-score{font-family:monospace;font-size:1.4rem;font-weight:700;color:#ffaa00;flex-shrink:0;filter:drop-shadow(0 0 8px #ffaa00)}
        .pgb-close{background:none;border:1px solid rgba(255,170,0,.25);border-radius:6px;color:rgba(255,220,100,.6);
          font-size:.75rem;padding:5px 12px;cursor:pointer;flex-shrink:0;transition:.2s}
        .pgb-close:hover{background:rgba(255,170,0,.1);color:#ffaa00}
      </style>
      <span class="pgb-icon">⚠</span>
      <div class="pgb-text">
        <div class="pgb-title">PhishGuard AI — Suspicious Website</div>
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

  // ─── 3. SAFE — bottom-right toast ────────────────────────────────────────────

  function showSafeToast(result) {
    removeExisting('pg-toast');
    const toast = document.createElement('div');
    toast.id = 'pg-toast';
    toast.innerHTML = `
      <style>
        #pg-toast{position:fixed;bottom:24px;right:24px;z-index:2147483646;
          background:linear-gradient(135deg,#011a0d,#021408);border:1px solid rgba(0,204,102,.35);border-radius:12px;
          padding:12px 18px;display:flex;align-items:center;gap:10px;
          box-shadow:0 4px 24px rgba(0,0,0,.5),0 0 20px rgba(0,204,102,.12);
          font-family:'Segoe UI',system-ui,sans-serif;animation:pgToastIn .4s cubic-bezier(.34,1.56,.64,1);max-width:300px}
        @keyframes pgToastIn{from{transform:translateX(120%);opacity:0}to{transform:translateX(0);opacity:1}}
        #pg-toast *{box-sizing:border-box}
        .pgt-icon{font-size:1.3rem;filter:drop-shadow(0 0 8px #00cc66);flex-shrink:0}
        .pgt-text{flex:1}.pgt-title{font-size:.8rem;font-weight:700;color:#00cc66;margin-bottom:1px}
        .pgt-sub{font-size:.67rem;color:rgba(0,200,100,.45)}
        .pgt-score{font-family:monospace;font-size:1.1rem;font-weight:700;color:#00cc66;flex-shrink:0;filter:drop-shadow(0 0 6px #00cc66)}
      </style>
      <span class="pgt-icon">✓</span>
      <div class="pgt-text"><div class="pgt-title">PhishGuard AI — Site is Safe</div><div class="pgt-sub">No threats detected</div></div>
      <span class="pgt-score">${result.risk_score}%</span>`;

    document.body.appendChild(toast);
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
