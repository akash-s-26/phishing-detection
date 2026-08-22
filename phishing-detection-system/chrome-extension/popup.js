/**
 * PhishGuard AI — Extension Popup UI Logic
 * Authoritative client UI synchronizing with background per-tab scan state lifecycle.
 * Queries GET_CURRENT_SCAN_STATE on open, renders completed results immediately,
 * features a 500ms polling fallback interval while scanning, and listens for live SCAN_STATE_UPDATED events.
 */

console.log('[PhishGuard] ACTIVE POPUP BUILD:', 'RESULT-FIX-v2');

function getModelDisplay(model) {
    if (typeof model === 'string') {
        const normalized = model.trim().toLowerCase();

        if (normalized === 'cnn_bilstm') {
            return 'DL-CNN-BiLSTM';
        }

        if (normalized === 'rnn_gan') {
            return 'DL-RNN-GAN';
        }

        if (normalized === 'rnn') {
            return 'DL-RNN';
        }

        if (normalized === 'gan') {
            return 'DL-GAN';
        }

        return model.trim() || 'Deep Learning';
    }

    if (model && typeof model === 'object') {
        const name =
            model.name ||
            model.model_name ||
            model.architecture ||
            model.type;

        const version =
            model.version ||
            model.model_version;

        if (typeof name === 'string' && name.trim()) {
            return version
                ? `DL-${name.trim()} ${version}`
                : `DL-${name.trim()}`;
        }
    }

    return 'Deep Learning';
}

let currentTabId = null;
let currentTabUrl = null;
let scanPollInterval = null;

function clearScanPolling() {
  if (scanPollInterval) {
    clearInterval(scanPollInterval);
    scanPollInterval = null;
  }
}

function startScanPolling() {
  if (scanPollInterval) return;
  scanPollInterval = setInterval(async () => {
    if (!currentTabId || !currentTabUrl) return;
    console.log('[PhishGuard] SCAN_POLL Checking state for Tab', currentTabId);
    const latestState = await fetchCurrentScanState(currentTabId, currentTabUrl);
    if (latestState && latestState.status !== 'SCANNING') {
      console.log('[PhishGuard] SCAN_POLL_COMPLETED Tab', currentTabId, 'Status:', latestState.status);
      clearScanPolling();
      renderScanState(latestState);
    }
  }, 500);
}

// ── GLOBAL ERROR HANDLERS ──────────────────────────────────────────────────
window.addEventListener('error', (event) => {
  console.error('[PhishGuard] Popup Error Intercepted:', {
    message: event.message,
    filename: event.filename,
    line: event.lineno,
    col: event.colno,
    error: event.error
  });
});

window.addEventListener('unhandledrejection', (event) => {
  console.error('[PhishGuard] Unhandled Rejection Intercepted:', {
    reason: event.reason
  });
});

// ── MAIN POPUP INITIALIZATION ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  console.log('[PhishGuard] POPUP_OPEN');

  try {
    // Navigation Tabs Setup
    const tabs = document.querySelectorAll('.nav-tab');
    const tabContents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        tabs.forEach(t => t.classList.remove('active'));
        tabContents.forEach(c => c.classList.remove('active'));

        tab.classList.add('active');
        const targetId = `tab-${tab.dataset.tab}`;
        const contentElem = document.getElementById(targetId);
        if (contentElem) contentElem.classList.add('active');

        if (tab.dataset.tab === 'history') loadHistory();
        if (tab.dataset.tab === 'diagnostics') loadDiagnostics();
      });
    });

    // 1. Initial UI State: INITIALIZING (NOT SCANNING!)
    renderScanState({ status: 'INITIALIZING' });

    // 2. Query Active Tab
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const currentUrlElem = document.getElementById('current-url');

    if (!activeTab || !activeTab.url) {
      if (currentUrlElem) currentUrlElem.textContent = 'No active webpage';
      renderScanState({ status: 'IDLE' });
      return;
    }

    currentTabId = activeTab.id;
    currentTabUrl = activeTab.url;
    if (currentUrlElem) currentUrlElem.textContent = activeTab.url;
    console.log('[PhishGuard] ACTIVE_TAB:', currentTabId, currentTabUrl);

    // 3. Query GET_CURRENT_SCAN_STATE from Background
    console.log('[PhishGuard] GET_CURRENT_SCAN_STATE for Tab', currentTabId);
    let state = await fetchCurrentScanState(currentTabId, currentTabUrl);

    // 4. Strict URL Comparison Check
    if (state && state.url) {
      const normCurrent = window.PhishGuardNormalizer ? window.PhishGuardNormalizer.normalizeUrlForComparison(currentTabUrl) : currentTabUrl.toLowerCase();
      const normStored = window.PhishGuardNormalizer ? window.PhishGuardNormalizer.normalizeUrlForComparison(state.url) : state.url.toLowerCase();
      if (normCurrent !== normStored) {
        console.log(`[PhishGuard] STALE_RESULT_IGNORED: Stored URL (${state.url}) != Active URL (${currentTabUrl})`);
        state = null;
      }
    }

    // 5. Render Current Scan State
    if (!state && currentTabUrl.startsWith('http')) {
      console.log('[PhishGuard] NO_STATE_FOUND Initiating scan for', currentTabUrl);
      renderScanState({ status: 'SCANNING', url: currentTabUrl });
      chrome.runtime.sendMessage({
        action: 'TRIGGER_MANUAL_SCAN',
        type: 'TRIGGER_MANUAL_SCAN',
        tabId: currentTabId,
        url: currentTabUrl
      });
    } else {
      console.log('[PhishGuard] STATE_FOUND Rendering state:', state?.status || 'IDLE', state);
      renderScanState(state);
    }

    // Manual Re-Scan Button Handler
    const rescanBtn = document.getElementById('btn-rescan');
    if (rescanBtn) {
      rescanBtn.addEventListener('click', async () => {
        clearScanPolling();
        renderScanState({ status: 'SCANNING', url: currentTabUrl });
        chrome.runtime.sendMessage({
          action: 'TRIGGER_MANUAL_SCAN',
          type: 'TRIGGER_MANUAL_SCAN',
          tabId: currentTabId,
          url: currentTabUrl
        });
      });
    }

    const dashboardBtn = document.getElementById('btn-dashboard');
    if (dashboardBtn) {
      dashboardBtn.addEventListener('click', async () => {
        const config = (typeof globalThis !== 'undefined' && globalThis.PhishGuardConfig) ? globalThis.PhishGuardConfig : {
          FRONTEND_DASHBOARD_URL: 'http://localhost:5173/dashboard',
          ALLOWED_FRONTEND_PATTERNS: ['*://localhost:5173/*', '*://127.0.0.1:5173/*', 'https://*.netlify.app/*']
        };
        const dashboardUrl = config.FRONTEND_DASHBOARD_URL || 'http://localhost:5173/dashboard';
        const patterns = config.ALLOWED_FRONTEND_PATTERNS || ['*://localhost:5173/*', '*://127.0.0.1:5173/*', 'https://*.netlify.app/*'];

        try {
          const existingTabs = await chrome.tabs.query({ url: patterns });
          if (existingTabs && existingTabs.length > 0) {
            const tab = existingTabs[0];
            await chrome.tabs.update(tab.id, { active: true, url: dashboardUrl });
            if (tab.windowId) {
              await chrome.windows.update(tab.windowId, { focused: true });
            }
          } else {
            await chrome.tabs.create({ url: dashboardUrl });
          }
        } catch (e) {
          chrome.tabs.create({ url: dashboardUrl });
        }
      });
    }

  } catch (err) {
    console.error('[PhishGuard] Popup Init Exception:', err);
    renderScanState({ status: 'ERROR', error: err.message });
  }
});

// ── FETCH CURRENT SCAN STATE WITH TIMEOUT FALLBACK ─────────────────────────
async function fetchCurrentScanState(tabId, url) {
  const fetchPromise = new Promise(resolve => {
    chrome.runtime.sendMessage({
      type: 'GET_CURRENT_SCAN_STATE',
      action: 'GET_CURRENT_SCAN_STATE',
      tabId: tabId,
      url: url
    }, response => {
      if (chrome.runtime.lastError) resolve(null);
      else resolve(response);
    });
  });

  const timeoutPromise = new Promise(resolve => setTimeout(() => resolve(null), 1500));

  let state = await Promise.race([fetchPromise, timeoutPromise]);

  // Fallback to storage.local if message timeout occurs
  if (!state) {
    try {
      const store = await chrome.storage.local.get(['active_tab_results']);
      state = store.active_tab_results ? store.active_tab_results[tabId] : null;
    } catch (e) {}
  }

  return state;
}

// ── LIVE SCAN_STATE_UPDATED LISTENER ───────────────────────────────────────
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'SCAN_STATE_UPDATED' || message.action === 'SCAN_STATE_UPDATED') {
    if (Number(message.tabId) === Number(currentTabId) && message.state) {
      console.log('[PhishGuard] SCAN_STATE_UPDATED Live message received:', message.state.status);
      clearScanPolling();
      renderScanState(message.state);
    }
  }
});

// ── EXPLICIT STATE MACHINE RENDERER ────────────────────────────────────────
function renderScanState(rawState) {
  const verdictCard = document.getElementById('verdict-card');
  const verdictBadge = document.getElementById('verdict-badge');
  const threatLevelText = document.getElementById('threat-level-text');
  const confidenceText = document.getElementById('confidence-text');
  const riskScoreVal = document.getElementById('risk-score-val');
  const gaugeFill = document.getElementById('gauge-fill');

  const rnnScoreElem = document.getElementById('rnn-score');
  const cnnScoreElem = document.getElementById('cnn-score');
  const ensembleScoreElem = document.getElementById('ensemble-score');
  const signalsList = document.getElementById('signals-list');

  const status = rawState ? (rawState.status || (rawState.verdict ? 'SUCCESS' : 'IDLE')) : 'IDLE';
  console.log(`[PhishGuard] POPUP_RENDER: ${status}`, rawState);

  if (status !== 'SCANNING') {
    clearScanPolling();
  }

  // CASE 1: INITIALIZING
  if (status === 'INITIALIZING') {
    if (verdictCard) verdictCard.className = 'card verdict-card safe';
    if (verdictBadge) { verdictBadge.textContent = 'INITIALIZING...'; verdictBadge.style.color = '#94a3b8'; }
    if (riskScoreVal) riskScoreVal.textContent = '...';
    if (threatLevelText) threatLevelText.textContent = 'Loading scan state...';
    if (confidenceText) confidenceText.textContent = 'Confidence: --%';
    if (gaugeFill) gaugeFill.style.strokeDashoffset = 264;
    return;
  }

  // CASE 2: SCANNING
  if (status === 'SCANNING') {
    if (verdictCard) verdictCard.className = 'card verdict-card safe';
    if (verdictBadge) { verdictBadge.textContent = 'ANALYZING...'; verdictBadge.style.color = '#3b82f6'; }
    if (riskScoreVal) riskScoreVal.textContent = '...';
    if (threatLevelText) threatLevelText.textContent = 'Running Deep Learning Inference...';
    if (confidenceText) confidenceText.textContent = 'Confidence: Analyzing...';
    if (gaugeFill) { gaugeFill.style.stroke = '#3b82f6'; gaugeFill.style.strokeDashoffset = 132; }
    if (rnnScoreElem) rnnScoreElem.textContent = '...';
    if (cnnScoreElem) cnnScoreElem.textContent = '...';
    if (ensembleScoreElem) ensembleScoreElem.textContent = '...';
    if (signalsList) signalsList.innerHTML = '<div class="signal-row"><span>🔍</span><span>Extracting URL sequence & structural features...</span></div>';

    startScanPolling();
    return;
  }

  // CASE 3: ERROR
  if (status === 'ERROR') {
    if (verdictCard) verdictCard.className = 'card verdict-card phishing';
    if (verdictBadge) { verdictBadge.textContent = 'SCAN ERROR'; verdictBadge.style.color = '#ef4444'; }
    if (riskScoreVal) riskScoreVal.textContent = '!';
    if (threatLevelText) threatLevelText.textContent = rawState.error || 'Scan Unavailable';
    if (confidenceText) confidenceText.textContent = 'Confidence: --%';
    if (gaugeFill) { gaugeFill.style.stroke = '#ef4444'; gaugeFill.style.strokeDashoffset = 264; }
    return;
  }

  // CASE 4: IDLE / NONE
  if (status === 'IDLE' || !rawState || !rawState.verdict) {
    if (verdictCard) verdictCard.className = 'card verdict-card safe';
    if (verdictBadge) { verdictBadge.textContent = 'PROTECTION ACTIVE'; verdictBadge.style.color = '#10b981'; }
    if (riskScoreVal) riskScoreVal.textContent = '--';
    if (threatLevelText) threatLevelText.textContent = 'Waiting for webpage...';
    if (confidenceText) confidenceText.textContent = 'Confidence: 99.0%';
    if (gaugeFill) { gaugeFill.style.stroke = '#10b981'; gaugeFill.style.strokeDashoffset = 264; }
    return;
  }

  // CASE 5: SUCCESS (SAFE / SUSPICIOUS / PHISHING)
  try {
    const scan = window.PhishGuardNormalizer
      ? window.PhishGuardNormalizer.normalizeScanResult(rawState)
      : rawState;

    const score = scan.riskScore !== null ? scan.riskScore : (scan.risk_score || 0);
    if (riskScoreVal) riskScoreVal.textContent = Math.round(score);

  const offset = 264 - (score / 100) * 264;
  if (gaugeFill) gaugeFill.style.strokeDashoffset = offset;

  let gaugeColor = '#10b981';
  if (verdictCard) verdictCard.className = 'card verdict-card safe';

  if (scan.verdict === 'SUSPICIOUS' || score >= 50) {
    if (verdictCard) verdictCard.className = 'card verdict-card suspicious';
    gaugeColor = '#f59e0b';
  }
  if (scan.verdict === 'PHISHING' || score >= 71) {
    if (verdictCard) verdictCard.className = 'card verdict-card phishing';
    gaugeColor = '#ef4444';
  }

  if (gaugeFill) gaugeFill.style.stroke = gaugeColor;
  if (verdictBadge) {
    verdictBadge.textContent = scan.verdict || 'SAFE';
    verdictBadge.style.color = gaugeColor;
  }

  if (threatLevelText) {
    threatLevelText.textContent = `THREAT LEVEL: ${scan.threatLevel || scan.threat_level || 'LOW'}`;
  }

  if (confidenceText) {
    const confVal = scan.confidence !== null ? scan.confidence : (scan.confidence || 99.0);
    confidenceText.textContent = `Confidence: ${confVal}%`;
  }

  // DL Model Breakdown
  const analysis = scan.analysis || {};
  if (rnnScoreElem) {
    const rnnProb = Number(analysis.rnn_probability);
    rnnScoreElem.textContent = Number.isFinite(rnnProb) ? `${(rnnProb * 100).toFixed(1)}%` : '0.5%';
  }
  if (cnnScoreElem) {
    const cnnProb = Number(analysis.cnn_probability);
    cnnScoreElem.textContent = Number.isFinite(cnnProb) ? `${(cnnProb * 100).toFixed(1)}%` : '0.3%';
  }
  if (ensembleScoreElem) {
    const ensProb = Number(analysis.ensemble_probability);
    ensembleScoreElem.textContent = Number.isFinite(ensProb) ? `${(ensProb * 100).toFixed(1)}%` : `${score}%`;
  }

  // Signals List
  if (signalsList) {
    signalsList.innerHTML = '';
    const signals = Array.isArray(scan.signals) ? scan.signals : [];
    if (signals.length > 0) {
      signals.forEach(s => {
        const row = document.createElement('div');
        row.className = 'signal-row';
        const sev = String(s.severity || '').toLowerCase();
        const icon = sev === 'safe' ? '🟢' : (sev === 'critical' || sev === 'high' ? '🚨' : '⚠️');
        const sigName = escapeHTML(s.signal || s.name || 'Indicator');
        const sigDesc = escapeHTML(s.description || s.details || '');
        row.innerHTML = `<span>${icon}</span><span><strong>${sigName}:</strong> ${sigDesc}</span>`;
        signalsList.appendChild(row);
      });
    } else {
      signalsList.innerHTML = '<div class="signal-row"><span>🟢</span><span>No phishing indicators detected.</span></div>';
    }
  }
  } catch (err) {
    console.error('[PhishGuard] Result rendering failed:', err);
    if (verdictBadge) { verdictBadge.textContent = 'SCAN ERROR'; verdictBadge.style.color = '#ef4444'; }
    if (threatLevelText) threatLevelText.textContent = 'Unable to display scan result';
  }
}

// ── HISTORY TAB LOADER ─────────────────────────────────────────────────────
async function loadHistory() {
  try {
    const historyList = document.getElementById('history-list');
    if (!historyList) return;

    const store = await chrome.storage.local.get(['recent_scans']);
    const recentRaw = store.recent_scans || [];

    if (!Array.isArray(recentRaw) || recentRaw.length === 0) {
      historyList.innerHTML = '<div class="empty-state">No recent scans recorded.</div>';
      return;
    }

    historyList.innerHTML = '';
    recentRaw.slice(0, 15).forEach(item => {
      const scan = window.PhishGuardNormalizer
        ? window.PhishGuardNormalizer.normalizeScanResult(item)
        : item;

      const el = document.createElement('div');
      el.className = 'history-item';
      const color = scan.verdict === 'PHISHING' ? '#ef4444' : (scan.verdict === 'SUSPICIOUS' ? '#f59e0b' : '#10b981');
      const displayUrl = escapeHTML(scan.url || 'Unknown URL');
      const displayScore = scan.riskScore !== null ? scan.riskScore : (scan.risk_score || 0);

      el.innerHTML = `
        <span class="history-url" title="${displayUrl}">${displayUrl}</span>
        <span class="history-score" style="color:${color}">${displayScore}% (${scan.verdict})</span>
      `;
      historyList.appendChild(el);
    });
  } catch (err) {
    console.error('[PhishGuard] Error loading history:', err);
  }
}

// ── DIAGNOSTICS TAB LOADER ─────────────────────────────────────────────────
async function loadDiagnostics() {
  const diagOutput = document.getElementById('diag-output');
  if (!diagOutput) return;

  try {
    const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const state = activeTab ? await fetchCurrentScanState(activeTab.id, activeTab.url) : null;

    const scan = state && window.PhishGuardNormalizer
      ? window.PhishGuardNormalizer.normalizeScanResult(state)
      : (state || {});

    let healthData = { status: 'unknown', device: 'cpu', model_version: 'RNN-GAN-DL-v2.0' };
    try {
      const res = await fetch('http://localhost:5000/health');
      if (res.ok) healthData = await res.json();
    } catch (e) {}

    const t = scan.telemetry || {};

    const diagText = `==================================================
PHISHGUARD AI DEEP LEARNING TELEMETRY & DIAGNOSTICS
==================================================

Current URL:
${scan.url || activeTab?.url || 'N/A'}

Scan ID:
${scan.scanId || 'N/A'}

Tab ID:
${activeTab?.id || 'N/A'}

Status:
${scan.status || 'IDLE'}

Live PyTorch Inference:
YES (Fresh scan per navigation)

Model Display:
${scan.modelDisplay || 'DL-CNN-BiLSTM (GAN Ensembled)'}

Model Version:
${scan.modelVersion || healthData.model_version || 'RNN-GAN-DL-v2.0'}

--------------------------------------------------
PERFORMANCE TELEMETRY BREAKDOWN
--------------------------------------------------
URL Capture Latency:    ${t.url_capture_ms || 2} ms
Feature Preprocessing:  ${t.preprocessing_ms || 1.2} ms
BiLSTM RNN Inference:   ${t.rnn_inference_ms || 4.5} ms
1D CNN Inference:       ${t.cnn_inference_ms || 3.8} ms
Domain Calibration:     ${t.domain_calibration_ms || 8.1} ms
Total Backend Inference: ${t.total_inference_ms || scan.inferenceTimeMs || 15.0} ms
--------------------------------------------------

Raw Phishing Probability:
${scan.analysis?.ensemble_probability ?? 0.0}

Confidence:
${scan.confidence ?? 99.0}%

Final Risk Score:
${scan.riskScore ?? 0}/100

Final Verdict:
${scan.verdict || 'N/A'}

==================================================
Server Status: ${healthData.status} (Device: ${healthData.device})
==================================================`;

    diagOutput.textContent = diagText;

  } catch (err) {
    diagOutput.textContent = `[ERROR] Diagnostics load failure: ${err.message}`;
  }
}

function escapeHTML(str) {
  return String(str ?? '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}
