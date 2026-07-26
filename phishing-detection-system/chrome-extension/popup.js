/**
 * popup.js — PhishGuard AI Extension Popup
 *
 * Reads the scan result background.js already fetched from Flask's
 * /predict endpoint and stored in chrome.storage.local. If nothing is
 * stored yet (backend was offline at page load), it requests a fresh
 * scan through background.js, which itself calls POST /predict.
 */

const API_BASE = 'http://localhost:5000';
const CIRCUM = 2 * Math.PI * 38; // matches SVG r=38

const $ = id => document.getElementById(id);
const stateScan = $('stateScan');
const stateError = $('stateError');
const stateResult = $('stateResult');
const statusIcon = $('statusIcon');
const statusLabel = $('statusLabel');
const statusUrl = $('statusUrl');
const meterArc = $('meterArc');
const meterScore = $('meterScore');
const confBar = $('confBar');
const confVal = $('confVal');
const methodBadge = $('methodBadge');
const cachedRow = $('cachedRow');
const signalsList = $('signalsList');
const signalsCount = $('signalsCount');
const phishActions = $('phishingActions');
const scanningUrl = $('scanningUrl');

const STATUS = {
  safe: { label: '✓  SAFE', icon: '✓', color: '#00ff88', theme: 'safe-theme', bar: '#00ff88' },
  suspicious: { label: '⚠  SUSPICIOUS', icon: '⚠', color: '#ffb800', theme: 'suspect-theme', bar: '#ffb800' },
  phishing: { label: '✕  PHISHING DETECTED', icon: '✕', color: '#ff3366', theme: 'phish-theme', bar: '#ff3366' },
};
const SEV_COLORS = { safe: '#00ff88', low: '#88ccff', medium: '#ffb800', high: '#ff7700', critical: '#ff3366' };

// ─── Init ─────────────────────────────────────────────────────────────────────

async function init() {
  showState('scan');
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];

  if (!tab || !tab.url || !tab.url.startsWith('http')) {
    showError('Cannot scan this page (internal Chrome page).');
    return;
  }

  scanningUrl.textContent = truncate(tab.url, 44);

  const stored = await getStoredScan(tab.id);
  if (stored && stored.url === tab.url && stored.result) {
    renderResult(stored.result, stored.url, !!stored.result.cached);
    return;
  }
  if (stored && stored.error) {
    await directScan(tab.url, tab.id);
    return;
  }

  await sleep(800); // background.js may still be mid-scan
  const stored2 = await getStoredScan(tab.id);
  if (stored2 && stored2.result) {
    renderResult(stored2.result, stored2.url, false);
  } else {
    await directScan(tab.url, tab.id);
  }
}

async function directScan(url, tabId) {
  showState('scan');
  try {
    const reply = await bgMessage({ type: 'SCAN_URL', url, tabId });
    if (reply && reply.success && reply.result) {
      renderResult(reply.result, url, false);
      return;
    }
  } catch (_) {}

  // last-resort: call Flask /predict directly
  try {
    const res = await fetch(`${API_BASE}/predict`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();
    renderResult(data, url, false);
  } catch (err) {
    showError('Backend offline. Run: python app.py');
  }
}

// ─── Render ───────────────────────────────────────────────────────────────────

function renderResult(result, url, fromCache) {
  const prediction = result.prediction || 'safe';
  const cfg = STATUS[prediction] || STATUS.safe;
  const risk = result.risk_score || 0;
  const conf = result.confidence || 0;

  $('popupRoot').className = `popup ${cfg.theme}`;

  statusIcon.textContent = cfg.icon;
  statusIcon.style.color = cfg.color;
  statusLabel.textContent = cfg.label;
  statusLabel.style.color = cfg.color;
  statusUrl.textContent = truncate(url, 46);

  const offset = CIRCUM - (risk / 100) * CIRCUM;
  meterArc.style.strokeDashoffset = offset;
  meterArc.setAttribute('stroke', cfg.color);
  meterArc.style.filter = `drop-shadow(0 0 8px ${cfg.color})`;
  meterScore.textContent = `${risk}%`;
  meterScore.setAttribute('fill', cfg.color);

  confBar.style.width = `${conf}%`;
  confBar.style.background = cfg.bar;
  confBar.style.boxShadow = `0 0 6px ${cfg.bar}`;
  confVal.textContent = `${conf}%`;
  confVal.style.color = cfg.bar;

  methodBadge.textContent = (result.method || 'ml').toUpperCase();
  if (fromCache) cachedRow.style.display = 'flex';

  renderSignals(result.signals || []);
  if (prediction === 'phishing') phishActions.style.display = 'flex';

  showState('result');
}

function renderSignals(signals) {
  signalsCount.textContent = signals.length;
  signalsList.innerHTML = '';
  signals.forEach((s, i) => {
    const color = SEV_COLORS[s.severity] || '#888';
    const el = document.createElement('div');
    el.className = `signal-item ${s.severity}`;
    el.style.animationDelay = `${i * 0.06}s`;
    el.innerHTML = `
      <div class="sig-dot" style="background:${color};box-shadow:0 0 5px ${color}"></div>
      <div>
        <div class="sig-name">${esc(s.signal)}</div>
        <div class="sig-desc">${esc(s.description)}</div>
      </div>`;
    signalsList.appendChild(el);
  });
}

// ─── UI state ─────────────────────────────────────────────────────────────────

function showState(state) {
  [stateScan, stateError, stateResult].forEach(el => el.classList.add('hidden'));
  if (state === 'scan') stateScan.classList.remove('hidden');
  if (state === 'error') stateError.classList.remove('hidden');
  if (state === 'result') stateResult.classList.remove('hidden');
}

function showError(msg) {
  document.querySelector('#stateError .error-msg').textContent = msg;
  showState('error');
}

// ─── Utility ──────────────────────────────────────────────────────────────────

function getStoredScan(tabId) {
  return new Promise(resolve => {
    chrome.storage.local.get(`scan_${tabId}`, data => resolve(data[`scan_${tabId}`] || null));
  });
}
function bgMessage(msg) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(msg, res => {
      if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
      else resolve(res);
    });
  });
}
function truncate(s, n) { return s.length > n ? s.slice(0, n) + '…' : s; }
function esc(s) { const d = document.createElement('div'); d.textContent = String(s || ''); return d.innerHTML; }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ─── Events ───────────────────────────────────────────────────────────────────

$('rescanBtn').addEventListener('click', async () => {
  $('rescanBtn').style.transform = 'rotate(-360deg)';
  $('rescanBtn').style.transition = 'transform .5s';
  setTimeout(() => { $('rescanBtn').style.transform = ''; $('rescanBtn').style.transition = ''; }, 500);

  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab || !tab.url) return;
  await chrome.storage.local.remove(`scan_${tab.id}`);
  await directScan(tab.url, tab.id);
});

$('retryBtn').addEventListener('click', init);

$('btnLeave').addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'LEAVE_SITE' });
  window.close();
});

$('btnContinue').addEventListener('click', () => {
  phishActions.style.display = 'none';
  window.close();
});

$('btnReport').addEventListener('click', async () => {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = (tabs[0] && tabs[0].url) || '';
  const btn = $('btnReport');
  chrome.runtime.sendMessage({ type: 'REPORT_FALSE_POSITIVE', url }, (res) => {
    if (res && res.success) {
      btn.textContent = '✓ Reported';
      btn.style.color = '#00ff88';
    } else {
      btn.textContent = '✗ Server offline';
      btn.style.color = '#ff3366';
    }
  });
});

document.addEventListener('DOMContentLoaded', init);
