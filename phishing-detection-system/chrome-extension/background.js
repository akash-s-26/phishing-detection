/**
 * background.js — PhishGuard AI Service Worker (Manifest V3)
 *
 * Talks directly to the Flask backend defined in backend/app.py:
 *   POST /predict              -> { prediction, risk_score, confidence, signals, ... }
 *   POST /report-false-positive
 *
 * Auto-scans every page on navigation, updates the badge, stores the
 * result for popup.js to read instantly, and pushes it to content.js
 * so the in-page overlay/banner/toast appears with no manual click.
 */

const API_BASE = 'http://localhost:5000';
const scanCache = new Map(); // url -> last /predict response, avoids duplicate calls

// ─── Auto-scan on page load ──────────────────────────────────────────────────

chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only, skip iframes
  const { tabId, url } = details;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;
  await runScan(tabId, url);
});

// Catches SPA route changes / redirects that onCompleted can miss
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  const url = tab.url || '';
  if (!url.startsWith('http://') && !url.startsWith('https://')) return;

  const key = `scan_${tabId}`;
  const stored = await chrome.storage.local.get(key);
  const prev = stored[key];
  if (prev && prev.url === url && (Date.now() - prev.timestamp) < 4000) return; // debounce

  await runScan(tabId, url);
});

// ─── Core: call Flask /predict, then fan out the result ──────────────────────

async function runScan(tabId, url) {
  console.log(`[PhishGuard] Scanning tab ${tabId}: ${url}`);

  let result;
  try {
    result = await callPredictAPI(url);
  } catch (err) {
    console.warn('[PhishGuard] /predict unreachable:', err.message);
    await chrome.storage.local.set({
      [`scan_${tabId}`]: { url, result: null, error: err.message, timestamp: Date.now() }
    });
    await setBadge(tabId, '?', '#555555');
    return;
  }

  await updateBadge(tabId, result.prediction);

  await chrome.storage.local.set({
    [`scan_${tabId}`]: { url, result, timestamp: Date.now() }
  });

  await pushToContentScript(tabId, url, result);

  if (result.prediction === 'phishing') {
    showNotification(tabId, url, result.risk_score);
  }
}

// ─── Flask API call — matches backend/app.py exactly ──────────────────────────

async function callPredictAPI(url) {
  if (scanCache.has(url)) {
    return { ...scanCache.get(url), cached: true };
  }

  const res = await fetch(`${API_BASE}/predict`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);

  const data = await res.json();
  // data shape from app.py: { url, prediction, risk_score, confidence,
  //                            features, signals, model_comparison, method, scanned_at }
  scanCache.set(url, data);
  if (scanCache.size > 100) scanCache.delete(scanCache.keys().next().value);
  return data;
}

// ─── Badge ────────────────────────────────────────────────────────────────────

async function updateBadge(tabId, prediction) {
  const map = {
    safe: { text: '✓', color: '#00cc66' },
    suspicious: { text: '!', color: '#ffaa00' },
    phishing: { text: '✕', color: '#ff2244' },
  };
  const cfg = map[prediction] || { text: '?', color: '#555555' };
  await setBadge(tabId, cfg.text, cfg.color);
}

async function setBadge(tabId, text, color) {
  try {
    await chrome.action.setBadgeText({ tabId, text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color });
  } catch (_) { /* tab may have closed */ }
}

// ─── Push result to content.js so the overlay renders instantly ──────────────

async function pushToContentScript(tabId, url, result) {
  const msg = { type: 'SCAN_COMPLETE', url, result };
  try {
    await chrome.tabs.sendMessage(tabId, msg);
  } catch (_) {
    // content script not injected yet (e.g. page loaded before extension) — inject then retry
    try {
      await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
      setTimeout(() => chrome.tabs.sendMessage(tabId, msg).catch(() => {}), 300);
    } catch (injectErr) {
      console.warn('[PhishGuard] Could not inject content.js:', injectErr.message);
    }
  }
}

// ─── System notification for phishing ─────────────────────────────────────────

function showNotification(tabId, url, riskScore) {
  try {
    chrome.notifications.create(`pg_${tabId}_${Date.now()}`, {
      type: 'basic',
      iconUrl: 'icons/icon48.png',
      title: '🚨 PhishGuard AI — PHISHING DETECTED',
      message: `Risk Score: ${riskScore}%\n${url.substring(0, 80)}`,
      priority: 2,
    });
  } catch (_) { /* notifications permission may be missing on some builds */ }
}

// ─── Message bridge — popup.js and content.js use this ───────────────────────

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {

  // popup.js reads the last stored scan for the active tab
  if (msg.type === 'GET_SCAN') {
    chrome.storage.local.get(`scan_${msg.tabId}`, (data) => {
      sendResponse(data[`scan_${msg.tabId}`] || null);
    });
    return true;
  }

  // content.js pulls the latest scan for its own tab on load (self-init),
  // so the overlay/banner/toast appears reliably even if the SCAN_COMPLETE
  // push was sent before the content script was injected.
  if (msg.type === 'GET_SCAN_FOR_TAB') {
    const tabId = sender.tab && sender.tab.id;
    if (tabId) {
      chrome.storage.local.get(`scan_${tabId}`, (data) => {
        sendResponse(data[`scan_${tabId}`] || null);
      });
    } else {
      sendResponse(null);
    }
    return true;
  }

  // popup.js or content.js requests a forced fresh scan (Re-Scan button)
  if (msg.type === 'SCAN_URL') {
    scanCache.delete(msg.url);
    const tabId = msg.tabId || sender.tab?.id;
    callPredictAPI(msg.url)
      .then(async (result) => {
        if (tabId) {
          await updateBadge(tabId, result.prediction);
          await chrome.storage.local.set({
            [`scan_${tabId}`]: { url: msg.url, result, timestamp: Date.now() }
          });
          await pushToContentScript(tabId, msg.url, result);
        }
        sendResponse({ success: true, result });
      })
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }

  // "Leave Website" button — sends the tab to a safe blank page
  if (msg.type === 'LEAVE_SITE') {
    const tabId = sender.tab?.id || msg.tabId;
    if (tabId) chrome.tabs.update(tabId, { url: 'chrome://newtab/' });
    sendResponse({ ok: true });
    return true;
  }

  // "Report False Positive" button — forwards to Flask /report-false-positive
  if (msg.type === 'REPORT_FALSE_POSITIVE') {
    fetch(`${API_BASE}/report-false-positive`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: msg.url }),
    })
      .then(res => res.json())
      .then(data => sendResponse({ success: true, data }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true;
  }
});
