/**
 * PhishGuard AI — Chrome Extension Background Service Worker (Manifest V3)
 * Authoritative single source of truth for per-tab scan state lifecycle (IDLE -> SCANNING -> SUCCESS / ERROR).
 * Handles GET_CURRENT_SCAN_STATE requests, broadcasts SCAN_STATE_UPDATED events,
 * preserves completed SUCCESS scan states across duplicate events,
 * and executes 100% live PyTorch Deep Learning inference with zero whitelists or detection caches.
 */

importScripts('normalizer.js');

const API_BASE_URL = 'http://localhost:5000';

// Per-tab Scan State Machine Map
const scanStates = new Map(); // tabId -> scanState object
const activeScanState = {}; // tabId -> { scanId, url, timestamp }
const recentNavigations = {}; // `${tabId}_${url}` -> timestamp
const scanPulseTimers = new Map(); // tabId -> intervalId

function createScanId() {
  return 'scan_' + Date.now() + '_' + Math.random().toString(36).substring(2, 9);
}

function normalizeUrl(url) {
  if (self.PhishGuardNormalizer && self.PhishGuardNormalizer.normalizeUrlForComparison) {
    return self.PhishGuardNormalizer.normalizeUrlForComparison(url);
  }
  return String(url || '').trim().toLowerCase().replace(/\/+$/, '');
}

// ── ACTION BADGE & TOOLTIP SCANNING STATUS ──────────────────────────────────

function updateActionBadge(tabId, stateObj) {
  if (!tabId || !chrome.action) return;

  // Clear any active scanning animation timer for this tab
  if (scanPulseTimers.has(tabId)) {
    clearInterval(scanPulseTimers.get(tabId));
    scanPulseTimers.delete(tabId);
  }

  if (!stateObj) {
    chrome.action.setBadgeText({ tabId, text: '' });
    chrome.action.setTitle({ tabId, title: 'PhishGuard AI — Real-Time Deep Learning Protection' });
    return;
  }

  const status = stateObj.status;

  if (status === 'SCANNING') {
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#2563EB' }); // Vibrant Blue
    chrome.action.setBadgeText({ tabId, text: 'SCAN' });
    chrome.action.setTitle({ tabId, title: `PhishGuard AI: Scanning ${stateObj.url || 'website'}...` });

    // Animated pulse badge while scanning
    let step = 0;
    const pulseFrames = ['SCAN', '•••', 'SCAN', '•••'];
    const timerId = setInterval(() => {
      step = (step + 1) % pulseFrames.length;
      chrome.action.setBadgeText({ tabId, text: pulseFrames[step] }).catch(() => {});
    }, 400);
    scanPulseTimers.set(tabId, timerId);

  } else if (status === 'SUCCESS') {
    const risk = typeof stateObj.riskScore === 'number' ? stateObj.riskScore : (stateObj.risk_score || 0);
    const verdict = (stateObj.verdict || stateObj.prediction || '').toUpperCase();

    if (verdict === 'PHISHING' || risk > 70) {
      chrome.action.setBadgeText({ tabId, text: 'RISK' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#DC2626' }); // Crimson Red
      chrome.action.setTitle({ tabId, title: `PhishGuard AI: 🚨 PHISHING DETECTED! (Risk: ${risk}%)` });
    } else if (verdict === 'SUSPICIOUS' || risk > 30) {
      chrome.action.setBadgeText({ tabId, text: 'WARN' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#D97706' }); // Warm Amber
      chrome.action.setTitle({ tabId, title: `PhishGuard AI: ⚠️ Suspicious Website (Risk: ${risk}%)` });
    } else {
      chrome.action.setBadgeText({ tabId, text: 'SAFE' });
      chrome.action.setBadgeBackgroundColor({ tabId, color: '#059669' }); // Emerald Green
      chrome.action.setTitle({ tabId, title: `PhishGuard AI: ✓ Safe Website (Risk: ${risk}%)` });
    }
  } else if (status === 'ERROR') {
    chrome.action.setBadgeText({ tabId, text: 'ERR' });
    chrome.action.setBadgeBackgroundColor({ tabId, color: '#4B5563' }); // Dark Gray
    chrome.action.setTitle({ tabId, title: `PhishGuard AI: Scan Error (${stateObj.error || 'Server offline'})` });
  } else {
    chrome.action.setBadgeText({ tabId, text: '' });
    chrome.action.setTitle({ tabId, title: 'PhishGuard AI — Real-Time Deep Learning Protection' });
  }
}

// ── PER-TAB SCAN STATE LIFECYCLE MANAGEMENT ────────────────────────────────

async function setTabScanState(tabId, stateObj) {
  if (!tabId) return;

  scanStates.set(tabId, stateObj);

  // Update action icon badge & title when pinned in Chrome toolbar
  updateActionBadge(tabId, stateObj);

  // 1. Session Storage Persistence
  try {
    if (chrome.storage && chrome.storage.session) {
      await chrome.storage.session.set({ [`tab_${tabId}`]: stateObj });
    }
  } catch (e) {}

  // 2. Local Storage Fallback
  try {
    const store = await chrome.storage.local.get(['active_tab_results']);
    const activeResults = store.active_tab_results || {};
    activeResults[tabId] = stateObj;
    await chrome.storage.local.set({ active_tab_results: activeResults });
  } catch (e) {}

  // 3. Broadcast live update to any open popup listening
  chrome.runtime.sendMessage({
    type: 'SCAN_STATE_UPDATED',
    action: 'SCAN_STATE_UPDATED',
    tabId: tabId,
    state: stateObj
  }).catch(() => {
    // Suppress error if popup is closed
  });
}

async function getTabScanState(tabId, currentUrl) {
  if (!tabId) return null;

  let state = scanStates.get(tabId);

  if (!state && chrome.storage && chrome.storage.session) {
    try {
      const res = await chrome.storage.session.get([`tab_${tabId}`]);
      state = res[`tab_${tabId}`];
    } catch (e) {}
  }

  if (!state) {
    try {
      const store = await chrome.storage.local.get(['active_tab_results']);
      state = store.active_tab_results ? store.active_tab_results[tabId] : null;
    } catch (e) {}
  }

  if (!state) return null;

  // Strict URL Invalidation Check
  if (currentUrl && state.url) {
    const normCurrent = normalizeUrl(currentUrl);
    const normStored = normalizeUrl(state.url);
    if (normCurrent !== normStored) {
      console.log(`[PhishGuard] STALE_RESULT_IGNORED Tab ${tabId}: Stored URL (${state.url}) != Current URL (${currentUrl})`);
      return null;
    }
  }

  return state;
}

// ── NAVIGATION DEDUPLICATION & WARNING INJECTION ───────────────────────────

function isDuplicateNavigation(tabId, url) {
  const key = `${tabId}_${url}`;
  const now = Date.now();
  const lastTime = recentNavigations[key];
  if (lastTime && now - lastTime < 250) {
    return true;
  }
  recentNavigations[key] = now;
  return false;
}

function isInjectableUrl(url) {
  if (!url || typeof url !== 'string') return false;
  const lower = url.toLowerCase().trim();
  if (!lower.startsWith('http://') && !lower.startsWith('https://')) return false;
  if (lower.includes('chrome-error://') || lower.includes('chromewebdata')) return false;
  return true;
}

async function sendOrInjectWarning(tabId, scanState) {
  if (!tabId || !chrome.runtime?.id) return;

  const scanUrl = scanState ? (scanState.url || scanState.target_url) : '';
  if (scanUrl && !isInjectableUrl(scanUrl)) {
    console.log(`[PhishGuard] Warning injection skipped on restricted/error URL: ${scanUrl}`);
    return;
  }

  console.log('[PhishGuard] Sending warning to tab:', tabId, scanState);
  const msgObj = {
    type: 'PHISHGUARD_SCAN_COMPLETE',
    action: 'SHOW_THREAT_WARNING',
    result: scanState,
    data: scanState
  };

  try {
    chrome.tabs.sendMessage(tabId, msgObj, (response) => {
      const err = chrome.runtime.lastError;
      if (err) {
        chrome.tabs.get(tabId, (tab) => {
          if (chrome.runtime.lastError || !tab || !isInjectableUrl(tab.url)) {
            console.warn(`[PhishGuard] Warning message skipped on Tab ${tabId}: ${err.message}`);
            return;
          }
          if (chrome.scripting) {
            chrome.scripting.executeScript({
              target: { tabId },
              files: ['normalizer.js', 'content.js']
            }).then(() => {
              setTimeout(() => {
                if (!chrome.runtime?.id) return;
                chrome.tabs.sendMessage(tabId, msgObj, () => {
                  const retryErr = chrome.runtime.lastError;
                  if (!retryErr) {
                    console.log(`[PhishGuard] WARNING_SENT after injection to Tab ${tabId}`);
                  }
                });
              }, 100);
            }).catch(injErr => {
              console.warn(`[PhishGuard] Warning script injection bypassed on Tab ${tabId}: ${injErr.message}`);
            });
          }
        });
      } else {
        console.log(`[PhishGuard] WARNING_SENT: Direct message delivered to Tab ${tabId}`);
      }
    });
  } catch (e) {
    console.warn('[PhishGuard] Warning message exception:', e.message);
  }
}

async function sendOrInjectResultBanner(tabId, scanState) {
  if (!tabId || !chrome.runtime?.id) return;

  const scanUrl = scanState ? (scanState.url || scanState.target_url) : '';
  if (scanUrl && !isInjectableUrl(scanUrl)) {
    console.log(`[PhishGuard] Banner injection skipped on restricted/error URL: ${scanUrl}`);
    return;
  }

  console.log('[PhishGuard] Sending result to tab:', tabId, scanState);
  const msgObj = {
    type: 'PHISHGUARD_SCAN_COMPLETE',
    action: 'SHOW_RESULT_BANNER',
    result: scanState,
    data: scanState
  };

  try {
    chrome.tabs.sendMessage(tabId, msgObj, (response) => {
      const err = chrome.runtime.lastError;
      if (err) {
        chrome.tabs.get(tabId, (tab) => {
          if (chrome.runtime.lastError || !tab || !isInjectableUrl(tab.url)) {
            console.warn(`[PhishGuard] Result message skipped on Tab ${tabId}: ${err.message}`);
            return;
          }
          if (chrome.scripting) {
            chrome.scripting.executeScript({
              target: { tabId },
              files: ['normalizer.js', 'content.js']
            }).then(() => {
              setTimeout(() => {
                if (!chrome.runtime?.id) return;
                chrome.tabs.sendMessage(tabId, msgObj, (resp) => {
                  const retryErr = chrome.runtime.lastError;
                  if (!retryErr) {
                    console.log('[PhishGuard] Scan result delivered to tab after injection:', tabId);
                  }
                });
              }, 150);
            }).catch(injErr => {
              console.warn(`[PhishGuard] Content script injection bypassed on Tab ${tabId}: ${injErr.message}`);
            });
          }
        });
      } else {
        console.log('[PhishGuard] Scan result delivered to tab', tabId);
      }
    });
  } catch (e) {
    console.warn('[PhishGuard] Result message exception:', e.message);
  }
}

// ── REAL-TIME DEEP LEARNING SCAN EXECUTION ─────────────────────────────────

async function performScan(tabId, url, triggerSource = 'nav') {
  if (!url || !url.startsWith('http')) return;

  const normUrl = normalizeUrl(url);

  // Preserve already completed SUCCESS result for the same URL unless manually triggered
  const existingState = scanStates.get(tabId);
  const existingNormUrl = existingState && existingState.url ? normalizeUrl(existingState.url) : '';

  if (existingState && existingState.status === 'SUCCESS' && normUrl === existingNormUrl && triggerSource !== 'manual') {
    console.log(`[PhishGuard] EXISTING_SUCCESS_PRESERVED Tab ${tabId} | URL: ${url}`);
    if (existingState.verdict === 'PHISHING' || (existingState.riskScore !== null && existingState.riskScore >= 71.0)) {
      sendOrInjectWarning(tabId, existingState);
    } else {
      sendOrInjectResultBanner(tabId, existingState);
    }
    return;
  }

  if (isDuplicateNavigation(tabId, url) && triggerSource !== 'manual') {
    console.log(`[PhishGuard] SCAN_DUP_IGNORED Tab ${tabId} | URL: ${url}`);
    if (existingState && existingState.status === 'SUCCESS') {
      if (existingState.verdict === 'PHISHING' || (existingState.riskScore !== null && existingState.riskScore >= 71.0)) {
        sendOrInjectWarning(tabId, existingState);
      } else {
        sendOrInjectResultBanner(tabId, existingState);
      }
    }
    return;
  }

  const scanId = createScanId();
  const captureTime = Date.now();

  activeScanState[tabId] = { scanId, url, timestamp: captureTime };

  // Set State to SCANNING
  const scanningState = {
    status: 'SCANNING',
    scanId,
    tabId,
    url,
    timestamp: captureTime
  };
  await setTabScanState(tabId, scanningState);

  console.log(`[PhishGuard] SCAN_STARTED Tab ${tabId} | Source: ${triggerSource} | ScanID: ${scanId} | URL: ${url}`);

  try {
    const apiStartTime = Date.now();
    const response = await fetch(`${API_BASE_URL}/api/v1/detect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, scan_id: scanId, tab_id: tabId, timestamp: captureTime })
    });

    const data = await response.json();
    const networkMs = Date.now() - apiStartTime;

    // Strict Stale-Result Protection
    const currentState = activeScanState[tabId];
    if (!currentState || currentState.scanId !== scanId || currentState.url !== url) {
      console.warn(`[PhishGuard] STALE_RESULT_DISCARDED Outdated response for ${url} (ScanID: ${scanId}) ignored on Tab ${tabId}`);
      return;
    }

    if (!response.ok) {
      if (data.error_code === 'SCAN_UNAVAILABLE') {
        throw new Error('SCAN_UNAVAILABLE: Deep Learning models are currently unavailable on backend.');
      }
      throw new Error(data.error || `HTTP error ${response.status}`);
    }

    const telemetry = data.telemetry || {};
    telemetry.url_capture_ms = Math.max(1, Date.now() - captureTime - networkMs);
    telemetry.network_transit_ms = networkMs;

    // Normalize API Response
    const scan = self.PhishGuardNormalizer ? self.PhishGuardNormalizer.normalizeScanResult(data) : data;
    scan.status = 'SUCCESS';
    scan.scanId = scanId;
    scan.tabId = tabId;
    scan.telemetry = telemetry;

    // Legacy fields for backward compatibility
    scan.risk_score = scan.riskScore;
    scan.threat_level = scan.threatLevel;
    scan.model = scan.modelDisplay;
    scan.model_details = typeof data.model === 'object' ? data.model : { name: scan.modelDisplay };
    scan.inference_time_ms = scan.inferenceTimeMs;

    // 1. PERSIST COMPLETED STATE FIRST
    await setTabScanState(tabId, scan);

    // Save to Recent Scans History list
    try {
      const store = await chrome.storage.local.get(['recent_scans']);
      const recentScans = store.recent_scans || [];
      recentScans.unshift(scan);
      if (recentScans.length > 50) recentScans.pop();
      await chrome.storage.local.set({ recent_scans: recentScans });
    } catch (e) {}

    console.log('[PhishGuard] Scan completed:', scan);
    console.log(
      `[PhishGuard] RESULT_PERSISTED Tab ${tabId} | Status: SUCCESS | Risk: ${scan.riskScore}% | Verdict: ${scan.verdict} | ` +
      `Model: ${scan.modelDisplay} | Latency: ${scan.inferenceTimeMs}ms`
    );

    // 2. SEND CHROME NOTIFICATION
    try {
      if (chrome.notifications) {
        const notifTitle = scan.verdict === 'PHISHING' ? '🚨 PHISHING DETECTED' : (scan.verdict === 'SUSPICIOUS' ? '⚠️ SUSPICIOUS WEBSITE' : '✓ SAFE WEBSITE');
        chrome.notifications.create(`scan_notif_${scanId}`, {
          type: 'basic',
          iconUrl: 'icon128.png',
          title: notifTitle,
          message: `Risk: ${scan.riskScore}/100 | Model: ${scan.modelDisplay}`
        });
        console.log(`[PhishGuard] NOTIFICATION_SENT Tab ${tabId} -> ${notifTitle}`);
      }
    } catch (nErr) {}

    // 3. AUTOMATICALLY TRIGGER RESULT BANNER FOR ALL RESULTS AND WARNING OVERLAY IF PHISHING
    sendOrInjectResultBanner(tabId, scan);
    if (scan.verdict === 'PHISHING' || (scan.riskScore !== null && scan.riskScore >= 71.0)) {
      sendOrInjectWarning(tabId, scan);
    }

  } catch (error) {
    console.error(`[PhishGuard] SCAN_ERROR Tab ${tabId}:`, error.message);
    const errData = {
      success: false,
      scan_id: scanId,
      url: url,
      verdict: 'ERROR',
      prediction: 'SCAN UNAVAILABLE',
      error: error.message
    };
    const errResult = self.PhishGuardNormalizer ? self.PhishGuardNormalizer.normalizeScanResult(errData) : errData;
    errResult.status = 'ERROR';
    errResult.tabId = tabId;
    errResult.error = error.message;

    await setTabScanState(tabId, errResult);
    sendOrInjectResultBanner(tabId, errResult);
  }
}

// ── FAST IMMEDIATE NAVIGATION LISTENERS ───────────────────────────────────

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId === 0 && details.url && details.url.startsWith('http')) {
    performScan(details.tabId, details.url, 'onCommitted');
  }
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url && changeInfo.url.startsWith('http')) {
    performScan(tabId, changeInfo.url, 'onUpdated');
  }
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId === 0 && details.url && details.url.startsWith('http')) {
    performScan(details.tabId, details.url, 'onHistoryStateUpdated');
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  if (activeInfo && activeInfo.tabId) {
    const state = await getTabScanState(activeInfo.tabId);
    updateActionBadge(activeInfo.tabId, state);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  if (scanPulseTimers.has(tabId)) {
    clearInterval(scanPulseTimers.get(tabId));
    scanPulseTimers.delete(tabId);
  }
  delete activeScanState[tabId];
  scanStates.delete(tabId);
  if (chrome.storage && chrome.storage.session) {
    chrome.storage.session.remove([`tab_${tabId}`]).catch(() => {});
  }
});

// ── EXTENSION MESSAGE HANDLERS ──────────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {

  // GET_CURRENT_SCAN_STATE Handler
  if (message.type === 'GET_CURRENT_SCAN_STATE' || message.action === 'GET_CURRENT_SCAN_STATE' || message.action === 'GET_ACTIVE_RESULT') {
    const reqTabId = message.tabId || (sender.tab ? sender.tab.id : null);
    const reqUrl = message.url;

    console.log(`[PhishGuard] GET_CURRENT_SCAN_STATE Request for Tab ${reqTabId} | URL: ${reqUrl}`);

    getTabScanState(reqTabId, reqUrl).then(state => {
      console.log(`[PhishGuard] CURRENT_STATE_RETURNED Tab ${reqTabId} -> Status: ${state?.status || 'NONE'} | Verdict: ${state?.verdict || 'NONE'}`);
      sendResponse(state || null);
    });

    return true; // Keep channel open for async response
  }

  // TRIGGER_MANUAL_SCAN Handler
  if (message.action === 'TRIGGER_MANUAL_SCAN' || message.type === 'TRIGGER_MANUAL_SCAN') {
    performScan(message.tabId, message.url, 'manual').then(() => {
      sendResponse({ status: 'started' });
    });
    return true;
  }

  // SPA Route Change Handler
  if (message.action === 'URL_CHANGED' || message.type === 'URL_CHANGED') {
    const tabId = sender.tab ? sender.tab.id : message.tabId;
    performScan(tabId, message.url, 'spa_change').then(() => {
      sendResponse({ status: 'scanning' });
    });
    return true;
  }
});

// ── EXTERNAL WEB APP MESSAGE HANDLER (localhost:5173 integration) ───────────
if (chrome.runtime.onMessageExternal) {
  chrome.runtime.onMessageExternal.addListener((request, sender, sendResponse) => {
    console.log('[PhishGuard] External message received from:', sender.url, request);

    if (request.type === 'PING' || request.action === 'PING') {
      sendResponse({ status: 'connected', extensionVersion: '2.0.0', active: true });
      return true;
    }

    if (request.type === 'GET_STATS' || request.action === 'GET_STATS') {
      chrome.storage.local.get(['recent_scans'], (data) => {
        const recent = data.recent_scans || [];
        sendResponse({
          totalScans: recent.length,
          phishingCount: recent.filter(s => s.verdict === 'PHISHING').length,
          safeCount: recent.filter(s => s.verdict === 'SAFE').length,
          recentScans: recent.slice(0, 10)
        });
      });
      return true;
    }

    if (request.type === 'SCAN_URL' && request.url) {
      fetch('http://localhost:5000/api/v1/detect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: request.url })
      })
      .then(res => res.json())
      .then(data => sendResponse({ status: 'completed', result: data }))
      .catch(err => sendResponse({ status: 'error', error: err.message }));
      return true;
    }
  });
}

