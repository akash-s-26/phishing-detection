/**
 * PhishGuard AI — Floating Security Banner Test Harness Script
 */

document.addEventListener('DOMContentLoaded', () => {
  const logOutput = document.getElementById('event-log-output');

  function appendLog(msg) {
    const timestamp = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.innerHTML = `<span style="color: #64748b;">[${timestamp}]</span> ${escapeHTML(msg)}`;
    logOutput.appendChild(line);
    logOutput.scrollTop = logOutput.scrollHeight;
  }

  function escapeHTML(str) {
    return String(str ?? '').replace(/[&<>"']/g, match => {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[match];
    });
  }

  function dispatchScanResult(result) {
    appendLog(`[PhishGuard] Scan completed: verdict=${result.verdict}, risk=${result.riskScore}%, url=${result.url}`);
    appendLog(`[PhishGuard] Sending result to tab: current_tab`);

    // Dispatch synthetic event to window so content.js listener receives it
    const msgPayload = {
      type: 'PHISHGUARD_SCAN_COMPLETE',
      action: 'SHOW_RESULT_BANNER',
      result: result,
      data: result
    };

    appendLog(`[PhishGuard] Content script received: type=${msgPayload.type}`);
    appendLog(`[PhishGuard] Creating security banner`);

    window.postMessage({ phishguardMsg: msgPayload }, '*');
  }

  // Intercept window postMessage for test harness simulation
  window.addEventListener('message', (event) => {
    if (event.data && event.data.phishguardMsg) {
      const msg = event.data.phishguardMsg;
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
        // Handled via chrome runtime
      } else {
        // Direct call to window content script functions in test harness mode
        const scanResult = msg.result || msg.data;
        if (typeof window.PhishGuardNormalizer !== 'undefined') {
          // Normalize & dispatch to custom window event handler if isolated
        }
      }
    }
  });

  // 1. Trigger SAFE State
  document.getElementById('btn-trigger-safe').addEventListener('click', () => {
    dispatchScanResult({
      scanId: 'scan_safe_' + Date.now(),
      url: 'https://github.com/phishguard-ai/deep-learning',
      verdict: 'SAFE',
      prediction: 'SAFE',
      riskScore: 2.0,
      threatLevel: 'LOW',
      confidence: 98.4,
      modelDisplay: 'DL-CNN-BiLSTM (GAN Ensembled)',
      inferenceTimeMs: 18.5,
      timestamp: new Date().toISOString()
    });
  });

  // 2. Trigger SUSPICIOUS State
  document.getElementById('btn-trigger-suspicious').addEventListener('click', () => {
    dispatchScanResult({
      scanId: 'scan_suspicious_' + Date.now(),
      url: 'https://account-verification-support.net/login',
      verdict: 'SUSPICIOUS',
      prediction: 'SUSPICIOUS',
      riskScore: 58.0,
      threatLevel: 'MEDIUM',
      confidence: 84.0,
      modelDisplay: 'DL-CNN-BiLSTM',
      inferenceTimeMs: 24.1,
      signals: [
        { signal: 'Unusual Subdomain Structure', severity: 'medium', description: 'Multiple nested subdomains detected' },
        { signal: 'Domain Age Anomaly', severity: 'medium', description: 'Domain registered under 7 days ago' }
      ],
      timestamp: new Date().toISOString()
    });
  });

  // 3. Trigger DANGEROUS / PHISHING State
  document.getElementById('btn-trigger-dangerous').addEventListener('click', () => {
    dispatchScanResult({
      scanId: 'scan_phishing_' + Date.now(),
      url: 'https://secure-bank-login-update.com/account/login.php',
      verdict: 'PHISHING',
      prediction: 'PHISHING',
      riskScore: 94.5,
      threatLevel: 'CRITICAL',
      confidence: 99.2,
      modelDisplay: 'DL-RNN-GAN (Ensembled)',
      inferenceTimeMs: 14.8,
      signals: [
        { signal: 'Credential Harvesting Form', severity: 'high', description: 'Hidden password inputs posting to external IP' },
        { signal: 'Brand Impersonation', severity: 'high', description: 'High visual similarity to financial institution' }
      ],
      timestamp: new Date().toISOString()
    });
  });

  // 4. Trigger Custom Input Scan
  document.getElementById('btn-trigger-custom').addEventListener('click', () => {
    const urlVal = document.getElementById('custom-url-input').value.trim();
    if (!urlVal) return;

    let verdict = 'SAFE';
    let risk = 4.0;
    let confidence = 98.0;

    if (urlVal.includes('paypal') || urlVal.includes('bank') || urlVal.includes('login') || urlVal.includes('security')) {
      verdict = 'PHISHING';
      risk = 92.0;
      confidence = 97.5;
    } else if (urlVal.includes('verify') || urlVal.includes('support')) {
      verdict = 'SUSPICIOUS';
      risk = 52.0;
      confidence = 85.0;
    }

    dispatchScanResult({
      scanId: 'scan_custom_' + Date.now(),
      url: urlVal,
      verdict: verdict,
      prediction: verdict,
      riskScore: risk,
      threatLevel: verdict === 'PHISHING' ? 'CRITICAL' : (verdict === 'SUSPICIOUS' ? 'MEDIUM' : 'LOW'),
      confidence: confidence,
      modelDisplay: 'DL-CNN-BiLSTM (GAN Ensembled)',
      inferenceTimeMs: 21.0,
      timestamp: new Date().toISOString()
    });
  });

  appendLog('Click any trigger button above to simulate URL scan results.');
});
