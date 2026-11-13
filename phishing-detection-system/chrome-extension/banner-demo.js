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

  // 1. Trigger SAFE State (Level 1)
  document.getElementById('btn-trigger-safe').addEventListener('click', () => {
    dispatchScanResult({
      scanId: 'demo_l1_safe_' + Date.now(),
      url: 'https://demo.secure-bank-login.com',
      verdict: 'SAFE',
      prediction: 'SAFE',
      riskScore: 4.2,
      threatLevel: 'LOW',
      confidence: 98.8,
      modelDisplay: 'DL-CNN-BiLSTM (GAN Ensembled)',
      inferenceTimeMs: 14.2,
      ssl: true,
      ssl_status: 'Valid SSL (TLS 1.3 - Verified)',
      domain_age: '12 years (Established)',
      domain_age_days: 4380,
      redirects: 0,
      redirect_status: '0 redirects (Direct)',
      blacklisted: false,
      blacklist_status: 'Clean (Not listed on threat databases)',
      reason: '[DEMO DATA] URL evaluated cleanly with no suspicious indicators. Domain is established (12 years) with valid TLS 1.3 encryption and clean reputation on all threat feeds.',
      signals: [
        { signal: 'Valid SSL Certificate', severity: 'safe', description: 'Strong TLS 1.3 certificate issued by DigiCert with extended validation.' },
        { signal: 'Established Domain Reputation', severity: 'safe', description: 'Domain active for over 12 years with clean WHOIS and zero security flags.' }
      ],
      is_demo: true,
      isDemo: true,
      timestamp: new Date().toISOString()
    });
  });

  // 2. Trigger SUSPICIOUS State (Level 2)
  document.getElementById('btn-trigger-suspicious').addEventListener('click', () => {
    dispatchScanResult({
      scanId: 'demo_l2_suspicious_' + Date.now(),
      url: 'https://demo-account-verification-alert.xyz/verify',
      verdict: 'SUSPICIOUS',
      prediction: 'SUSPICIOUS',
      riskScore: 48.5,
      threatLevel: 'MEDIUM',
      confidence: 86.4,
      modelDisplay: 'DL-CNN-BiLSTM (GAN Ensembled)',
      inferenceTimeMs: 22.4,
      ssl: true,
      ssl_status: 'Valid SSL (Free / Low Assurance)',
      domain_age: '14 days (Newly Registered)',
      domain_age_days: 14,
      redirects: 1,
      redirect_status: '1 redirect (Tracking intermediary)',
      blacklisted: false,
      blacklist_status: 'Clean (Not yet blacklisted - emerging domain)',
      reason: '[DEMO DATA] Flagged as Level 2 Medium Risk (Suspicious) with a continuous threat score of 48.5%. Detected indicators: Newly registered domain (14 days), high-risk generic TLD (.xyz), and intermediate redirect. Caution is advised: avoid submitting passwords or sensitive credentials until verified.',
      signals: [
        { signal: 'Newly Registered Domain', severity: 'medium', description: 'Domain registered only 14 days ago — typical of temporary phishing infrastructure.' },
        { signal: 'Unusual Subdomain & TLD', severity: 'medium', description: 'High-risk .xyz generic TLD paired with urgent verification keywords.' },
        { signal: 'Intermediate Redirect Hop', severity: 'low', description: 'URL redirects through an external tracking hop before reaching final page.' }
      ],
      is_demo: true,
      isDemo: true,
      timestamp: new Date().toISOString()
    });
  });

  // 3. Trigger DANGEROUS / PHISHING State (Level 3)
  document.getElementById('btn-trigger-dangerous').addEventListener('click', () => {
    dispatchScanResult({
      scanId: 'demo_l3_phishing_' + Date.now(),
      url: 'http://demo.paypal.security-update.com.signin.net/login',
      verdict: 'PHISHING',
      prediction: 'PHISHING',
      riskScore: 92.4,
      threatLevel: 'CRITICAL',
      confidence: 99.1,
      modelDisplay: 'DL-CNN-BiLSTM (GAN Ensembled)',
      inferenceTimeMs: 18.7,
      ssl: false,
      ssl_status: 'Missing SSL (Plain HTTP - Insecure)',
      domain_age: 'Unable to verify (Privacy protected)',
      domain_age_days: null,
      redirects: 2,
      redirect_status: '2 redirects (Obfuscated chain)',
      blacklisted: true,
      blacklist_status: 'Listed (Confirmed Phishing Threat)',
      reason: '[DEMO DATA] CRITICAL WARNING: Classified as Level 3 High Risk (Dangerous Phishing) with a threat score of 92.4%. Critical indicators: Unencrypted plain HTTP transmission, aggressive brand spoofing (PayPal impersonation), and active threat blacklist listing. Do NOT enter passwords, banking details, or personal credentials.',
      signals: [
        { signal: 'Deceptive Brand Impersonation', severity: 'critical', description: 'Detected deceptive PayPal brand imitation using nested misleading subdomains.' },
        { signal: 'Unencrypted Plain HTTP Transmission', severity: 'critical', description: 'Sensitive login interface transmitted without SSL/TLS encryption.' },
        { signal: 'Active Threat Blacklist Match', severity: 'high', description: 'Domain actively flagged in threat intelligence feeds as credential harvesting infrastructure.' }
      ],
      is_demo: true,
      isDemo: true,
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
