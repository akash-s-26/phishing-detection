/**
 * PhishGuard AI — Chrome Extension Production & Development Configuration
 * Centralized API & Netlify Dashboard URL settings.
 */

const IS_PRODUCTION = true; // Set to true for production build

const CONFIG = {
  DEV: {
    API_BASE_URL: 'http://localhost:5000',
    FRONTEND_DASHBOARD_URL: 'http://localhost:5173/dashboard',
    ALLOWED_FRONTEND_PATTERNS: ['*://localhost:5173/*', '*://127.0.0.1:5173/*']
  },
  PROD: {
    API_BASE_URL: 'https://phishing-detection-4lb0.onrender.com',
    FRONTEND_DASHBOARD_URL: 'https://phishing-detection-ai.netlify.app/dashboard',
    ALLOWED_FRONTEND_PATTERNS: ['https://phishing-detection-ai.netlify.app/*', 'https://*.netlify.app/*']
  }
};

const THRESHOLDS = {
  SAFE_MAX: 39.9,
  SUSPICIOUS_MAX: 69.9,
  DANGEROUS_MIN: 70.0
};

const ACTIVE_CONFIG = {
  ...(IS_PRODUCTION ? CONFIG.PROD : CONFIG.DEV),
  THRESHOLDS
};

if (typeof window !== 'undefined') {
  window.PhishGuardConfig = ACTIVE_CONFIG;
}
if (typeof globalThis !== 'undefined') {
  globalThis.PhishGuardConfig = ACTIVE_CONFIG;
}
