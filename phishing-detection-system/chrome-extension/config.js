/**
 * PhishGuard AI — Chrome Extension Production & Development Configuration
 * Centralized API & Netlify Dashboard URL settings.
 */

const IS_PRODUCTION = false; // Set to true for production build

const CONFIG = {
  DEV: {
    API_BASE_URL: 'http://localhost:5000',
    FRONTEND_DASHBOARD_URL: 'http://localhost:5173/dashboard',
    ALLOWED_FRONTEND_PATTERNS: ['*://localhost:5173/*', '*://127.0.0.1:5173/*']
  },
  PROD: {
    API_BASE_URL: 'https://phishguard-api.up.railway.app',
    FRONTEND_DASHBOARD_URL: 'https://phishguard-ai.netlify.app/dashboard',
    ALLOWED_FRONTEND_PATTERNS: ['https://*.netlify.app/*']
  }
};

const ACTIVE_CONFIG = IS_PRODUCTION ? CONFIG.PROD : CONFIG.DEV;

if (typeof window !== 'undefined') {
  window.PhishGuardConfig = ACTIVE_CONFIG;
}
if (typeof globalThis !== 'undefined') {
  globalThis.PhishGuardConfig = ACTIVE_CONFIG;
}
