import type { ScanResult } from '@/types';

export interface DemoFixtureMeta {
  level: 1 | 2 | 3;
  label: string;
  badge: string;
  tagline: string;
  url: string;
  colorScheme: 'green' | 'amber' | 'red';
  fixture: ScanResult;
}

export const DEMO_FIXTURES: Record<1 | 2 | 3, DemoFixtureMeta> = {
  1: {
    level: 1,
    label: 'Level 1 – Safe',
    badge: 'LEVEL 1: LOW RISK',
    tagline: 'Verified Safe Webpage',
    url: 'https://demo.secure-bank-login.com',
    colorScheme: 'green',
    fixture: {
      scan_id: 'demo_l1_safe',
      url: 'https://demo.secure-bank-login.com',
      prediction: 'safe',
      verdict: 'SAFE',
      risk_score: 4.2,
      riskScore: 4.2,
      risk_level: 'Low Risk',
      threat_level: 'LOW',
      detection_level: 1,
      level_name: 'Level 1 – Low Risk (Safe)',
      confidence: 98.8,
      bilstm_score: 4.1,
      cnn_score: 4.3,
      ensemble_score: 4.2,
      analysis: {
        rnn_probability: 0.041,
        cnn_probability: 0.043,
        ensemble_probability: 0.042,
      },
      model: 'DL-CNN-BiLSTM (0.55 / 0.45 Ensemble + GAN)',
      inference_time_ms: 14.2,
      ssl: true,
      ssl_status: 'Valid SSL (TLS 1.3 - Verified)',
      domain_age: '12 years (Established)',
      domain_age_days: 4380,
      redirects: 0,
      redirect_status: '0 redirects (Direct)',
      blacklisted: false,
      blacklist_status: 'Clean (Not listed on threat databases)',
      reason:
        '[DEMO DATA] URL evaluated cleanly with no suspicious indicators. Domain is established (12 years) with valid TLS 1.3 encryption and clean reputation on all threat feeds.',
      signals: [
        {
          signal: 'Valid SSL Certificate',
          severity: 'safe',
          description: 'Strong TLS 1.3 certificate issued by DigiCert with extended validation.',
        },
        {
          signal: 'Established Domain Reputation',
          severity: 'safe',
          description: 'Domain active for over 12 years with clean WHOIS and zero security flags.',
        },
      ],
      method: 'realtime-ml',
      source: 'Presentation Demo Simulation',
      is_demo: true,
      isDemo: true,
    },
  },
  2: {
    level: 2,
    label: 'Level 2 – Suspicious',
    badge: 'LEVEL 2: MEDIUM RISK',
    tagline: 'Caution Advised / Moderate Threat',
    url: 'https://demo-account-verification-alert.xyz/verify',
    colorScheme: 'amber',
    fixture: {
      scan_id: 'demo_l2_suspicious',
      url: 'https://demo-account-verification-alert.xyz/verify',
      prediction: 'suspicious',
      verdict: 'SUSPICIOUS',
      risk_score: 48.5,
      riskScore: 48.5,
      risk_level: 'Medium Risk',
      threat_level: 'MEDIUM',
      detection_level: 2,
      level_name: 'Level 2 – Medium Risk (Suspicious)',
      confidence: 86.4,
      bilstm_score: 49.2,
      cnn_score: 47.6,
      ensemble_score: 48.5,
      analysis: {
        rnn_probability: 0.492,
        cnn_probability: 0.476,
        ensemble_probability: 0.485,
      },
      model: 'DL-CNN-BiLSTM (0.55 / 0.45 Ensemble + GAN)',
      inference_time_ms: 22.4,
      ssl: true,
      ssl_status: 'Valid SSL (Free / Low Assurance)',
      domain_age: '14 days (Newly Registered)',
      domain_age_days: 14,
      redirects: 1,
      redirect_status: '1 redirect (Tracking intermediary)',
      blacklisted: false,
      blacklist_status: 'Clean (Not yet blacklisted - emerging domain)',
      reason:
        '[DEMO DATA] Flagged as Level 2 Medium Risk (Suspicious) with a continuous threat score of 48.5%. Detected indicators: Newly registered domain (14 days), high-risk generic TLD (.xyz), and intermediate redirect. Caution is advised: avoid submitting passwords or sensitive credentials until verified.',
      signals: [
        {
          signal: 'Newly Registered Domain',
          severity: 'medium',
          description: 'Domain registered only 14 days ago — typical of temporary phishing infrastructure.',
        },
        {
          signal: 'Unusual Subdomain & TLD',
          severity: 'medium',
          description: 'High-risk .xyz generic TLD paired with urgent verification keywords.',
        },
        {
          signal: 'Intermediate Redirect Hop',
          severity: 'low',
          description: 'URL redirects through an external tracking hop before reaching final page.',
        },
      ],
      method: 'realtime-ml',
      source: 'Presentation Demo Simulation',
      is_demo: true,
      isDemo: true,
    },
  },
  3: {
    level: 3,
    label: 'Level 3 – Dangerous',
    badge: 'LEVEL 3: HIGH RISK (PHISHING)',
    tagline: 'Critical Threat / Phishing Attack',
    url: 'http://demo.paypal.security-update.com.signin.net/login',
    colorScheme: 'red',
    fixture: {
      scan_id: 'demo_l3_phishing',
      url: 'http://demo.paypal.security-update.com.signin.net/login',
      prediction: 'phishing',
      verdict: 'PHISHING',
      risk_score: 92.4,
      riskScore: 92.4,
      risk_level: 'High Risk',
      threat_level: 'CRITICAL',
      detection_level: 3,
      level_name: 'Level 3 – High Risk (Dangerous Phishing)',
      confidence: 99.1,
      bilstm_score: 91.8,
      cnn_score: 93.1,
      ensemble_score: 92.4,
      analysis: {
        rnn_probability: 0.918,
        cnn_probability: 0.931,
        ensemble_probability: 0.924,
      },
      model: 'DL-CNN-BiLSTM (0.55 / 0.45 Ensemble + GAN)',
      inference_time_ms: 18.7,
      ssl: false,
      ssl_status: 'Missing SSL (Plain HTTP - Insecure)',
      domain_age: 'Unable to verify (Privacy protected)',
      domain_age_days: null,
      redirects: 2,
      redirect_status: '2 redirects (Obfuscated chain)',
      blacklisted: true,
      blacklist_status: 'Listed (Confirmed Phishing Threat)',
      reason:
        '[DEMO DATA] CRITICAL WARNING: Classified as Level 3 High Risk (Dangerous Phishing) with a threat score of 92.4%. Critical indicators: Unencrypted plain HTTP transmission, aggressive brand spoofing (PayPal impersonation), and active threat blacklist listing. Do NOT enter passwords, banking details, or personal credentials.',
      signals: [
        {
          signal: 'Deceptive Brand Impersonation',
          severity: 'critical',
          description: 'Detected deceptive PayPal brand imitation using nested misleading subdomains.',
        },
        {
          signal: 'Unencrypted Plain HTTP Transmission',
          severity: 'critical',
          description: 'Sensitive login interface transmitted without SSL/TLS encryption.',
        },
        {
          signal: 'Active Threat Blacklist Match',
          severity: 'high',
          description: 'Domain actively flagged in threat intelligence feeds as credential harvesting infrastructure.',
        },
      ],
      method: 'realtime-ml',
      source: 'Presentation Demo Simulation',
      is_demo: true,
      isDemo: true,
    },
  },
};

export function getDemoFixture(level: 1 | 2 | 3): ScanResult {
  return DEMO_FIXTURES[level].fixture;
}
