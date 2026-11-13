import type { DetectionLevel, DetectionLevelMeta } from '@/types';

export function resolveDetectionLevel(
  score: number,
  verdict?: string,
  threatLevel?: string,
  explicitLevel?: number
): DetectionLevelMeta {
  let level: DetectionLevel = 1;

  if (explicitLevel === 1 || explicitLevel === 2 || explicitLevel === 3) {
    level = explicitLevel;
  } else {
    const v = (verdict || '').toLowerCase();
    const t = (threatLevel || '').toLowerCase();

    if (v === 'phishing' || v === 'malicious' || t === 'critical' || t === 'high' || score > 70.0) {
      level = 3;
    } else if (v === 'suspicious' || t === 'medium' || (score > 30.0 && score <= 70.0)) {
      level = 2;
    } else {
      level = 1;
    }
  }

  if (level === 1) {
    return {
      level: 1,
      levelName: 'Level 1 – Low Risk',
      badgeLabel: 'LEVEL 1: LOW RISK',
      title: 'Safe — Low Phishing Risk',
      statusText: 'Safe — Verified Clean',
      advisory:
        'No significant phishing indicators were detected. The domain and URL structure align with legitimate web patterns. Standard browsing precautions apply.',
      completionStatus: 'Scan Completed • Clean Site Verified',
      colorScheme: 'green',
      hexColor: '#10b981',
    };
  }

  if (level === 2) {
    return {
      level: 2,
      levelName: 'Level 2 – Medium Risk',
      badgeLabel: 'LEVEL 2: MEDIUM RISK',
      title: 'Suspicious — Moderate Risk Detected',
      statusText: 'Caution Advised — Suspicious Activity',
      advisory:
        'Suspicious indicators detected by Deep Learning sequence analysis. Avoid entering passwords, banking credentials, or sensitive information until this website is independently verified.',
      completionStatus: 'Scan Completed • Caution Advised',
      colorScheme: 'amber',
      hexColor: '#f59e0b',
    };
  }

  return {
    level: 3,
    levelName: 'Level 3 – High Risk',
    badgeLabel: 'LEVEL 3: HIGH RISK (DANGEROUS)',
    title: 'Dangerous — Phishing Attack Detected',
    statusText: 'Dangerous — Phishing Threat Detected',
    advisory:
      'CRITICAL WARNING: PhishGuard AI deep neural ensemble detected high-confidence phishing indicators. Do NOT enter passwords, banking credentials, or personal information.',
    completionStatus: 'Scan Completed • Threat Detected',
    colorScheme: 'red',
    hexColor: '#ef4444',
  };
}
