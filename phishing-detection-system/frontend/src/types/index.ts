export type Verdict = 'safe' | 'suspicious' | 'phishing';

export interface Signal {
  signal: string;
  severity: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  description: string;
}

export interface ModelComparisonEntry {
  prediction: string;
  confidence: number;
}

export interface WhoisInfo {
  registrar: string;
  country: string;
}

export interface ScanResult {
  url: string;
  prediction: Verdict;
  risk_score: number;
  risk_level?: string;
  confidence: number;
  inference_time_ms?: number;
  ssl: boolean;
  domain_age: string;
  redirects: number;
  blacklisted: boolean;
  whois: WhoisInfo;
  reason: string;
  signals: Signal[];
  model_comparison?: Record<string, ModelComparisonEntry>;
  scanned_at: string;
  method: string;
}

export interface HistoryEntry {
  id: number;
  url: string;
  prediction: Verdict;
  risk_score: number;
  confidence: number;
  scanned_at: string;
}

export interface Statistics {
  total: number;
  phishing: number;
  suspicious: number;
  safe: number;
}

export interface DailyScanPoint {
  date: string;
  safe: number;
  suspicious: number;
  phishing: number;
}

export interface WeeklyScanPoint {
  week: string;
  scans: number;
}

export interface AnalyticsData {
  daily_scans: DailyScanPoint[];
  weekly_scans: WeeklyScanPoint[];
  detection_accuracy: number | null;
  threat_distribution: { safe: number; suspicious: number; phishing: number };
  safe_vs_phishing_ratio: number | null;
  total_scans: number;
}

export interface User {
  id: number;
  name: string;
  email: string;
  created_at?: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  user: User;
}

export interface ApiError {
  error: string;
}
