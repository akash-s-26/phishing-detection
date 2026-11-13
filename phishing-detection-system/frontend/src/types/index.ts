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

export interface DLAnalysis {
  rnn_probability: number;
  cnn_probability: number;
  ensemble_probability: number;
}

export interface DLModelMetadata {
  name: string;
  version: string;
  rnn_executed: boolean;
  cnn_executed: boolean;
  gan_executed: boolean;
  rnn_probability: number;
  cnn_probability: number;
  ensemble_probability: number;
  inference_time_ms: number;
}

export type DetectionLevel = 1 | 2 | 3;

export interface DetectionLevelMeta {
  level: DetectionLevel;
  levelName: string;
  badgeLabel: string;
  title: string;
  statusText: string;
  advisory: string;
  completionStatus: string;
  colorScheme: 'green' | 'amber' | 'red';
  hexColor: string;
}

export interface ScanResult {
  scan_id?: string;
  url: string;
  prediction: Verdict;
  verdict?: string;
  risk_score: number;
  riskScore?: number;
  risk_level?: string;
  threat_level?: string;
  detection_level?: DetectionLevel;
  level_name?: string;
  bilstm_score?: number;
  cnn_score?: number;
  ensemble_score?: number;
  confidence: number;
  inference_time_ms?: number;
  ssl?: boolean;
  ssl_status?: string;
  ssl_detail?: Record<string, any>;
  domain_age?: string;
  domain_age_days?: number | null;
  redirects?: number;
  redirect_chain?: string[];
  redirect_status?: string;
  blacklisted?: boolean;
  blacklist_status?: string;
  blacklist_detail?: Record<string, any>;
  whois?: WhoisInfo;
  reason?: string;
  signals: Signal[];
  analysis?: DLAnalysis;
  model?: DLModelMetadata | string;
  cache?: string;
  trusted_domain_bypass?: string;
  model_comparison?: Record<string, ModelComparisonEntry>;
  scanned_at?: string;
  timestamp?: string;
  method?: string;
  source?: string;
  is_demo?: boolean;
  isDemo?: boolean;
}

export interface HistoryEntry {
  id: number;
  url: string;
  domain?: string;
  prediction: Verdict;
  status?: string;
  risk_score: number;
  threat_score?: number;
  confidence: number;
  reason?: string;
  model_prediction?: string;
  source?: string;
  scanned_at: string;
  created_at?: string;
  detection_level?: DetectionLevel;
  level_name?: string;
  risk_level?: string;
  threat_level?: string;
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
