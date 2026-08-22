/**
 * PhishGuard AI — API Response Normalization Layer & Type Safety Utilities
 * Centralized parsing layer to ensure browser UI scripts never crash due to
 * API shape variations, missing fields, or object type mismatches.
 */

(function (root, factory) {
  if (typeof define === 'function' && define.amd) {
    define([], factory);
  } else if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.PhishGuardNormalizer = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {

  /**
   * Safely formats any model representation (string or object) into a clean display title.
   * Handles Formats A-D without ever producing "[object Object]".
   */
  function getModelDisplay(model) {
    if (typeof model === 'string') {
      const normalized = model.trim().toLowerCase();

      if (normalized === 'cnn_bilstm' || normalized.includes('bilstm')) {
        return 'DL-CNN-BiLSTM';
      }
      if (normalized === 'rnn_gan') {
        return 'DL-RNN-GAN';
      }
      if (normalized === 'rnn') {
        return 'DL-RNN';
      }
      if (normalized === 'gan') {
        return 'DL-GAN';
      }
      if (normalized.includes('pure deep learning') || normalized.includes('fusion')) {
        return 'DL-CNN-BiLSTM (GAN Ensembled)';
      }

      return model.trim();
    }

    if (model && typeof model === 'object' && !Array.isArray(model)) {
      const name = model.name || model.model_name || model.architecture || model.type;
      const version = model.version || model.model_version;

      if (name) {
        let cleanName = String(name).trim();
        if (cleanName.toLowerCase() === 'cnn_bilstm') cleanName = 'DL-CNN-BiLSTM';
        if (cleanName.toLowerCase() === 'rnn_gan') cleanName = 'DL-RNN-GAN';
        return version ? `${cleanName} ${version}` : cleanName;
      }

      if (model.rnn_executed && model.cnn_executed) {
        return 'DL-CNN-BiLSTM (GAN Ensembled)';
      }
    }

    return 'Deep Learning';
  }

  /**
   * Safely extracts model version string from raw model data or top-level field.
   */
  function getModelVersion(model, rawVersion) {
    if (rawVersion && typeof rawVersion === 'string') {
      return rawVersion.trim();
    }
    if (model && typeof model === 'object' && !Array.isArray(model)) {
      if (model.version) return String(model.version).trim();
      if (model.model_version) return String(model.model_version).trim();
    }
    return 'v2.0';
  }

  /**
   * Normalizes risk score inputs (numbers or strings) to [0.0, 100.0] float range.
   * Returns null if unparseable or infinite.
   */
  function normalizeRiskScore(value) {
    if (value === null || value === undefined) return null;
    const score = Number(value);
    if (!Number.isFinite(score)) return null;
    return Math.max(0, Math.min(100, Math.round(score * 10) / 10));
  }

  /**
   * Normalizes confidence values into percentage scale [0.0, 100.0].
   * Handles both fractional [0.0, 1.0] and percentage [0.0, 100.0] inputs.
   */
  function normalizeConfidence(value) {
    if (value === null || value === undefined) return null;
    const numeric = Number(value);
    if (!Number.isFinite(numeric)) return null;

    if (numeric > 0 && numeric <= 1.0) {
      return Math.round(numeric * 1000) / 10;
    }
    return Math.max(0, Math.min(100, Math.round(numeric * 10) / 10));
  }

  /**
   * Validates and normalizes security verdicts into standard uppercase strings:
   * 'SAFE' | 'SUSPICIOUS' | 'PHISHING' | 'MALICIOUS' | 'UNKNOWN'
   */
  function normalizeVerdict(value) {
    if (typeof value !== 'string') return 'UNKNOWN';
    const verdict = value.trim().toUpperCase();

    if (verdict === 'SAFE' || verdict === 'LOW') return 'SAFE';
    if (verdict === 'SUSPICIOUS' || verdict === 'MEDIUM') return 'SUSPICIOUS';
    if (verdict === 'PHISHING' || verdict === 'HIGH' || verdict === 'CRITICAL') return 'PHISHING';
    if (verdict === 'MALICIOUS') return 'MALICIOUS';

    const allowed = ['SAFE', 'SUSPICIOUS', 'PHISHING', 'MALICIOUS', 'UNKNOWN'];
    return allowed.includes(verdict) ? verdict : 'UNKNOWN';
  }

  /**
   * Normalizes threat detection signals list elements safely.
   */
  function normalizeSignal(signalObj) {
    if (!signalObj || typeof signalObj !== 'object') {
      return {
        signal: 'Detection Anomaly',
        severity: 'medium',
        description: String(signalObj || 'Suspicious structural URL pattern detected')
      };
    }
    return {
      signal: String(signalObj.signal || signalObj.name || 'Detection Anomaly'),
      severity: String(signalObj.severity || 'medium').toLowerCase(),
      description: String(signalObj.description || signalObj.details || '')
    };
  }

  /**
   * Master Normalization Entry Point
   * Converts any raw backend payload or storage entry into a strictly typed, immutable result object.
   */
  function normalizeScanResult(raw) {
    if (!raw || typeof raw !== 'object') {
      return {
        success: false,
        scanId: 'scan_error',
        tabId: null,
        url: '',
        verdict: 'UNKNOWN',
        prediction: 'Scan Unavailable',
        riskScore: null,
        threatLevel: 'UNKNOWN',
        confidence: null,
        model: 'Deep Learning',
        modelDisplay: 'Deep Learning',
        modelVersion: 'v2.0',
        inferenceTimeMs: null,
        analysis: {},
        signals: [],
        telemetry: {},
        cache: 'DISABLED',
        trustedDomainBypass: 'DISABLED',
        timestamp: new Date().toISOString()
      };
    }

    const rawVerdict = raw.verdict || raw.prediction;
    const normalizedVerdict = normalizeVerdict(rawVerdict);
    const riskScore = normalizeRiskScore(raw.risk_score ?? raw.riskScore ?? raw.risk);

    let threatLevel = String(raw.threat_level || raw.threatLevel || '').toUpperCase();
    if (!threatLevel || threatLevel === 'UNKNOWN') {
      if (normalizedVerdict === 'SAFE') threatLevel = 'LOW';
      else if (normalizedVerdict === 'SUSPICIOUS') threatLevel = 'MEDIUM';
      else if (normalizedVerdict === 'PHISHING') threatLevel = 'CRITICAL';
      else threatLevel = 'LOW';
    }

    const modelDisplay = getModelDisplay(raw.model);
    const modelVersion = getModelVersion(raw.model, raw.model_version);

    const signalsRaw = Array.isArray(raw.signals) ? raw.signals : [];
    const signals = signalsRaw.map(normalizeSignal);

    const inferenceTime = Number(raw.inference_time_ms ?? raw.inferenceTime);

    return {
      success: raw.success !== false,
      scanId: String(raw.scan_id || raw.scanId || 'scan_unknown'),
      tabId: raw.tab_id || raw.tabId || null,
      url: String(raw.url || raw.target_url || ''),
      verdict: normalizedVerdict,
      prediction: String(raw.prediction || normalizedVerdict),
      riskScore: riskScore,
      threatLevel: threatLevel,
      confidence: normalizeConfidence(raw.confidence),
      model: raw.model,
      modelDisplay: modelDisplay,
      modelVersion: modelVersion,
      inferenceTimeMs: Number.isFinite(inferenceTime) ? Math.round(inferenceTime * 10) / 10 : null,
      analysis: typeof raw.analysis === 'object' && raw.analysis !== null ? raw.analysis : {},
      signals: signals,
      telemetry: typeof raw.telemetry === 'object' && raw.telemetry !== null ? raw.telemetry : {},
      cache: 'DISABLED',
      trustedDomainBypass: 'DISABLED',
      timestamp: String(raw.timestamp || new Date().toISOString())
    };
  }

  /**
   * Normalizes URL strings for exact comparison, ignoring trailing slashes, hashes, and query params.
   */
  function normalizeUrlForComparison(url) {
    if (!url || typeof url !== 'string') return '';
    try {
      const u = new URL(url.trim());
      return (u.origin + u.pathname).toLowerCase().replace(/\/+$/, '');
    } catch (e) {
      return url.trim().toLowerCase().replace(/\/+$/, '');
    }
  }

  return {
    getModelDisplay: getModelDisplay,
    getModelVersion: getModelVersion,
    normalizeRiskScore: normalizeRiskScore,
    normalizeConfidence: normalizeConfidence,
    normalizeVerdict: normalizeVerdict,
    normalizeScanResult: normalizeScanResult,
    normalizeUrlForComparison: normalizeUrlForComparison
  };
}));
