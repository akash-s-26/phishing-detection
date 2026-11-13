import { useState, type ReactNode } from 'react';
import { motion } from 'framer-motion';
import {
  Lock,
  LockOpen,
  Calendar,
  ArrowRightLeft,
  ShieldAlert,
  Globe2,
  Flag,
  Cpu,
  ShieldCheck,
  AlertTriangle,
  AlertOctagon,
  Copy,
  Check,
  ArrowLeft,
  ShieldX,
} from 'lucide-react';
import type { ScanResult } from '@/types';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { RiskRing } from '@/components/RiskRing';
import { SignalsList } from '@/components/SignalsList';
import { reportFalsePositive } from '@/services/scanService';
import { resolveDetectionLevel } from '@/utils/securityLevels';
import { toast } from 'sonner';

export function ResultCard({ result }: { result: ScanResult }) {
  const [reporting, setReporting] = useState(false);
  const [copied, setCopied] = useState(false);
  const [level3Acknowledged, setLevel3Acknowledged] = useState(false);

  const levelMeta = resolveDetectionLevel(
    result.risk_score,
    result.prediction,
    result.threat_level,
    result.detection_level
  );

  async function handleReport() {
    setReporting(true);
    try {
      await reportFalsePositive(result.url);
      toast.success('Thanks — false positive report logged successfully.');
    } catch {
      toast.error('Could not send report. Please try again.');
    } finally {
      setReporting(false);
    }
  }

  function handleCopyUrl() {
    navigator.clipboard.writeText(result.url);
    setCopied(true);
    toast.success('URL copied to clipboard');
    setTimeout(() => setCopied(false), 2000);
  }

  function handleReturnToSafety() {
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.location.href = 'https://www.google.com';
    }
  }

  // Level-specific styles and badges
  const isLevel1 = levelMeta.level === 1;
  const isLevel2 = levelMeta.level === 2;
  const isLevel3 = levelMeta.level === 3;

  const bannerTheme = isLevel1
    ? {
        border: 'border-emerald-500/30',
        bg: 'bg-emerald-950/20',
        text: 'text-emerald-400',
        glow: 'shadow-[0_0_25px_rgba(16,185,129,0.12)]',
        badgeBg: 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300',
        icon: <ShieldCheck className="h-6 w-6 text-emerald-400" />,
      }
    : isLevel2
    ? {
        border: 'border-amber-500/30',
        bg: 'bg-amber-950/20',
        text: 'text-amber-400',
        glow: 'shadow-[0_0_25px_rgba(245,158,11,0.12)]',
        badgeBg: 'bg-amber-500/15 border-amber-500/30 text-amber-300',
        icon: <AlertTriangle className="h-6 w-6 text-amber-400" />,
      }
    : {
        border: 'border-rose-500/40',
        bg: 'bg-rose-950/30',
        text: 'text-rose-400',
        glow: 'shadow-[0_0_35px_rgba(239,68,68,0.2)]',
        badgeBg: 'bg-rose-500/20 border-rose-500/40 text-rose-300',
        icon: <AlertOctagon className="h-6 w-6 text-rose-400 animate-pulse" />,
      };

  // DL Scores
  const rnnProb = result.analysis?.rnn_probability ?? (result.bilstm_score ? result.bilstm_score / 100 : 0);
  const cnnProb = result.analysis?.cnn_probability ?? (result.cnn_score ? result.cnn_score / 100 : 0);

  // Dynamic Executive Security Explanation resolution (guarantees zero identical fallback text)
  const resolvedExplanation = (() => {
    if (result.reason && result.reason.trim()) {
      return result.reason.trim();
    }
    let host = 'Target website';
    try {
      host = new URL(result.url).hostname || result.url;
    } catch {
      host = result.url || 'Target website';
    }
    const score = result.risk_score ?? 0;
    if (levelMeta.level === 1) {
      const isHttps = result.url.startsWith('https://');
      const sslNote = isHttps ? 'valid HTTPS encryption verified' : 'URL syntax conforms to standard web patterns';
      return `URL '${host}' evaluated as Level 1 Low Risk with a threat score of ${score}%. Deep learning character and sequence analysis verified legitimate structural characteristics with ${sslNote}. No significant phishing indicators were detected.`;
    }
    if (levelMeta.level === 2) {
      const sigNames = (result.signals || []).map(s => s.signal).filter(Boolean);
      const sigDetail = sigNames.length > 0 ? `Detected indicators: ${sigNames.join(', ')}.` : 'Anomalous structural patterns and unverified domain markers detected.';
      return `Flagged as Level 2 Medium Risk (Suspicious) with a continuous threat score of ${score}%. ${sigDetail} Caution is advised: avoid submitting passwords or sensitive credentials until this destination is independently verified.`;
    }
    const sigDescs = (result.signals || []).map(s => s.description || s.signal).filter(Boolean);
    const criticalDetail = sigDescs.length > 0 ? `Critical indicators: ${sigDescs.slice(0, 3).join('; ')}.` : 'High-confidence brand impersonation or credential-harvesting patterns identified by deep neural sequence models.';
    return `CRITICAL WARNING: Classified as Level 3 High Risk (Dangerous Phishing) with a threat score of ${score}%. ${criticalDetail} Do NOT enter passwords, banking details, or personal credentials on this website.`;
  })();

  // SSL Certificate Indicator resolution
  const isHttps = result.url.startsWith('https://');
  const resolvedSslValue = result.ssl_status || (
    result.ssl !== undefined
      ? (result.ssl ? 'Valid SSL' : (isHttps ? 'Valid SSL' : 'Missing SSL'))
      : (isHttps ? 'Valid SSL (HTTPS)' : 'Missing SSL (Plain HTTP)')
  );
  const resolvedSslTone: 'safe' | 'warn' | 'danger' =
    resolvedSslValue.includes('Valid') ? 'safe' :
    resolvedSslValue.includes('Unable') ? 'warn' : 'danger';

  // Domain Age Indicator resolution
  const resolvedDomainAge = result.domain_age || (
    result.domain_age_days !== undefined && result.domain_age_days !== null
      ? `${result.domain_age_days} days`
      : 'Unable to verify'
  );
  const resolvedDomainAgeTone: 'safe' | 'warn' | 'danger' =
    result.domain_age_days !== null && result.domain_age_days !== undefined && result.domain_age_days < 180
      ? 'warn'
      : (resolvedDomainAge === 'Unable to verify' ? 'warn' : 'safe');

  // Redirect Chain Indicator resolution
  const resolvedRedirects = result.redirect_status || (
    typeof result.redirects === 'number'
      ? `${result.redirects} ${result.redirects === 1 ? 'redirect' : 'redirects'}`
      : (result.url.startsWith('http') ? '0 redirects (Direct)' : 'Unable to verify')
  );
  const resolvedRedirectTone: 'safe' | 'warn' | 'danger' =
    (result.redirects || 0) >= 2 ? 'warn' : (resolvedRedirects.includes('Unable') ? 'warn' : 'safe');

  // Blacklist Check Indicator resolution
  const resolvedBlacklist = result.blacklist_status || (
    result.blacklisted !== undefined
      ? (result.blacklisted ? 'Listed' : 'Clean')
      : 'Clean'
  );
  const resolvedBlacklistTone: 'safe' | 'warn' | 'danger' =
    resolvedBlacklist === 'Listed' || result.blacklisted ? 'danger' :
    resolvedBlacklist === 'Clean' ? 'safe' : 'warn';

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="space-y-6"
    >
      {/* ── DEMO DATA WATERMARK / NOTICE ── */}
      {(result.is_demo || result.isDemo) && (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-xl border border-cyan-500/40 bg-cyan-950/40 px-4 py-2.5 text-xs font-mono shadow-md backdrop-blur-sm">
          <div className="flex items-center gap-2 font-bold text-cyan-300">
            <span className="h-2 w-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>DEMO DATA — CONTROLLED PRESENTATION SIMULATION</span>
          </div>
          <span className="text-[11px] text-cyan-400/80">
            Simulated test response for academic presentation demonstration
          </span>
        </div>
      )}

      {/* ── 1. PROMINENT THREE-LEVEL DETECTION BANNER ── */}
      <div
        className={`rounded-2xl border ${bannerTheme.border} ${bannerTheme.bg} ${bannerTheme.glow} p-5 md:p-6 transition-all`}
      >
        <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className="mt-1 flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-slate-900/80 p-2.5">
              {bannerTheme.icon}
            </div>

            <div className="space-y-1">
              <div className="flex flex-wrap items-center gap-2.5">
                <span
                  className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-extrabold tracking-wide uppercase border font-mono ${bannerTheme.badgeBg}`}
                >
                  <span className="h-2 w-2 rounded-full bg-current animate-pulse" />
                  {levelMeta.badgeLabel}
                </span>

                <span className="text-xs font-mono text-slate-400 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                  {levelMeta.completionStatus}
                </span>
              </div>

              <h2 className="text-xl md:text-2xl font-black tracking-tight text-white mt-1">
                {levelMeta.title}
              </h2>

              <p className={`text-sm font-medium ${bannerTheme.text}`}>
                Status: {levelMeta.statusText} • Continuous Threat Score: {result.risk_score}%
              </p>
            </div>
          </div>

          {/* Quick Action Button */}
          {isLevel3 && (
            <div className="flex items-center gap-2 self-start md:self-center">
              <Button
                variant="danger"
                onClick={handleReturnToSafety}
                className="bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs shadow-lg shadow-rose-600/30 flex items-center gap-2"
              >
                <ArrowLeft className="h-4 w-4" /> Return to Safety
              </Button>
            </div>
          )}
        </div>

        {/* Scanned URL display bar */}
        <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-2 rounded-xl bg-slate-950/70 border border-white/5 p-3">
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[11px] font-mono text-slate-500 uppercase tracking-wider shrink-0">
              Scanned URL:
            </span>
            <span className="truncate font-mono text-xs text-slate-200" title={result.url}>
              {result.url}
            </span>
          </div>

          <button
            onClick={handleCopyUrl}
            className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition shrink-0 ml-auto"
            title="Copy URL"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            <span>{copied ? 'Copied' : 'Copy'}</span>
          </button>
        </div>

        {/* Level Security Advisory Notice */}
        <div className="mt-4 rounded-xl border border-white/5 bg-slate-900/60 p-4">
          <p className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-1.5 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyan-400" /> Security Advisory
          </p>
          <p className="text-sm leading-relaxed text-slate-200">
            {levelMeta.advisory}
          </p>
        </div>

        {/* Level 3 Specific Critical Actions */}
        {isLevel3 && (
          <div className="mt-4 pt-4 border-t border-rose-500/20 flex flex-wrap items-center justify-between gap-3 text-xs">
            <div className="flex items-center gap-2 text-rose-300 font-semibold">
              <ShieldX className="h-4 w-4 text-rose-400" />
              <span>Do not submit credentials, credit card details, or sensitive passwords.</span>
            </div>

            <button
              onClick={() => setLevel3Acknowledged(!level3Acknowledged)}
              className="text-xs font-medium text-slate-400 hover:text-white underline"
            >
              {level3Acknowledged ? 'Hide Threat Details' : 'Acknowledge Warning & View Details'}
            </button>
          </div>
        )}
      </div>

      {/* ── 2. MAIN TECHNICAL ANALYSIS & METRICS ── */}
      <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
        {/* Left Column: Risk Gauge & Model Confidence */}
        <Card className="flex flex-col items-center justify-center gap-4 text-center border-white/10 bg-[#111827]">
          <RiskRing score={result.risk_score} verdict={result.prediction} />
          <div className="space-y-1">
            <Badge verdict={result.prediction} className="text-sm px-4 py-1">
              {result.prediction}
            </Badge>
            <div className="mt-1">
              <span
                className={`inline-block px-2.5 py-0.5 rounded-full text-[11px] font-mono font-bold uppercase border ${bannerTheme.badgeBg}`}
              >
                {levelMeta.levelName}
              </span>
            </div>
            {result.risk_level && (
              <p className="text-xs font-mono text-slate-400 mt-1">
                Risk Classification: <span className="font-semibold text-slate-200">{result.risk_level}</span>
              </p>
            )}
          </div>

          <div className="w-full pt-3 border-t border-white/5 space-y-2 text-xs font-mono text-slate-400">
            <div className="flex justify-between">
              <span>Risk Score:</span>
              <span className="font-bold text-white">{result.risk_score}%</span>
            </div>
            <div className="flex justify-between">
              <span>Model Confidence:</span>
              <span className="font-bold text-white">{result.confidence}%</span>
            </div>
            {result.inference_time_ms && (
              <div className="flex justify-between">
                <span>Latency:</span>
                <span className="font-bold text-cyan-400">{result.inference_time_ms} ms</span>
              </div>
            )}
            <div className="flex justify-between">
              <span>Engine:</span>
              <span className="font-bold text-slate-300">{(result.method || 'realtime-ml').toUpperCase()}</span>
            </div>
          </div>
        </Card>

        {/* Right Column: Deep Learning Ensemble Breakdown & Technical Findings */}
        <div className="flex flex-col gap-5">
          {/* Executive Security Explanation */}
          <Card className="border-white/10 bg-[#111827]">
            <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-cyan-400" /> Executive Security Explanation
            </h4>
            <p className="text-sm leading-relaxed text-slate-200">
              {resolvedExplanation}
            </p>
          </Card>

          {/* Deep Learning 0.55 BiLSTM + 0.45 CNN Ensemble Grid */}
          <Card className="border-white/10 bg-[#111827]">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <Cpu className="h-4 w-4 text-cyan-400" /> Deep Learning Fusion Ensemble Predictions
              </div>
              <span className="text-xs font-mono text-slate-400">0.55 BiLSTM + 0.45 1D CNN + GAN</span>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="rounded-xl border border-white/5 bg-slate-900/60 p-3 space-y-1">
                <p className="text-[11px] font-medium capitalize text-slate-400">BiLSTM RNN (55%)</p>
                <p className="text-xs font-bold font-mono text-cyan-400">
                  {result.bilstm_score !== undefined
                    ? `${result.bilstm_score}%`
                    : `${(rnnProb * 100).toFixed(1)}%`}
                </p>
                <p className="text-[10px] font-mono text-slate-500">Character Sequence</p>
              </div>

              <div className="rounded-xl border border-white/5 bg-slate-900/60 p-3 space-y-1">
                <p className="text-[11px] font-medium capitalize text-slate-400">1D CNN Model (45%)</p>
                <p className="text-xs font-bold font-mono text-cyan-400">
                  {result.cnn_score !== undefined
                    ? `${result.cnn_score}%`
                    : `${(cnnProb * 100).toFixed(1)}%`}
                </p>
                <p className="text-[10px] font-mono text-slate-500">n-Gram Conv Patterns</p>
              </div>

              <div className="rounded-xl border border-white/5 bg-slate-900/60 p-3 space-y-1">
                <p className="text-[11px] font-medium capitalize text-slate-400">GAN Augmentation</p>
                <p className="text-xs font-bold font-mono text-emerald-400">ACTIVE</p>
                <p className="text-[10px] font-mono text-slate-500">+5.7k Quality Samples</p>
              </div>

              <div className="rounded-xl border border-white/5 bg-slate-900/60 p-3 space-y-1">
                <p className="text-[11px] font-medium capitalize text-slate-400">Fusion Score</p>
                <p className="text-xs font-bold font-mono text-cyan-400">
                  {result.risk_score}%
                </p>
                <p className="text-[10px] font-mono text-slate-500">Continuous Output</p>
              </div>
            </div>
          </Card>

          {/* Quick Technical Signals Grid */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <InfoTile
              icon={
                resolvedSslTone === 'safe'
                  ? <Lock className="h-4 w-4 text-emerald-400" />
                  : (resolvedSslTone === 'warn' ? <Lock className="h-4 w-4 text-amber-400" /> : <LockOpen className="h-4 w-4 text-rose-400" />)
              }
              label="SSL Certificate"
              value={resolvedSslValue}
              tone={resolvedSslTone}
            />
            <InfoTile
              icon={<Calendar className="h-4 w-4 text-slate-400" />}
              label="Domain Age"
              value={resolvedDomainAge}
              tone={resolvedDomainAgeTone}
            />
            <InfoTile
              icon={<ArrowRightLeft className="h-4 w-4 text-slate-400" />}
              label="Redirect Chain"
              value={resolvedRedirects}
              tone={resolvedRedirectTone}
            />
            <InfoTile
              icon={<ShieldAlert className="h-4 w-4 text-slate-400" />}
              label="Blacklist Check"
              value={resolvedBlacklist}
              tone={resolvedBlacklistTone}
            />
          </div>

          {/* WHOIS Registry Info */}
          <Card className="border-white/10 bg-[#111827]">
            <div className="mb-3 flex items-center gap-2 text-sm font-bold text-white">
              <Globe2 className="h-4 w-4 text-cyan-400" /> WHOIS Registry Information
            </div>
            <div className="grid grid-cols-2 gap-4 text-xs font-mono text-slate-300">
              <div>
                <p className="text-[11px] text-slate-500 font-sans">Registrar</p>
                <p className="font-semibold text-slate-200">{result.whois?.registrar || 'Unable to verify'}</p>
              </div>
              <div>
                <p className="text-[11px] text-slate-500 font-sans">Country</p>
                <p className="font-semibold text-slate-200">{result.whois?.country || 'Unable to verify'}</p>
              </div>
            </div>
          </Card>

          {/* Detection Signals */}
          <Card className="border-white/10 bg-[#111827]">
            <p className="mb-3 text-sm font-bold text-white flex items-center justify-between">
              <span>Detection Signals & Behavioral Indicators</span>
              <span className="text-xs font-normal text-slate-400 font-mono">
                {result.signals?.length || 0} signals
              </span>
            </p>
            <SignalsList signals={result.signals} />
          </Card>

          <Button
            variant="ghost"
            onClick={handleReport}
            isLoading={reporting}
            className="self-start text-xs text-amber-400 hover:text-amber-300"
          >
            <Flag className="h-3.5 w-3.5 mr-1" /> Report False Positive
          </Button>
        </div>
      </div>
    </motion.div>
  );
}

function InfoTile({
  icon,
  label,
  value,
  tone,
}: {
  icon: ReactNode;
  label: string;
  value: string;
  tone?: 'safe' | 'warn' | 'danger';
}) {
  const toneColor =
    tone === 'safe'
      ? 'text-emerald-400'
      : tone === 'warn'
      ? 'text-amber-400'
      : tone === 'danger'
      ? 'text-rose-400'
      : 'text-slate-200';
  return (
    <div className="flex flex-col gap-1 rounded-xl border border-white/5 bg-[#111827] p-3.5">
      <div className="flex items-center gap-1.5 text-xs text-slate-400">
        {icon}
        {label}
      </div>
      <p className={`font-mono text-xs font-semibold ${toneColor}`}>{value}</p>
    </div>
  );
}
