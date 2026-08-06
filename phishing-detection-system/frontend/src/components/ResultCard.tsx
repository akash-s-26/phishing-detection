import { useState, type ReactNode } from 'react';
import { motion } from 'framer-motion';
import { Lock, LockOpen, Calendar, ArrowRightLeft, ShieldAlert, Globe2, Flag, Cpu, ShieldCheck } from 'lucide-react';
import type { ScanResult } from '@/types';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { RiskRing } from '@/components/RiskRing';
import { SignalsList } from '@/components/SignalsList';
import { reportFalsePositive } from '@/services/scanService';
import { toast } from 'sonner';

export function ResultCard({ result }: { result: ScanResult }) {
  const [reporting, setReporting] = useState(false);

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

  const modelComparison = result.model_comparison || {};
  const hasComparison = Object.keys(modelComparison).length > 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="grid gap-6 lg:grid-cols-[280px_1fr]"
    >
      <Card className="flex flex-col items-center justify-center gap-4 text-center border-white/10 bg-[#111827]">
        <RiskRing score={result.risk_score} verdict={result.prediction} />
        <div className="space-y-1">
          <Badge verdict={result.prediction} className="text-sm px-4 py-1">
            {result.prediction}
          </Badge>
          {result.risk_level && (
            <p className="text-xs font-mono text-slate-400 mt-1">
              Risk Level: <span className="font-semibold text-slate-200">{result.risk_level}</span>
            </p>
          )}
        </div>

        <div className="w-full pt-3 border-t border-white/5 space-y-2 text-xs font-mono text-slate-400">
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

      <div className="flex flex-col gap-5">
        <Card className="border-white/10 bg-[#111827]">
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2 flex items-center gap-2">
            <ShieldCheck className="h-4 w-4 text-cyan-400" /> Executive Security Explanation
          </h4>
          <p className="text-sm leading-relaxed text-slate-200">
            {result.reason || 'URL evaluated cleanly with no suspicious indicators.'}
          </p>
        </Card>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <InfoTile
            icon={result.ssl ? <Lock className="h-4 w-4 text-emerald-400" /> : <LockOpen className="h-4 w-4 text-rose-400" />}
            label="SSL Certificate"
            value={result.ssl ? 'Valid SSL' : 'Missing SSL'}
            tone={result.ssl ? 'safe' : 'danger'}
          />
          <InfoTile icon={<Calendar className="h-4 w-4 text-slate-400" />} label="Domain Age" value={result.domain_age || 'Unknown'} />
          <InfoTile
            icon={<ArrowRightLeft className="h-4 w-4 text-slate-400" />}
            label="Redirect Chain"
            value={`${result.redirects || 0} redirects`}
            tone={result.redirects >= 2 ? 'warn' : undefined}
          />
          <InfoTile
            icon={<ShieldAlert className="h-4 w-4 text-slate-400" />}
            label="Blacklist Check"
            value={result.blacklisted ? 'Flagged' : 'Clean'}
            tone={result.blacklisted ? 'danger' : 'safe'}
          />
        </div>

        {hasComparison && (
          <Card className="border-white/10 bg-[#111827]">
            <div className="mb-3 flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm font-bold text-white">
                <Cpu className="h-4 w-4 text-cyan-400" /> Multi-Model Ensemble Predictions
              </div>
              <span className="text-xs font-mono text-slate-400">4 Trained Classifiers</span>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {Object.entries(modelComparison).map(([mName, info]) => {
                const isPhish = info.prediction.toLowerCase() === 'phishing';
                return (
                  <div key={mName} className="rounded-xl border border-white/5 bg-slate-900/60 p-3 space-y-1">
                    <p className="text-[11px] font-medium capitalize text-slate-400">{mName.replace('_', ' ')}</p>
                    <p className={`text-xs font-bold font-mono ${isPhish ? 'text-rose-400' : 'text-emerald-400'}`}>
                      {info.prediction.toUpperCase()}
                    </p>
                    <p className="text-[10px] font-mono text-slate-500">{info.confidence}% conf</p>
                  </div>
                );
              })}
            </div>
          </Card>
        )}

        <Card className="border-white/10 bg-[#111827]">
          <div className="mb-3 flex items-center gap-2 text-sm font-bold text-white">
            <Globe2 className="h-4 w-4 text-cyan-400" /> WHOIS Registry Information
          </div>
          <div className="grid grid-cols-2 gap-4 text-xs font-mono text-slate-300">
            <div>
              <p className="text-[11px] text-slate-500 font-sans">Registrar</p>
              <p className="font-semibold text-slate-200">{result.whois?.registrar || 'Unknown'}</p>
            </div>
            <div>
              <p className="text-[11px] text-slate-500 font-sans">Country</p>
              <p className="font-semibold text-slate-200">{result.whois?.country || 'Unknown'}</p>
            </div>
          </div>
        </Card>

        <Card className="border-white/10 bg-[#111827]">
          <p className="mb-3 text-sm font-bold text-white">Detection Signals</p>
          <SignalsList signals={result.signals} />
        </Card>

        <Button variant="ghost" onClick={handleReport} isLoading={reporting} className="self-start text-xs text-amber-400 hover:text-amber-300">
          <Flag className="h-3.5 w-3.5 mr-1" /> Report False Positive
        </Button>
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
    tone === 'safe' ? 'text-emerald-400' : tone === 'warn' ? 'text-amber-400' : tone === 'danger' ? 'text-rose-400' : 'text-slate-200';
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
