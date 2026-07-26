import { useState, type ReactNode } from 'react';
import { motion } from 'framer-motion';
import { Lock, LockOpen, Calendar, ArrowRightLeft, ShieldAlert, Globe2, Flag } from 'lucide-react';
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
      toast.success('Thanks — we logged this as a reported false positive.');
    } catch {
      toast.error('Could not send the report. Try again in a moment.');
    } finally {
      setReporting(false);
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="grid gap-6 lg:grid-cols-[auto_1fr]"
    >
      <Card className="flex flex-col items-center justify-center gap-4">
        <RiskRing score={result.risk_score} verdict={result.prediction} />
        <Badge verdict={result.prediction} className="text-sm">
          {result.prediction}
        </Badge>
        <p className="text-center text-xs text-slate-400">
          {result.confidence}% model confidence
        </p>
      </Card>

      <div className="flex flex-col gap-4">
        <Card>
          <p className="text-sm leading-relaxed text-slate-200">
            <span className="font-hand text-brand-soft underline-scribble">Explanation</span>
            <br />
            {result.reason}
          </p>
        </Card>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <InfoTile
            icon={result.ssl ? <Lock className="h-4 w-4" /> : <LockOpen className="h-4 w-4" />}
            label="SSL"
            value={result.ssl ? 'Valid' : 'Missing'}
            tone={result.ssl ? 'safe' : 'danger'}
          />
          <InfoTile icon={<Calendar className="h-4 w-4" />} label="Domain age" value={result.domain_age} />
          <InfoTile
            icon={<ArrowRightLeft className="h-4 w-4" />}
            label="Redirects"
            value={String(result.redirects)}
            tone={result.redirects >= 2 ? 'warn' : undefined}
          />
          <InfoTile
            icon={<ShieldAlert className="h-4 w-4" />}
            label="Blacklist"
            value={result.blacklisted ? 'Flagged' : 'Clear'}
            tone={result.blacklisted ? 'danger' : 'safe'}
          />
        </div>

        <Card>
          <div className="mb-3 flex items-center gap-2 text-sm font-semibold">
            <Globe2 className="h-4 w-4 text-brand-soft" /> WHOIS
          </div>
          <div className="grid grid-cols-2 gap-3 text-sm text-slate-300">
            <div>
              <p className="text-xs text-slate-500">Registrar</p>
              <p>{result.whois.registrar}</p>
            </div>
            <div>
              <p className="text-xs text-slate-500">Country</p>
              <p>{result.whois.country}</p>
            </div>
          </div>
        </Card>

        <Card>
          <p className="mb-3 text-sm font-semibold">Detection signals</p>
          <SignalsList signals={result.signals} />
        </Card>

        <Button variant="ghost" onClick={handleReport} isLoading={reporting} className="self-start">
          <Flag className="h-4 w-4" /> Report false positive
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
    tone === 'safe' ? 'text-safe' : tone === 'warn' ? 'text-warn' : tone === 'danger' ? 'text-danger' : 'text-slate-200';
  return (
    <div className="sketch-panel flex flex-col gap-1 p-3">
      <div className="flex items-center gap-1.5 text-xs text-slate-500">
        {icon}
        {label}
      </div>
      <p className={`font-mono text-sm font-medium ${toneColor}`}>{value}</p>
    </div>
  );
}
