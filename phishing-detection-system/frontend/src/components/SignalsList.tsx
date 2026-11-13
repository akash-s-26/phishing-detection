import type { Signal } from '@/types';
import { cn } from '@/utils/cn';
import { CheckCircle2 } from 'lucide-react';

const severityDot: Record<string, string> = {
  safe: 'bg-emerald-400',
  low: 'bg-slate-400',
  medium: 'bg-amber-400',
  high: 'bg-rose-500',
  critical: 'bg-rose-500',
};

export function SignalsList({ signals }: { signals: Signal[] }) {
  if (!signals || signals.length === 0) {
    return (
      <div className="flex items-center gap-3 rounded-xl border border-emerald-500/20 bg-emerald-950/20 p-4 text-xs">
        <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-400" />
        <div>
          <p className="font-semibold text-emerald-300">No Phishing Indicators Detected</p>
          <p className="text-slate-400 mt-0.5">
            Deep Learning sequence modeling and structural feature analysis verified this URL as clean.
          </p>
        </div>
      </div>
    );
  }

  return (
    <ul className="flex flex-col gap-2">
      {signals.map((s) => (
        <li key={s.signal} className="flex items-start gap-3 rounded-lg bg-black/15 p-3">
          <span className={cn('mt-1.5 h-2 w-2 shrink-0 rounded-full', severityDot[s.severity] ?? 'bg-slate-400')} />
          <div>
            <p className="text-sm font-medium text-slate-200">{s.signal}</p>
            <p className="text-xs text-slate-400">{s.description}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}
