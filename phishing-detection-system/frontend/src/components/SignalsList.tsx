import type { Signal } from '@/types';
import { cn } from '@/utils/cn';

const severityDot: Record<string, string> = {
  safe: 'bg-safe',
  low: 'bg-slate-400',
  medium: 'bg-warn',
  high: 'bg-danger',
  critical: 'bg-danger',
};

export function SignalsList({ signals }: { signals: Signal[] }) {
  return (
    <ul className="flex flex-col gap-2">
      {signals.map((s) => (
        <li key={s.signal} className="flex items-start gap-3 rounded-lg bg-black/15 p-3">
          <span className={cn('mt-1.5 h-2 w-2 shrink-0 rounded-full', severityDot[s.severity] ?? 'bg-slate-400')} />
          <div>
            <p className="text-sm font-medium">{s.signal}</p>
            <p className="text-xs text-slate-400">{s.description}</p>
          </div>
        </li>
      ))}
    </ul>
  );
}
