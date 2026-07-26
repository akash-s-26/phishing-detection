import type { HTMLAttributes } from 'react';
import { cn } from '@/utils/cn';
import { verdictColor } from '@/utils/cn';

interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  verdict?: string;
}

export function Badge({ className, verdict, children, ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wide font-mono',
        verdict ? verdictColor(verdict) : 'text-slate-300 border-slate-500/30 bg-slate-500/10',
        className
      )}
      {...props}
    >
      {children}
    </span>
  );
}
