import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return iso;
  }
}

export function verdictColor(verdict: string): string {
  switch (verdict) {
    case 'safe':
      return 'text-safe border-safe/40 bg-safe/10';
    case 'suspicious':
      return 'text-warn border-warn/40 bg-warn/10';
    case 'phishing':
      return 'text-danger border-danger/40 bg-danger/10';
    default:
      return 'text-slate-400 border-slate-500/40 bg-slate-500/10';
  }
}

export function verdictHex(verdict: string): string {
  switch (verdict) {
    case 'safe':
      return '#3ecf8e';
    case 'suspicious':
      return '#f5a623';
    case 'phishing':
      return '#ff5470';
    default:
      return '#94a3b8';
  }
}
