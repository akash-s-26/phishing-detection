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
  const v = (verdict || '').toLowerCase();
  switch (v) {
    case 'safe':
      return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    case 'suspicious':
    case 'medium':
      return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    case 'phishing':
    case 'high':
      return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
    default:
      return 'text-slate-400 border-slate-500/30 bg-slate-500/10';
  }
}

export function verdictHex(verdict: string): string {
  const v = (verdict || '').toLowerCase();
  switch (v) {
    case 'safe':
      return '#10b981';
    case 'suspicious':
    case 'medium':
      return '#f59e0b';
    case 'phishing':
    case 'high':
      return '#f43f5e';
    default:
      return '#94a3b8';
  }
}
