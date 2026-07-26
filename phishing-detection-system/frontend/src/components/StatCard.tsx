import { motion } from 'framer-motion';
import type { ReactNode } from 'react';
import { Card } from '@/components/ui/Card';
import { cn } from '@/utils/cn';

interface StatCardProps {
  label: string;
  value: number | string;
  icon: ReactNode;
  tone?: 'safe' | 'warn' | 'danger' | 'brand';
  delay?: number;
}

const toneClass: Record<string, string> = {
  safe: 'text-safe',
  warn: 'text-warn',
  danger: 'text-danger',
  brand: 'text-brand-soft',
};

export function StatCard({ label, value, icon, tone = 'brand', delay = 0 }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay }}
    >
      <Card className="flex items-center gap-4">
        <div className={cn('rounded-full bg-black/20 p-3', toneClass[tone])}>{icon}</div>
        <div>
          <p className="font-mono text-2xl font-semibold">{value}</p>
          <p className="text-xs uppercase tracking-wide text-slate-400">{label}</p>
        </div>
      </Card>
    </motion.div>
  );
}
