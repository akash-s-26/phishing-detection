import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';
import type { DailyScanPoint } from '@/types';

export function ThreatTrendChart({ data }: { data: DailyScanPoint[] }) {
  return (
    <ResponsiveContainer width="100%" height={280}>
      <AreaChart data={data} margin={{ top: 8, right: 12, left: -16, bottom: 0 }}>
        <defs>
          <linearGradient id="safeFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#3ecf8e" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#3ecf8e" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="suspiciousFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#f5a623" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#f5a623" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="phishingFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#ff5470" stopOpacity={0.4} />
            <stop offset="100%" stopColor="#ff5470" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.15)" />
        <XAxis dataKey="date" tick={{ fontSize: 11, fill: '#94a3b8' }} />
        <YAxis tick={{ fontSize: 11, fill: '#94a3b8' }} allowDecimals={false} />
        <Tooltip
          contentStyle={{ background: '#121821', border: '1px solid rgba(148,163,184,0.25)', borderRadius: 10, fontSize: 12 }}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
        <Area type="monotone" dataKey="safe" stroke="#3ecf8e" fill="url(#safeFill)" strokeWidth={2} />
        <Area type="monotone" dataKey="suspicious" stroke="#f5a623" fill="url(#suspiciousFill)" strokeWidth={2} />
        <Area type="monotone" dataKey="phishing" stroke="#ff5470" fill="url(#phishingFill)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  );
}
