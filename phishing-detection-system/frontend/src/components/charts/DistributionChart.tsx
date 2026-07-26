import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts';

interface DistributionChartProps {
  safe: number;
  suspicious: number;
  phishing: number;
}

export function DistributionChart({ safe, suspicious, phishing }: DistributionChartProps) {
  const data = [
    { name: 'Safe', value: safe, color: '#3ecf8e' },
    { name: 'Suspicious', value: suspicious, color: '#f5a623' },
    { name: 'Phishing', value: phishing, color: '#ff5470' },
  ];

  const hasData = safe + suspicious + phishing > 0;

  if (!hasData) {
    return (
      <div className="flex h-[240px] items-center justify-center text-sm text-slate-500">
        No scans yet — results will chart here once you run a few.
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" innerRadius={60} outerRadius={90} paddingAngle={3}>
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.color} stroke="none" />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{ background: '#121821', border: '1px solid rgba(148,163,184,0.25)', borderRadius: 10, fontSize: 12 }}
        />
        <Legend wrapperStyle={{ fontSize: 12 }} />
      </PieChart>
    </ResponsiveContainer>
  );
}
