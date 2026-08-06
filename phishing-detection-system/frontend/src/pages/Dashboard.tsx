import { ShieldCheck, ShieldAlert, ShieldX, Activity, LayoutDashboard, Clock } from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { StatCard } from '@/components/StatCard';
import { ErrorState } from '@/components/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';
import { Badge } from '@/components/ui/Badge';
import { DistributionChart } from '@/components/charts/DistributionChart';
import { useAsync } from '@/hooks/useAsync';
import { fetchStatistics, fetchHistory } from '@/services/scanService';
import { formatDate } from '@/utils/cn';

export default function Dashboard() {
  const stats = useAsync(fetchStatistics);
  const recent = useAsync(() => fetchHistory({ limit: 8 }));

  return (
    <div className="mx-auto max-w-7xl px-6 py-10 space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <LayoutDashboard className="h-6 w-6 text-cyan-400" /> PhishGuard Security Dashboard
          </h1>
          <p className="text-xs text-slate-400 mt-1">Real-time threat monitoring and scan history metrics</p>
        </div>
      </div>

      {stats.isLoading && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
      )}
      {!stats.isLoading && stats.error && <ErrorState message={stats.error} onRetry={stats.refetch} />}
      {!stats.isLoading && stats.data && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total Scans" value={stats.data.total} icon={<Activity className="h-5 w-5 text-cyan-400" />} tone="brand" />
          <StatCard label="Safe Sites" value={stats.data.safe} icon={<ShieldCheck className="h-5 w-5 text-emerald-400" />} tone="safe" delay={0.05} />
          <StatCard
            label="Suspicious"
            value={stats.data.suspicious}
            icon={<ShieldAlert className="h-5 w-5 text-amber-400" />}
            tone="warn"
            delay={0.1}
          />
          <StatCard label="Phishing Threats" value={stats.data.phishing} icon={<ShieldX className="h-5 w-5 text-rose-400" />} tone="danger" delay={0.15} />
        </div>
      )}

      <div className="grid gap-6 lg:grid-cols-[1fr_1.3fr]">
        <Card className="border-white/10 bg-[#111827]">
          <CardHeader>
            <CardTitle className="text-sm font-bold text-white">Threat Distribution Breakdown</CardTitle>
          </CardHeader>
          {stats.isLoading && <Skeleton className="h-[240px]" />}
          {!stats.isLoading && stats.data && (
            <DistributionChart safe={stats.data.safe} suspicious={stats.data.suspicious} phishing={stats.data.phishing} />
          )}
        </Card>

        <Card className="border-white/10 bg-[#111827]">
          <CardHeader>
            <CardTitle className="text-sm font-bold text-white flex items-center gap-2">
              <Clock className="h-4 w-4 text-cyan-400" /> Recent Security Scans
            </CardTitle>
          </CardHeader>
          {recent.isLoading && (
            <div className="flex flex-col gap-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 rounded-xl" />
              ))}
            </div>
          )}
          {!recent.isLoading && recent.error && <ErrorState message={recent.error} onRetry={recent.refetch} />}
          {!recent.isLoading && recent.data && (
            <ul className="flex flex-col divide-y divide-white/5">
              {recent.data.length === 0 && (
                <li className="py-8 text-center text-xs text-slate-500 font-mono">No scans logged yet. Execute a URL scan from the Home tab.</li>
              )}
              {recent.data.map((entry) => (
                <li key={entry.id} className="flex items-center justify-between gap-3 py-3">
                  <span className="truncate font-mono text-xs text-slate-300 max-w-[280px]" title={entry.url}>
                    {entry.url}
                  </span>
                  <div className="flex shrink-0 items-center gap-3">
                    <Badge verdict={entry.prediction}>{entry.prediction}</Badge>
                    <span className="text-[11px] font-mono text-slate-500">{formatDate(entry.scanned_at)}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
