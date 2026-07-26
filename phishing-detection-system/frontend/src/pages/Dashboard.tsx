import { ShieldCheck, ShieldAlert, ShieldX, Activity } from 'lucide-react';
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
    <div className="mx-auto max-w-6xl px-6 py-10">
      <h1 className="mb-6 font-hand text-4xl underline-scribble">Dashboard</h1>

      {stats.isLoading && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
      )}
      {!stats.isLoading && stats.error && <ErrorState message={stats.error} onRetry={stats.refetch} />}
      {!stats.isLoading && stats.data && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total scans" value={stats.data.total} icon={<Activity className="h-5 w-5" />} tone="brand" />
          <StatCard label="Safe" value={stats.data.safe} icon={<ShieldCheck className="h-5 w-5" />} tone="safe" delay={0.05} />
          <StatCard
            label="Suspicious"
            value={stats.data.suspicious}
            icon={<ShieldAlert className="h-5 w-5" />}
            tone="warn"
            delay={0.1}
          />
          <StatCard label="Phishing" value={stats.data.phishing} icon={<ShieldX className="h-5 w-5" />} tone="danger" delay={0.15} />
        </div>
      )}

      <div className="mt-8 grid gap-6 lg:grid-cols-[1fr_1.2fr]">
        <Card>
          <CardHeader>
            <CardTitle>Threat distribution</CardTitle>
          </CardHeader>
          {stats.isLoading && <Skeleton className="h-[240px]" />}
          {!stats.isLoading && stats.data && (
            <DistributionChart safe={stats.data.safe} suspicious={stats.data.suspicious} phishing={stats.data.phishing} />
          )}
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent scans</CardTitle>
          </CardHeader>
          {recent.isLoading && (
            <div className="flex flex-col gap-2">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10" />
              ))}
            </div>
          )}
          {!recent.isLoading && recent.error && <ErrorState message={recent.error} onRetry={recent.refetch} />}
          {!recent.isLoading && recent.data && (
            <ul className="flex flex-col divide-y divide-slate-500/10">
              {recent.data.length === 0 && (
                <li className="py-6 text-center text-sm text-slate-500">No scans yet — run one from the Scan page.</li>
              )}
              {recent.data.map((entry) => (
                <li key={entry.id} className="flex items-center justify-between gap-3 py-2.5">
                  <span className="truncate font-mono text-xs text-slate-300" title={entry.url}>
                    {entry.url}
                  </span>
                  <div className="flex shrink-0 items-center gap-2">
                    <Badge verdict={entry.prediction}>{entry.prediction}</Badge>
                    <span className="text-xs text-slate-500">{formatDate(entry.scanned_at)}</span>
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
