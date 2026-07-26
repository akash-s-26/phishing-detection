import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { StatCard } from '@/components/StatCard';
import { ErrorState } from '@/components/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';
import { ThreatTrendChart } from '@/components/charts/ThreatTrendChart';
import { WeeklyScansChart } from '@/components/charts/WeeklyScansChart';
import { DistributionChart } from '@/components/charts/DistributionChart';
import { useAsync } from '@/hooks/useAsync';
import { fetchAnalytics } from '@/services/scanService';
import { Target, ScanLine, TrendingUp } from 'lucide-react';

export default function Analytics() {
  const analytics = useAsync(fetchAnalytics);

  if (analytics.isLoading) {
    return (
      <div className="mx-auto max-w-6xl px-6 py-10">
        <h1 className="mb-6 font-hand text-4xl underline-scribble">Analytics</h1>
        <div className="grid gap-4 sm:grid-cols-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <Skeleton key={i} className="h-24" />
          ))}
        </div>
        <Skeleton className="mt-6 h-72" />
      </div>
    );
  }

  if (analytics.error) {
    return (
      <div className="mx-auto max-w-6xl px-6 py-10">
        <h1 className="mb-6 font-hand text-4xl underline-scribble">Analytics</h1>
        <ErrorState message={analytics.error} onRetry={analytics.refetch} />
      </div>
    );
  }

  const data = analytics.data!;
  const ratioLabel = data.safe_vs_phishing_ratio !== null ? `${data.safe_vs_phishing_ratio}:1` : '—';

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <h1 className="mb-6 font-hand text-4xl underline-scribble">Analytics</h1>

      <div className="grid gap-4 sm:grid-cols-3">
        <StatCard
          label="Detection accuracy"
          value={data.detection_accuracy !== null ? `${Math.round(data.detection_accuracy * 100)}%` : '—'}
          icon={<Target className="h-5 w-5" />}
          tone="safe"
        />
        <StatCard label="Total scans" value={data.total_scans} icon={<ScanLine className="h-5 w-5" />} tone="brand" delay={0.05} />
        <StatCard label="Safe : phishing ratio" value={ratioLabel} icon={<TrendingUp className="h-5 w-5" />} tone="warn" delay={0.1} />
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-[1.4fr_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Daily scan trend</CardTitle>
          </CardHeader>
          {data.daily_scans.length === 0 ? (
            <p className="py-10 text-center text-sm text-slate-500">No scans yet — trends appear once you start scanning.</p>
          ) : (
            <ThreatTrendChart data={data.daily_scans} />
          )}
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Threat distribution</CardTitle>
          </CardHeader>
          <DistributionChart {...data.threat_distribution} />
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>Weekly scans</CardTitle>
        </CardHeader>
        {data.weekly_scans.length === 0 ? (
          <p className="py-10 text-center text-sm text-slate-500">Not enough history yet for a weekly view.</p>
        ) : (
          <WeeklyScansChart data={data.weekly_scans} />
        )}
      </Card>
    </div>
  );
}
