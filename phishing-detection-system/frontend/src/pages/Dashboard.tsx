import { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, ShieldX, Activity, LayoutDashboard, Clock, Download, HardDrive, RefreshCw, Radio } from 'lucide-react';
import { Card, CardHeader, CardTitle } from '@/components/ui/Card';
import { StatCard } from '@/components/StatCard';
import { ErrorState } from '@/components/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';
import { Badge } from '@/components/ui/Badge';
import { DistributionChart } from '@/components/charts/DistributionChart';
import { fetchStatistics, fetchHistory } from '@/services/scanService';
import { useExtensionStatus } from '@/hooks/useExtensionStatus';
import { formatDate, cn } from '@/utils/cn';

export default function Dashboard() {
  const [statsData, setStatsData] = useState<any>(null);
  const [historyData, setHistoryData] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [showDownloadGuide, setShowDownloadGuide] = useState<boolean>(false);

  const { isConnected, version, lastChecked } = useExtensionStatus();

  async function loadData(showLoader = false) {
    if (showLoader) setIsLoading(true);
    setIsRefreshing(true);
    try {
      const [sData, hData] = await Promise.all([
        fetchStatistics(),
        fetchHistory({ limit: 10 })
      ]);
      setStatsData(sData);
      setHistoryData(hData || []);
      setError(null);
    } catch (err: any) {
      setError(err?.message || 'Failed to sync dashboard metrics');
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }

  useEffect(() => {
    loadData(true);
    const interval = setInterval(() => {
      loadData(false);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const downloadUrl = 'http://localhost:5000/download-extension';

  return (
    <div className="mx-auto max-w-7xl px-6 py-10 space-y-8">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold tracking-tight text-white flex items-center gap-2">
            <LayoutDashboard className="h-6 w-6 text-cyan-400" /> PhishGuard Security Dashboard
          </h1>
          <p className="text-xs text-slate-400 mt-1">Real-time deep learning threat monitoring & extension live synchronization</p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => loadData(false)}
            disabled={isRefreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-semibold bg-slate-900 border border-white/10 text-slate-300 hover:text-white hover:bg-slate-800 transition"
          >
            <RefreshCw className={cn("h-3.5 w-3.5", isRefreshing && "animate-spin text-cyan-400")} />
            Sync Now
          </button>

          <a
            href={downloadUrl}
            download="phishguard-ai-extension.zip"
            className="flex items-center gap-2 px-4 py-1.5 rounded-full text-xs font-bold bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/20 transition shadow-[0_0_15px_rgba(56,189,248,0.15)]"
          >
            <Download className="h-3.5 w-3.5" />
            Download Extension
          </a>
        </div>
      </div>

      {/* Extension & System Status Banner */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Extension Connection Card */}
        <div className={cn(
          "p-4 rounded-2xl border transition-all flex items-center justify-between",
          isConnected
            ? "bg-emerald-950/20 border-emerald-500/30 shadow-[0_0_20px_rgba(16,185,129,0.08)]"
            : "bg-amber-950/20 border-amber-500/30 shadow-[0_0_20px_rgba(245,158,11,0.08)]"
        )}>
          <div className="flex items-center gap-3">
            <div className={cn(
              "flex h-10 w-10 items-center justify-center rounded-xl border p-2",
              isConnected ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400" : "bg-amber-500/10 border-amber-500/30 text-amber-400"
            )}>
              <Radio className={cn("h-5 w-5", isConnected && "animate-pulse")} />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-bold text-white">Chrome Extension</span>
                <span className={cn(
                  "px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase tracking-wide",
                  isConnected ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                )}>
                  {isConnected ? '🟢 CONNECTED' : '🟡 STANDBY / NOT DETECTED'}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                {isConnected ? `Version v${version || '2.0.0'} • Active Content Protection` : 'Load unpacked extension in Chrome developer mode'}
              </p>
            </div>
          </div>

          <button
            onClick={() => setShowDownloadGuide(!showDownloadGuide)}
            className="text-xs font-semibold text-cyan-400 hover:underline shrink-0 ml-2"
          >
            {showDownloadGuide ? 'Hide Guide' : 'Setup Guide'}
          </button>
        </div>

        {/* Backend API Connection Card */}
        <div className="p-4 rounded-2xl border bg-slate-900/60 border-white/10 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 p-2">
            <HardDrive className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-white">PyTorch Backend API</span>
              <span className="px-2 py-0.5 rounded-full text-[10px] font-extrabold uppercase bg-cyan-500/20 text-cyan-400 border border-cyan-500/30">
                http://localhost:5000
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">100% Pure Deep Learning • RNN & 1D-CNN Models Loaded</p>
          </div>
        </div>

        {/* Live Sync Indicator Card */}
        <div className="p-4 rounded-2xl border bg-slate-900/60 border-white/10 flex items-center justify-between">
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Live Synchronization</span>
            <div className="text-sm font-bold text-white mt-1 flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping"></span>
              Auto-Sync Active (Every 3s)
            </div>
            <p className="text-[11px] text-slate-500 mt-0.5">
              Last Synced: {lastChecked ? new Date(lastChecked).toLocaleTimeString() : 'Just now'}
            </p>
          </div>
        </div>
      </div>

      {/* Extension Setup Guide (Collapsible) */}
      {showDownloadGuide && (
        <div className="p-6 rounded-2xl border border-cyan-500/30 bg-slate-950/80 backdrop-blur-md space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-white flex items-center gap-2">
              <Download className="h-5 w-5 text-cyan-400" /> How to Install PhishGuard AI Chrome Extension
            </h3>
            <span className="text-xs text-cyan-400 font-mono bg-cyan-500/10 px-2.5 py-1 rounded-full border border-cyan-500/20">
              Developer Mode (Unpacked)
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-xs">
            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-white/5 space-y-1.5">
              <div className="font-bold text-cyan-400">Step 1: Download Package</div>
              <p className="text-slate-300">Click the Download button to save <code className="text-cyan-300 bg-black/40 px-1 py-0.5 rounded">phishguard-ai-extension.zip</code> to your computer and unzip it.</p>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-white/5 space-y-1.5">
              <div className="font-bold text-cyan-400">Step 2: Open Extensions</div>
              <p className="text-slate-300">Open Chrome and navigate to <code className="text-cyan-300 bg-black/40 px-1 py-0.5 rounded">chrome://extensions/</code> in the address bar.</p>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-white/5 space-y-1.5">
              <div className="font-bold text-cyan-400">Step 3: Enable Developer Mode</div>
              <p className="text-slate-300">Toggle the <strong>"Developer mode"</strong> switch in the top-right corner of the Extensions page.</p>
            </div>
            <div className="p-3.5 rounded-xl bg-slate-900/80 border border-white/5 space-y-1.5">
              <div className="font-bold text-cyan-400">Step 4: Load Unpacked</div>
              <p className="text-slate-300">Click <strong>"Load unpacked"</strong> and select the unzipped <code className="text-cyan-300 bg-black/40 px-1 py-0.5 rounded">chrome-extension</code> folder!</p>
            </div>
          </div>
        </div>
      )}

      {/* Stat Cards */}
      {isLoading && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-24 rounded-xl" />
          ))}
        </div>
      )}

      {!isLoading && error && <ErrorState message={error} onRetry={() => loadData(true)} />}

      {!isLoading && statsData && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total Scans" value={statsData.total} icon={<Activity className="h-5 w-5 text-cyan-400" />} tone="brand" />
          <StatCard label="Safe Sites" value={statsData.safe} icon={<ShieldCheck className="h-5 w-5 text-emerald-400" />} tone="safe" delay={0.05} />
          <StatCard
            label="Suspicious"
            value={statsData.suspicious}
            icon={<ShieldAlert className="h-5 w-5 text-amber-400" />}
            tone="warn"
            delay={0.1}
          />
          <StatCard label="Phishing Threats" value={statsData.phishing} icon={<ShieldX className="h-5 w-5 text-rose-400" />} tone="danger" delay={0.15} />
        </div>
      )}

      {/* Main Charts & History Section */}
      <div className="grid gap-6 lg:grid-cols-[1fr_1.3fr]">
        <Card className="border-white/10 bg-[#111827]">
          <CardHeader>
            <CardTitle className="text-sm font-bold text-white">Threat Distribution Breakdown</CardTitle>
          </CardHeader>
          {isLoading && <Skeleton className="h-[240px]" />}
          {!isLoading && statsData && (
            <DistributionChart safe={statsData.safe} suspicious={statsData.suspicious} phishing={statsData.phishing} />
          )}
        </Card>

        <Card className="border-white/10 bg-[#111827]">
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-sm font-bold text-white flex items-center gap-2">
              <Clock className="h-4 w-4 text-cyan-400" /> Recent Security Scans (Extension & Web)
            </CardTitle>
            <span className="text-[11px] text-slate-500 font-mono">Live Polling</span>
          </CardHeader>

          {isLoading && (
            <div className="flex flex-col gap-2 p-4">
              {Array.from({ length: 5 }).map((_, i) => (
                <Skeleton key={i} className="h-10 rounded-xl" />
              ))}
            </div>
          )}

          {!isLoading && (
            <div className="p-4 pt-0">
              <ul className="flex flex-col divide-y divide-white/5">
                {historyData.length === 0 && (
                  <li className="py-8 text-center text-xs text-slate-500 font-mono">
                    No scans logged yet. Perform a scan or browse with the Chrome Extension.
                  </li>
                )}
                {historyData.map((entry) => (
                  <li key={entry.id || entry.scanned_at} className="flex items-center justify-between gap-3 py-3">
                    <div className="flex flex-col min-w-0">
                      <span className="truncate font-mono text-xs text-slate-200 max-w-[280px]" title={entry.url}>
                        {entry.url}
                      </span>
                      <span className="text-[10px] text-slate-500 flex items-center gap-1.5 mt-0.5">
                        <span className="bg-slate-800 text-slate-300 px-1.5 py-0.2 rounded">{entry.source || 'Chrome Extension'}</span>
                        <span>•</span>
                        <span>{entry.reason || `Risk: ${entry.risk_score}%`}</span>
                      </span>
                    </div>

                    <div className="flex shrink-0 items-center gap-3">
                      <Badge verdict={entry.prediction}>{entry.prediction}</Badge>
                      <span className="text-[11px] font-mono text-slate-500">{formatDate(entry.scanned_at)}</span>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
