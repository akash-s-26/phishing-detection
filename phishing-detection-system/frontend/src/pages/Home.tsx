import { useState, useRef } from 'react';
import { motion } from 'framer-motion';
import { Sparkles, Sliders, RotateCcw, ShieldCheck, AlertTriangle, AlertOctagon } from 'lucide-react';
import { toast } from 'sonner';
import { ScanForm } from '@/components/ScanForm';
import { ResultCard } from '@/components/ResultCard';
import { ErrorState } from '@/components/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';
import { scanUrl } from '@/services/scanService';
import { getApiErrorMessage } from '@/services/api';
import { DEMO_FIXTURES, getDemoFixture } from '@/data/demoFixtures';
import type { ScanResult } from '@/types';

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUrl, setLastUrl] = useState('');
  const [selectedDemoLevel, setSelectedDemoLevel] = useState<(1 | 2 | 3) | null>(null);
  const activeUrlRef = useRef<string>('');

  function handleSelectDemo(level: 1 | 2 | 3) {
    const fixture = getDemoFixture(level);
    activeUrlRef.current = fixture.url;
    setSelectedDemoLevel(level);
    setIsLoading(false);
    setError(null);
    setLastUrl(fixture.url);
    setResult(fixture);

    if (level === 1) {
      toast.success('Demonstrating Level 1: Low Risk (Safe) — Simulated Result');
    } else if (level === 2) {
      toast.warning('Demonstrating Level 2: Medium Risk (Suspicious) — Simulated Result');
    } else {
      toast.error('Demonstrating Level 3: High Risk (Dangerous Phishing) — Simulated Result');
    }
  }

  function handleResetDemo() {
    setSelectedDemoLevel(null);
    setResult(null);
    setError(null);
    setLastUrl('');
    toast.info('Demo cleared — Scanner ready for live URL analysis');
  }

  async function handleScan(url: string) {
    const trimmed = url.trim();
    if (!trimmed) return;

    activeUrlRef.current = trimmed;
    setSelectedDemoLevel(null);
    setIsLoading(true);
    setError(null);
    setResult(null); // Clear previous result immediately
    setLastUrl(trimmed);

    try {
      const data = await scanUrl(trimmed);
      // Prevent stale asynchronous responses from overwriting newer scans
      if (activeUrlRef.current !== trimmed) {
        return;
      }
      setResult(data);
      const pred = (data.prediction || 'safe').toLowerCase();
      if (pred === 'phishing') toast.error('Phishing Threat Detected!');
      else if (pred === 'suspicious' || pred === 'medium') toast.warning('Suspicious URL Indicators Detected');
      else toast.success('URL Analyzed Clean — Site is Safe');
    } catch (err) {
      if (activeUrlRef.current === trimmed) {
        setError(getApiErrorMessage(err));
        setResult(null);
      }
    } finally {
      if (activeUrlRef.current === trimmed) {
        setIsLoading(false);
      }
    }
  }

  return (
    <div className="mx-auto max-w-5xl px-6 py-12 space-y-8">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="flex flex-col items-center gap-4 text-center"
      >
        <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/30 bg-cyan-500/10 px-4 py-1.5 text-xs font-semibold text-cyan-400">
          <Sparkles className="h-3.5 w-3.5" /> PyTorch Deep Learning Security Engine
        </div>

        <h1 className="text-4xl font-extrabold tracking-tight text-white sm:text-5xl">
          Instant <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">Phishing & Risk</span> Analysis
        </h1>

        <p className="max-w-xl text-sm leading-relaxed text-slate-400">
          Paste any website link to run real-time PyTorch Deep Learning classification across BiLSTM RNN, 1D CNN, and GAN Data Augmentation models.
        </p>
      </motion.div>

      {/* ── PRESENTATION DEMO MODE SELECTOR ── */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="rounded-2xl border border-cyan-500/30 bg-slate-900/90 p-4 shadow-xl backdrop-blur-md"
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-white/5">
          <div className="flex items-center gap-2">
            <Sliders className="h-4 w-4 text-cyan-400" />
            <span className="text-xs font-bold tracking-wide text-white uppercase font-mono">
              Presentation Demo Mode
            </span>
            <span className="rounded-full bg-cyan-500/20 px-2 py-0.5 text-[10px] font-mono font-bold text-cyan-300 border border-cyan-500/30">
              {selectedDemoLevel ? `ACTIVE: LEVEL ${selectedDemoLevel}` : 'ACADEMIC DEMO'}
            </span>
          </div>

          <div className="flex items-center gap-2">
            {selectedDemoLevel && (
              <button
                type="button"
                onClick={handleResetDemo}
                className="flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs text-slate-300 hover:text-white hover:bg-slate-700 transition"
                title="Clear demo and reset scanner"
              >
                <RotateCcw className="h-3 w-3" /> Reset
              </button>
            )}
            <span className="text-[11px] text-slate-400 hidden md:inline">
              Simulate detection levels safely without navigating to live malicious sites
            </span>
          </div>
        </div>

        {/* Level Selector Buttons */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-3">
          <button
            type="button"
            onClick={() => handleSelectDemo(1)}
            className={`flex items-center justify-between gap-2 rounded-xl border px-3.5 py-2.5 text-left transition-all ${
              selectedDemoLevel === 1
                ? 'border-emerald-500 bg-emerald-950/50 shadow-[0_0_15px_rgba(16,185,129,0.25)]'
                : 'border-white/10 bg-slate-950/40 hover:border-emerald-500/50 hover:bg-slate-900/60'
            }`}
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <ShieldCheck className={`h-4 w-4 shrink-0 ${selectedDemoLevel === 1 ? 'text-emerald-400' : 'text-slate-400'}`} />
              <div className="truncate">
                <div className="text-xs font-bold text-white">Level 1: Safe</div>
                <div className="text-[10px] text-emerald-400 font-mono truncate">Risk: 4.2% • Clean Status</div>
              </div>
            </div>
            <span className="rounded bg-emerald-500/20 px-1.5 py-0.5 text-[9px] font-mono font-bold text-emerald-300 border border-emerald-500/30 shrink-0">
              DEMO L1
            </span>
          </button>

          <button
            type="button"
            onClick={() => handleSelectDemo(2)}
            className={`flex items-center justify-between gap-2 rounded-xl border px-3.5 py-2.5 text-left transition-all ${
              selectedDemoLevel === 2
                ? 'border-amber-500 bg-amber-950/50 shadow-[0_0_15px_rgba(245,158,11,0.25)]'
                : 'border-white/10 bg-slate-950/40 hover:border-amber-500/50 hover:bg-slate-900/60'
            }`}
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <AlertTriangle className={`h-4 w-4 shrink-0 ${selectedDemoLevel === 2 ? 'text-amber-400' : 'text-slate-400'}`} />
              <div className="truncate">
                <div className="text-xs font-bold text-white">Level 2: Suspicious</div>
                <div className="text-[10px] text-amber-400 font-mono truncate">Risk: 48.5% • Caution Advised</div>
              </div>
            </div>
            <span className="rounded bg-amber-500/20 px-1.5 py-0.5 text-[9px] font-mono font-bold text-amber-300 border border-amber-500/30 shrink-0">
              DEMO L2
            </span>
          </button>

          <button
            type="button"
            onClick={() => handleSelectDemo(3)}
            className={`flex items-center justify-between gap-2 rounded-xl border px-3.5 py-2.5 text-left transition-all ${
              selectedDemoLevel === 3
                ? 'border-rose-500 bg-rose-950/50 shadow-[0_0_15px_rgba(239,68,68,0.25)]'
                : 'border-white/10 bg-slate-950/40 hover:border-rose-500/50 hover:bg-slate-900/60'
            }`}
          >
            <div className="flex items-center gap-2.5 min-w-0">
              <AlertOctagon className={`h-4 w-4 shrink-0 ${selectedDemoLevel === 3 ? 'text-rose-400' : 'text-slate-400'}`} />
              <div className="truncate">
                <div className="text-xs font-bold text-white">Level 3: Dangerous</div>
                <div className="text-[10px] text-rose-400 font-mono truncate">Risk: 92.4% • Critical Threat</div>
              </div>
            </div>
            <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[9px] font-mono font-bold text-rose-300 border border-rose-500/30 shrink-0">
              DEMO L3
            </span>
          </button>
        </div>
      </motion.div>

      <div className="card-panel p-4 sm:p-6 bg-[#111827] border-white/10 shadow-2xl">
        <ScanForm
          onScan={handleScan}
          isLoading={isLoading}
          initialUrl={selectedDemoLevel ? DEMO_FIXTURES[selectedDemoLevel].url : undefined}
        />
      </div>

      <div className="pt-4">
        {isLoading && (
          <div className="grid gap-6 lg:grid-cols-[280px_1fr]">
            <Skeleton className="h-[280px] w-full rounded-2xl" />
            <div className="flex flex-col gap-4">
              <Skeleton className="h-24 w-full rounded-2xl" />
              <Skeleton className="h-28 w-full rounded-2xl" />
              <Skeleton className="h-36 w-full rounded-2xl" />
            </div>
          </div>
        )}
        {!isLoading && error && <ErrorState message={error} onRetry={() => handleScan(lastUrl)} />}
        {!isLoading && !error && result && <ResultCard result={result} />}
      </div>
    </div>
  );
}
