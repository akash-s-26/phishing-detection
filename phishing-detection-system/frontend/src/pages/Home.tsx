import { useState } from 'react';
import { motion } from 'framer-motion';
import { Sparkles } from 'lucide-react';
import { toast } from 'sonner';
import { ScanForm } from '@/components/ScanForm';
import { ResultCard } from '@/components/ResultCard';
import { ErrorState } from '@/components/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';
import { scanUrl } from '@/services/scanService';
import { getApiErrorMessage } from '@/services/api';
import type { ScanResult } from '@/types';

export default function Home() {
  const [result, setResult] = useState<ScanResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUrl, setLastUrl] = useState('');

  async function handleScan(url: string) {
    setIsLoading(true);
    setError(null);
    setLastUrl(url);
    try {
      const data = await scanUrl(url);
      setResult(data);
      const pred = (data.prediction || 'safe').toLowerCase();
      if (pred === 'phishing') toast.error('Phishing Threat Detected!');
      else if (pred === 'suspicious' || pred === 'medium') toast.warning('Suspicious URL Indicators Detected');
      else toast.success('URL Analyzed Clean — Site is Safe');
    } catch (err) {
      setError(getApiErrorMessage(err));
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-5xl px-6 py-12 space-y-10">
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

      <div className="card-panel p-4 sm:p-6 bg-[#111827] border-white/10 shadow-2xl">
        <ScanForm onScan={handleScan} isLoading={isLoading} />
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
