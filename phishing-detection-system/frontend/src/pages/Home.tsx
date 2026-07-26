import { useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldHalf } from 'lucide-react';
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
      if (data.prediction === 'phishing') toast.error('Phishing detected.');
      else if (data.prediction === 'suspicious') toast.warning('This URL looks suspicious.');
      else toast.success('This URL looks safe.');
    } catch (err) {
      setError(getApiErrorMessage(err));
      setResult(null);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="mx-auto max-w-4xl px-6 py-10">
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="mb-8 flex flex-col items-center gap-3 text-center"
      >
        <ShieldHalf className="h-10 w-10 text-brand-soft" />
        <h1 className="font-hand text-4xl underline-scribble">Scan a URL</h1>
        <p className="max-w-lg text-sm text-slate-400">
          Paste any link — PhishShield checks it against a trained ML model, live SSL and WHOIS
          data, and known blacklist patterns, then explains exactly why.
        </p>
      </motion.div>

      <ScanForm onScan={handleScan} isLoading={isLoading} />

      <div className="mt-8">
        {isLoading && (
          <div className="grid gap-6 lg:grid-cols-[auto_1fr]">
            <Skeleton className="h-[260px] w-[260px] shrink-0" />
            <div className="flex flex-col gap-4">
              <Skeleton className="h-20" />
              <Skeleton className="h-24" />
              <Skeleton className="h-32" />
            </div>
          </div>
        )}
        {!isLoading && error && <ErrorState message={error} onRetry={() => handleScan(lastUrl)} />}
        {!isLoading && !error && result && <ResultCard result={result} />}
      </div>
    </div>
  );
}
