import { useState, type FormEvent } from 'react';
import { motion } from 'framer-motion';
import { Search } from 'lucide-react';
import { Input } from '@/components/ui/Input';
import { Button } from '@/components/ui/Button';

interface ScanFormProps {
  onScan: (url: string) => void;
  isLoading: boolean;
}

export function ScanForm({ onScan, isLoading }: ScanFormProps) {
  const [url, setUrl] = useState('');

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) return;
    onScan(trimmed);
  }

  return (
    <motion.form
      onSubmit={handleSubmit}
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="flex w-full flex-col gap-3 sm:flex-row"
    >
      <div className="relative flex-1">
        <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
        <Input
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Paste a URL to scan — e.g. https://example.com/login"
          className="pl-11"
          type="text"
          autoFocus
        />
      </div>
      <Button type="submit" isLoading={isLoading} className="sm:w-40">
        {isLoading ? 'Scanning' : 'Scan URL'}
      </Button>
    </motion.form>
  );
}
