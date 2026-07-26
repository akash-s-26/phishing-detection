import type { HistoryEntry, Verdict } from '@/types';
import { Badge } from '@/components/ui/Badge';
import { Input } from '@/components/ui/Input';
import { formatDate } from '@/utils/cn';

interface HistoryTableProps {
  entries: HistoryEntry[];
  search: string;
  onSearchChange: (v: string) => void;
  result: Verdict | '';
  onResultChange: (v: Verdict | '') => void;
  dateFrom: string;
  onDateFromChange: (v: string) => void;
  dateTo: string;
  onDateToChange: (v: string) => void;
}

const RESULT_OPTIONS: Array<{ label: string; value: Verdict | '' }> = [
  { label: 'All results', value: '' },
  { label: 'Safe', value: 'safe' },
  { label: 'Suspicious', value: 'suspicious' },
  { label: 'Phishing', value: 'phishing' },
];

export function HistoryTable({
  entries,
  search,
  onSearchChange,
  result,
  onResultChange,
  dateFrom,
  onDateFromChange,
  dateTo,
  onDateToChange,
}: HistoryTableProps) {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-3 sm:grid-cols-4">
        <Input
          placeholder="Search by URL..."
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          className="sm:col-span-2"
        />
        <select
          value={result}
          onChange={(e) => onResultChange(e.target.value as Verdict | '')}
          className="rounded-[8px_12px_10px_14px] border border-slate-500/30 bg-black/20 px-3 py-2.5 text-sm text-current outline-none focus:border-brand"
        >
          {RESULT_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value} className="bg-ink text-current">
              {opt.label}
            </option>
          ))}
        </select>
        <div className="flex gap-2">
          <Input type="date" value={dateFrom} onChange={(e) => onDateFromChange(e.target.value)} />
          <Input type="date" value={dateTo} onChange={(e) => onDateToChange(e.target.value)} />
        </div>
      </div>

      <div className="sketch-panel overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-500/20 text-xs uppercase tracking-wide text-slate-500">
                <th className="px-4 py-3">URL</th>
                <th className="px-4 py-3">Result</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Scanned</th>
              </tr>
            </thead>
            <tbody>
              {entries.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-slate-500">
                    No scans match these filters yet.
                  </td>
                </tr>
              )}
              {entries.map((entry) => (
                <tr key={entry.id} className="border-b border-slate-500/10 last:border-0">
                  <td className="max-w-[280px] truncate px-4 py-3 font-mono text-xs" title={entry.url}>
                    {entry.url}
                  </td>
                  <td className="px-4 py-3">
                    <Badge verdict={entry.prediction}>{entry.prediction}</Badge>
                  </td>
                  <td className="px-4 py-3 font-mono">{entry.risk_score}%</td>
                  <td className="px-4 py-3 font-mono">{entry.confidence}%</td>
                  <td className="px-4 py-3 text-slate-400">{formatDate(entry.scanned_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
