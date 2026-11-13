import type { HistoryEntry, Verdict } from '@/types';
import { Badge } from '@/components/ui/Badge';
import { Input } from '@/components/ui/Input';
import { formatDate } from '@/utils/cn';
import { resolveDetectionLevel } from '@/utils/securityLevels';

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
  { label: 'All Detection Levels', value: '' },
  { label: 'Level 1 – Safe (Low Risk)', value: 'safe' },
  { label: 'Level 2 – Suspicious (Medium Risk)', value: 'suspicious' },
  { label: 'Level 3 – Dangerous (High Risk)', value: 'phishing' },
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
          placeholder="Search by URL or domain..."
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
                <th className="px-4 py-3">Scanned URL</th>
                <th className="px-4 py-3">Detection Level</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Threat Score</th>
                <th className="px-4 py-3">Confidence</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3">Scanned</th>
              </tr>
            </thead>
            <tbody>
              {entries.length === 0 && (
                <tr>
                  <td colSpan={7} className="px-4 py-8 text-center text-slate-500">
                    No scans match these filters yet.
                  </td>
                </tr>
              )}
              {entries.map((entry) => {
                const lvl = resolveDetectionLevel(
                  entry.risk_score,
                  entry.prediction,
                  entry.threat_level,
                  entry.detection_level
                );
                const levelBadgeClass =
                  lvl.level === 1
                    ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                    : lvl.level === 2
                    ? 'bg-amber-500/15 border-amber-500/30 text-amber-300'
                    : 'bg-rose-500/20 border-rose-500/40 text-rose-300';

                return (
                  <tr key={entry.id} className="border-b border-slate-500/10 last:border-0 hover:bg-white/[0.02] transition">
                    <td className="max-w-[280px] truncate px-4 py-3 font-mono text-xs" title={entry.url}>
                      {entry.url}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold border ${levelBadgeClass}`}
                      >
                        <span className="h-1.5 w-1.5 rounded-full bg-current" />
                        {lvl.levelName}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <Badge verdict={entry.prediction}>{entry.prediction}</Badge>
                    </td>
                    <td className="px-4 py-3 font-mono font-bold text-white">{entry.risk_score}%</td>
                    <td className="px-4 py-3 font-mono text-slate-300">{entry.confidence}%</td>
                    <td className="px-4 py-3">
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                        {entry.source || 'Web App'}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs">{formatDate(entry.scanned_at)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
