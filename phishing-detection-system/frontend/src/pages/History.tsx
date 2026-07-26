import { useState } from 'react';
import { HistoryTable } from '@/components/HistoryTable';
import { ErrorState } from '@/components/ErrorState';
import { Skeleton } from '@/components/ui/Skeleton';
import { useAsync } from '@/hooks/useAsync';
import { fetchHistory } from '@/services/scanService';
import type { Verdict } from '@/types';

export default function History() {
  const [search, setSearch] = useState('');
  const [result, setResult] = useState<Verdict | ''>('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');

  const history = useAsync(
    () => fetchHistory({ search, result, date_from: dateFrom, date_to: dateTo, limit: 100 }),
    [search, result, dateFrom, dateTo]
  );

  return (
    <div className="mx-auto max-w-6xl px-6 py-10">
      <h1 className="mb-6 font-hand text-4xl underline-scribble">Scan history</h1>

      {history.isLoading && (
        <div className="flex flex-col gap-3">
          <Skeleton className="h-10" />
          <Skeleton className="h-64" />
        </div>
      )}
      {!history.isLoading && history.error && <ErrorState message={history.error} onRetry={history.refetch} />}
      {!history.isLoading && !history.error && (
        <HistoryTable
          entries={history.data ?? []}
          search={search}
          onSearchChange={setSearch}
          result={result}
          onResultChange={setResult}
          dateFrom={dateFrom}
          onDateFromChange={setDateFrom}
          dateTo={dateTo}
          onDateToChange={setDateTo}
        />
      )}
    </div>
  );
}
