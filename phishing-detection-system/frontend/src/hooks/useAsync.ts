import { useCallback, useEffect, useState } from 'react';
import { getApiErrorMessage } from '@/services/api';

interface UseAsyncState<T> {
  data: T | null;
  isLoading: boolean;
  error: string | null;
  refetch: () => void;
}

/**
 * Runs `fetcher` on mount and whenever `deps` change. Exposes a `refetch`
 * for manual retries — used throughout for "Try again" buttons when the
 * backend is unreachable or slow.
 */
export function useAsync<T>(fetcher: () => Promise<T>, deps: unknown[] = []): UseAsyncState<T> {
  const [data, setData] = useState<T | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [nonce, setNonce] = useState(0);

  const refetch = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    fetcher()
      .then((result) => {
        if (!cancelled) setData(result);
      })
      .catch((err) => {
        if (!cancelled) setError(getApiErrorMessage(err));
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps]);

  return { data, isLoading, error, refetch };
}
