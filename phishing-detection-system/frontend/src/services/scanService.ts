import { api } from './api';
import type { AnalyticsData, HistoryEntry, ScanResult, Statistics, Verdict } from '@/types';

export async function scanUrl(url: string): Promise<ScanResult> {
  const { data } = await api.post<ScanResult>('/predict', { url });
  return data;
}

export interface HistoryFilters {
  result?: Verdict | '';
  search?: string;
  date_from?: string;
  date_to?: string;
  limit?: number;
}

export async function fetchHistory(filters: HistoryFilters = {}): Promise<HistoryEntry[]> {
  const params: Record<string, string | number> = {};
  if (filters.result) params.result = filters.result;
  if (filters.search) params.search = filters.search;
  if (filters.date_from) params.date_from = filters.date_from;
  if (filters.date_to) params.date_to = filters.date_to;
  params.limit = filters.limit ?? 50;

  const { data } = await api.get<HistoryEntry[]>('/history', { params });
  return data;
}

export async function fetchStatistics(): Promise<Statistics> {
  const { data } = await api.get<Statistics>('/statistics');
  return data;
}

export async function fetchAnalytics(): Promise<AnalyticsData> {
  const { data } = await api.get<AnalyticsData>('/analytics');
  return data;
}

export async function checkHealth(): Promise<{ status: string; model_loaded: boolean }> {
  const { data } = await api.get('/health');
  return data;
}

export async function reportFalsePositive(url: string): Promise<void> {
  await api.post('/report-false-positive', { url });
}
