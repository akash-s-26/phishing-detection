import { api, tokenStore } from './api';
import type { AuthResponse, User } from '@/types';

export async function signup(name: string, email: string, password: string): Promise<AuthResponse> {
  const { data } = await api.post<AuthResponse>('/auth/signup', { name, email, password });
  tokenStore.set(data.access_token, data.refresh_token);
  return data;
}

export async function login(email: string, password: string): Promise<AuthResponse> {
  const { data } = await api.post<AuthResponse>('/auth/login', { email, password });
  tokenStore.set(data.access_token, data.refresh_token);
  return data;
}

export async function logout(): Promise<void> {
  try {
    await api.post('/auth/logout');
  } finally {
    tokenStore.clear();
  }
}

export async function fetchProfile(): Promise<User> {
  const { data } = await api.get<User>('/auth/profile');
  return data;
}
