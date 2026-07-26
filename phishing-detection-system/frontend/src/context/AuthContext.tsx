import { createContext, useCallback, useEffect, useState, type ReactNode } from 'react';
import type { User } from '@/types';
import { tokenStore } from '@/services/api';
import * as authService from '@/services/authService';

interface AuthContextValue {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (name: string, email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

// eslint-disable-next-line react-refresh/only-export-components
export const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const clearSession = useCallback(() => {
    tokenStore.clear();
    setUser(null);
  }, []);

  useEffect(() => {
    async function bootstrap() {
      if (!tokenStore.getAccess()) {
        setIsLoading(false);
        return;
      }
      try {
        const profile = await authService.fetchProfile();
        setUser(profile);
      } catch {
        clearSession();
      } finally {
        setIsLoading(false);
      }
    }
    bootstrap();

    const onForcedLogout = () => clearSession();
    window.addEventListener('phishshield:logout', onForcedLogout);
    return () => window.removeEventListener('phishshield:logout', onForcedLogout);
  }, [clearSession]);

  const login = useCallback(async (email: string, password: string) => {
    const res = await authService.login(email, password);
    setUser(res.user);
  }, []);

  const signup = useCallback(async (name: string, email: string, password: string) => {
    const res = await authService.signup(name, email, password);
    setUser(res.user);
  }, []);

  const logout = useCallback(async () => {
    await authService.logout().catch(() => undefined);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider
      value={{ user, isAuthenticated: !!user, isLoading, login, signup, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}
