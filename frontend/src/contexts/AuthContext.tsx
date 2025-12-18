import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from 'react';
import type { User, LoginCredentials, RegisterCredentials } from '@/types';
import { mockApi } from '@/services/mockApi';
import { API_BASE_URL } from '@/services/api';

interface AuthContextType {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (credentials: LoginCredentials) => Promise<void>;
  register: (credentials: RegisterCredentials) => Promise<void>;
  loginWithToken: (token: string) => Promise<void>;
  logout: () => Promise<void>;
  updateUser: (data: Partial<User>) => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

const TOKEN_KEY = 'smartcodex_token';

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const restoreSession = useCallback(async () => {
    const token = localStorage.getItem(TOKEN_KEY);

    if (!token) {
      setIsLoading(false);
      return;
    }

    try {
      // Try real backend first
      const response = await fetch(`${API_BASE_URL}/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });

      if (response.ok) {
        const user = await response.json();
        setUser(user);
      } else {
        // Fallback to mock API (for legacy/dev users)
        const user = await mockApi.auth.me(token);
        setUser(user);
      }
    } catch {
      localStorage.removeItem(TOKEN_KEY);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    restoreSession();
  }, [restoreSession]);

  const login = async (credentials: LoginCredentials) => {
    const response = await mockApi.auth.login(credentials);
    localStorage.setItem(TOKEN_KEY, response.token);
    setUser(response.user);
  };

  const loginWithToken = async (token: string) => {
    localStorage.setItem(TOKEN_KEY, token);
    await restoreSession();
  };

  const register = async (credentials: RegisterCredentials) => {
    const response = await mockApi.auth.register(credentials);
    localStorage.setItem(TOKEN_KEY, response.token);
    setUser(response.user);
  };

  const logout = async () => {
    const token = localStorage.getItem(TOKEN_KEY);
    if (token) {
      try {
        await mockApi.auth.logout(token);
      } catch (e) {
        // Ignore errors during logout
      }
      localStorage.removeItem(TOKEN_KEY);
    }
    setUser(null);
  };

  const updateUser = (data: Partial<User>) => {
    if (user) {
      setUser({ ...user, ...data });
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isLoading,
        isAuthenticated: !!user,
        login,
        register,
        loginWithToken,
        logout,
        updateUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
