import { User as CoreUser } from "@guardhouse/core";

export interface GuardhouseConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  debug?: boolean;
  onRedirectCallback?: (appState?: AppState) => void;
  storage?: StorageAdapter;
  scope?: string;
  responseType?: string;
  logoutRedirectUri?: string;
}

export interface AppState {
  returnTo?: string;
  [key: string]: any;
}

export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  user: CoreUser | null;
}

export interface TokenData {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  expires_in: number;
  token_type: string;
  scope?: string;
}

export interface LoginOptions {
  appState?: AppState;
  prompt?: string;
  scope?: string;
  audience?: string;
}

export interface LogoutOptions {
  returnTo?: string;
  federated?: boolean;
}

export interface StorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

export interface ProtectedRouteProps {
  component?: React.ComponentType<any>;
  children?: React.ReactNode;
  onRedirecting?: () => React.ReactNode;
  [key: string]: any;
}

export interface WithAuthenticationRequiredOptions {
  returnTo?: string;
  onRedirecting?: () => React.ReactNode;
}
