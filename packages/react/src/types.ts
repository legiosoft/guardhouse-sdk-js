import type { DPoPProofFactory, User as CoreUser } from "@guardhouse/core";

export interface GuardhouseConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  authorizationEndpoint?: string;
  tokenEndpoint?: string;
  userInfoEndpoint?: string;
  introspectionEndpoint?: string;
  revocationEndpoint?: string;
  audience?: string;
  allowAuthorizationWithoutAudience?: boolean;
  requestUri?: string;
  debug?: boolean;
  onRedirectCallback?: (appState?: AppState) => void;
  scope?: string;
  responseType?: string;
  allowOfflineAccessScope?: boolean;
  requestTimeoutMs?: number;
  discoveryCacheTtlMs?: number;
  allowScopeNarrowing?: boolean;
  maxAuthorizationHeaderBytes?: number;
  maxSilentAuthAttempts?: number;
  requireUserInteractionForSensitiveOperations?: boolean;
  allowedPostLogoutRedirectUris?: string[];
  allowUnsafeHttpMethods?: boolean;
  requireDpopForAccessTokenRequests?: boolean;
  dpopProofFactory?: DPoPProofFactory;
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

export interface OidcSessionData {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  refreshToken?: string;
  idToken?: string;
  scope?: string;
  user: CoreUser;
  oidc: {
    issuer: string;
    audience?: string;
    sessionState?: string;
  };
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
