import type { ComponentType, ReactNode } from "react";
import type {
  DPoPProofFactory,
  GuardhouseError,
  OidcIdentityMetadata,
  User as CoreUser,
} from "@guardhouse/core";

export type AudiencePolicy = "guardhouse-required" | "oidc-optional";

export interface GuardhouseConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  tokenEndpoint?: string;
  userInfoEndpoint?: string;
  introspectionEndpoint?: string;
  revocationEndpoint?: string;
  audience?: string;
  resource?: string | readonly string[];
  audiencePolicy?: AudiencePolicy;
  debug?: boolean;
  onRedirectCallback?: (appState?: AppState) => void | Promise<void>;
  scope?: string;
  maxAgeSeconds?: number;
  requiredAcrValues?: readonly string[];
  requiredAmrValues?: readonly string[];
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
  [key: string]: unknown;
}

export interface AuthState {
  isAuthenticated: boolean;
  isLoading: boolean;
  error: Error | GuardhouseError | null;
  user: CoreUser | null;
}

export interface TokenData {
  access_token: string;
  refresh_token?: string;
  /**
   * SECURITY WARNING:
   * Never trust id_token claims directly for local authentication decisions.
   * Always validate signature, issuer, audience, and expiration with a JWT/OIDC validation library first.
   */
  id_token?: string;
  expires_in: number;
  token_type: string;
  scope?: string;
}

export interface OidcSessionData {
  version: 3;
  clientId: string;
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  refreshToken?: string;
  idToken: string;
  scope: string;
  identity: OidcIdentityMetadata;
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
  resource?: string | readonly string[];
  maxAgeSeconds?: number;
}

export interface LogoutOptions {
  returnTo?: string;
  federated?: boolean;
}

export interface StorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  /**
   * Atomically replaces `key` only when its current serialized value is
   * exactly `expectedValue`. Adapters backed by synchronous browser storage
   * may return the boolean directly.
   */
  compareAndSetItem?(
    key: string,
    expectedValue: string,
    value: string,
  ): boolean | Promise<boolean>;
  /**
   * Atomically removes `key` only when its current serialized value is exactly
   * `expectedValue`. Adapters backed by synchronous browser storage may return
   * the boolean directly.
   */
  compareAndRemoveItem?(
    key: string,
    expectedValue: string,
  ): boolean | Promise<boolean>;
}

export interface RedirectErrorRenderContext {
  error: Error;
  retry: () => void;
}

interface ProtectedRouteCommonProps {
  returnTo?: string;
  onRedirecting?: () => ReactNode;
  onRedirectError?: (context: RedirectErrorRenderContext) => ReactNode;
}

export type ProtectedRouteProps<P extends object = Record<string, never>> =
  ProtectedRouteCommonProps &
    (
      | {
          component: ComponentType<P>;
          componentProps: P;
          children?: never;
        }
      | {
          component?: never;
          componentProps?: never;
          children: ReactNode;
        }
    );

export interface WithAuthenticationRequiredOptions {
  returnTo?: string;
  onRedirecting?: () => ReactNode;
  onRedirectError?: (context: RedirectErrorRenderContext) => ReactNode;
}

export interface AuthContextValue extends AuthState {
  loginWithRedirect: (options?: LoginOptions) => Promise<void>;
  logout: (options?: LogoutOptions) => Promise<void>;
  getAccessToken: () => Promise<string | null>;
  getAccessTokenSilently: () => Promise<string | null>;
}

export interface GuardhouseProviderProps {
  config: GuardhouseConfig;
  children: ReactNode;
}
