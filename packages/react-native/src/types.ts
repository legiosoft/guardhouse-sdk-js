/**
 * Type Definitions for Guardhouse React Native SDK
 *
 * SECURITY NOTES:
 *
 * 1. User type is parsed from ID token JWT
 *    - Strictly typed based on OpenID Connect standard claims
 *    - Includes sub, name, email, etc.
 *    - Can be extended with additional claims
 *
 * 2. Error types for different failure scenarios
 *    - SecurityError: Generic security-related errors
 *    - RefreshTokenError: Token refresh failures
 *    - BiometricAuthFailedError: Biometric auth failures
 *    - SessionExpiredError: Session expiration errors
 */

import type { CryptoAdapter, User as CoreUser } from "@guardhouse/core";

export interface GuardhouseConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  cryptoAdapter?: CryptoAdapter;
  debug?: boolean;
  onRedirectCallback?: (appState?: AppState) => void;
  scope?: string;
  responseType?: string;
  logoutRedirectUri?: string;
  requireBiometrics?: boolean;
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

export interface SecurityError extends Error {
  code: "STATE_MISMATCH" | "INVALID_JWT" | "TOKEN_EXPIRED" | "STORAGE_ERROR";
}

/**
 * Refresh Token Error
 *
 * Thrown when silent token refresh fails
 * Causes automatic logout and requires user to re-authenticate
 */
export class RefreshTokenError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
  ) {
    super(message);
    this.name = "RefreshTokenError";
  }
}

/**
 * Biometric Authentication Failed Error
 *
 * Thrown when biometric authentication fails
 * Can be user cancellation (userCancelled=true) or actual failure
 */
export class BiometricAuthFailedError extends Error {
  constructor(
    message: string,
    public userCancelled?: boolean,
  ) {
    super(message);
    this.name = "BiometricAuthFailedError";
  }
}

/**
 * Session Expired Error
 *
 * Thrown when session is expired and cannot be refreshed
 * Requires user to re-authenticate
 */
export class SessionExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SessionExpiredError";
  }
}

/**
 * Auth Context Value
 *
 * Full authentication context including state and actions
 */
export interface AuthContextValue extends AuthState {
  login: (options?: LoginOptions) => Promise<void>;
  logout: (options?: LogoutOptions) => Promise<void>;
  getAccessToken: () => Promise<string | null>;
  accessToken: string | null;
}

/**
 * Auth Context Type
 *
 * Internal type for context object
 */
export interface AuthContext extends Omit<
  AuthContextValue,
  "user" | "accessToken"
> {}
