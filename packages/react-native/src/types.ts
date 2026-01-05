import { User as CoreUser } from "@guardhouse/core";

export interface GuardhouseConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
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

export class RefreshTokenError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
  ) {
    super(message);
    this.name = "RefreshTokenError";
  }
}

export class BiometricAuthFailedError extends Error {
  constructor(
    message: string,
    public userCancelled?: boolean,
  ) {
    super(message);
    this.name = "BiometricAuthFailedError";
  }
}

export class SessionExpiredError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SessionExpiredError";
  }
}
