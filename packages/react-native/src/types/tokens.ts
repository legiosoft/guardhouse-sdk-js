import type {
  TokenResponse as CoreTokenResponse,
  User as CoreUser,
} from "@guardhouse/core";

/**
 * OAuth token response returned by Guardhouse token endpoints.
 */
export type GuardhouseTokenResponse = CoreTokenResponse;

/**
 * Normalized in-app session representation.
 */
export interface GuardhouseSession {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType: string;
  scope?: string;
  expiresAt: number;
  user: CoreUser | null;
}

/**
 * Unified result returned by authentication operations.
 */
export interface GuardhouseAuthResult {
  session: GuardhouseSession;
  tokenResponse: GuardhouseTokenResponse;
  user: CoreUser | null;
  appState?: Record<string, unknown>;
}

/**
 * Token payload shape accepted from a deep link redirect.
 */
export interface RedirectTokenPayload {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType?: string;
  expiresIn?: number;
  scope?: string;
}
