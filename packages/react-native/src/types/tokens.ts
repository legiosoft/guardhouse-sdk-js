import type {
  OidcIdentityMetadata,
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
  /** Serializable metadata copied from Core-verified OIDC evidence. */
  identity?: OidcIdentityMetadata;
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
