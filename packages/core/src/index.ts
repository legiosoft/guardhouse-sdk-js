/**
 * Guardhouse Core Library
 * Universal JavaScript/TypeScript SDK for OAuth 2.0 with PKCE
 *
 * Security Architecture:
 * - Crypto adapter pattern (works everywhere)
 * - PKCE with S256 (RFC 7636 compliant)
 * - JWT claim validation
 * - HTTP Basic Auth for confidential clients
 * - HTTPS enforcement
 *
 * Usage:
 * ```ts
 * import { GuardhouseClient } from '@guardhouse/core';
 *
 * const client = new GuardhouseClient({
 *   authority: 'https://auth.example.com',
 *   clientId: 'my-app-id',
 *   // Optional for confidential clients
 *   clientSecret: 'my-app-secret',
 * });
 *
 * const { authorizationUrl, transaction } =
 *   await client.createAuthorizationRequest({
 *   redirectUri: 'https://app.example.com/callback',
 *   scope: 'openid profile',
 *   audience: 'https://api.example.com',
 * });
 *
 * // Persist transaction atomically by state, then redirect to authorizationUrl.
 * // On return, restore it, validate the callback, and exchange the code.
 * ```
 */

// Public API exports
export { GuardhouseClient } from "./client";
export { GuardhouseError } from "./config";
export type {
  GuardhouseConfig,
  DPoPProofContext,
  DPoPProofFactory,
} from "./config";
export type { User } from "./types";
export type {
  TokenResponse,
  UserInfoResponse,
  IntrospectionResponse,
  AuthorizationPageProtectionResult,
  AccountLinkingContext,
  AuthorizationCodeExchangeResult,
  ClientCredentialsTokenOptions,
  DynamicClientRegistrationResponse,
  HomeRealmDiscoveryResult,
  LogoutRequest,
  OpenIdConfiguration,
  PushedAuthorizationRequest,
  PostMessageTarget,
  RefreshOAuthTokenOptions,
  RefreshOidcSessionOptions,
  RefreshOidcSessionResult,
  SecureCookieOptions,
  OAuthSessionState,
  OidcSessionState,
  SessionState,
} from "./client";
export {
  createLocationHeaderRedirect,
  canonicalizeIssuer,
  isSilentAuthenticationError,
  OAuthStateManager,
  parseOAuthCallbackUrl as parseUntrustedOAuthCallback,
  sanitizeAuthorizationUrlForHistory,
  sanitizeOAuthCallbackUrl,
  restoreAuthorizationTransaction,
  StateExpiredError,
  validateFormPostCsrfToken,
  validateFrontChannelLogoutRequest,
} from "./auth";
export type {
  AuthorizationCallbackInput,
  AuthorizationTransaction,
  CreatedAuthorizationRequest,
  CreateAuthorizationRequestOptions,
  FrontChannelLogoutValidationOptions,
  RedirectResponse,
  ValidatedAuthorizationCallback,
} from "./auth";

// PKCE exports
export {
  generatePKCE,
  generateState,
  generateNonce,
  OAuthPKCEManager,
} from "./pkce";
export type {
  PKCECodePair,
  PKCEOptions,
  OAuthPKCEManagerOptions,
} from "./pkce";

// Crypto exports
export {
  detectCryptoAdapter,
  getCryptoAdapter,
  initializeCrypto,
  setCryptoAdapter,
} from "./crypto";
export type { CryptoAdapter } from "./crypto";

// Debug exports
export {
  createGuardhouseLogger,
  isGuardhouseDebugEnabled,
  setGuardhouseDebug,
} from "./debug";
export type { GuardhouseLogger } from "./debug";

// Token exports
export {
  decodeJWT,
  JtiReplayCache,
  validateJwkMetadataForToken,
  validateOidcHashClaims,
  verifyIdToken,
  OidcIdTokenVerifier,
  isTokenExpired,
  getTokenExpiresIn,
} from "./token";
export type {
  JWTPayload,
  JWTHeader,
  JwkMetadata,
  JwkMetadataValidationOptions,
  JwkMetadataValidationResult,
  UntrustedDecodedJWT,
  ExpectedJwkKeyType,
  OidcHashValidationOptions,
  OidcHashValidationResult,
  JtiReplayCacheOptions,
  IdTokenReplayCache,
  IdTokenReplayEntry,
  AuthorizationCodeIdTokenContext,
  HistoricalOidcIdentity,
  IdTokenSigningAlgorithm,
  IdTokenValidationContext,
  OidcIdentity,
  OidcIdentityEvidence,
  OidcIdentityMetadata,
  OidcIdTokenVerifierOptions,
  RefreshIdTokenContext,
  SessionIdTokenContext,
  VerifiedIdToken,
  VerifiedIdTokenPayload,
  VerifyIdTokenOptions,
} from "./token";

// Config exports
export { buildUrl, validateConfig } from "./config";
export type { StorageAdapter } from "./config";
