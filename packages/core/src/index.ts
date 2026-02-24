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
 * import { GuardhouseClient, generatePKCE, generateAuthUrl } from '@guardhouse/core';
 *
 * const client = new GuardhouseClient({
 *   authority: 'https://auth.example.com',
 *   clientId: 'my-app-id',
 *   // Optional for confidential clients
 *   clientSecret: 'my-app-secret',
 * });
 *
 * // Generate PKCE for OAuth flow
 * const { codeVerifier, codeChallenge } = await generatePKCE();
 *
 * // Build authorization URL
 * const authUrl = await generateAuthUrl({
 *   authority: client.config.authority,
 *   clientId: client.config.clientId,
 *   redirectUri: 'https://app.example.com/callback',
 *   codeChallenge,
 *   responseType: 'code',
 *   state: await generateState(),
 *   nonce: await generateNonce(),
 *   audience: 'https://api.example.com',
 * });
 *
 * // Exchange code for tokens
 * const tokens = await client.exchangeCodeForTokens(code, codeVerifier, redirectUri);
 *
 * // Use access token
 * const userInfo = await client.getUserInfo(tokens.access_token);
 * ```
 */

// Public API exports
export { GuardhouseClient } from "./client";
export type {
  GuardhouseConfig,
  GuardhouseError,
  DPoPProofContext,
  DPoPProofFactory,
} from "./config";
export type { User, AuthUrlOptions } from "./types";
export type {
  TokenResponse,
  UserInfoResponse,
  IntrospectionResponse,
  AuthorizationPageProtectionResult,
  LogoutRequest,
  SessionState,
} from "./client";
export {
  consumeStateBinding,
  generateAuthUrl,
  isSilentAuthenticationError,
  parseOAuthCallbackUrl,
  sanitizeAuthorizationUrlForHistory,
  sanitizeOAuthCallbackUrl,
  stashExpectedState,
  validateFormPostCsrfToken,
  validateFrontChannelLogoutRequest,
  validateAndConsumeState,
} from "./auth";
export type {
  FrontChannelLogoutValidationOptions,
  OAuthCallbackResult,
} from "./auth";

// PKCE exports
export {
  consumeCodeVerifier,
  generatePKCE,
  generateState,
  generateNonce,
  stashCodeVerifier,
} from "./pkce";
export type { PKCECodePair, PKCEOptions } from "./pkce";

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
  validateToken,
  isTokenExpired,
  getTokenExpiresIn,
} from "./token";
export type {
  JWTPayload,
  JWTHeader,
  DecodedJWT,
  ExpectedJwkKeyType,
  TokenValidationResult,
  TokenValidationOptions,
} from "./token";

// Config exports
export { buildUrl, validateConfig } from "./config";
export type { StorageAdapter } from "./config";
