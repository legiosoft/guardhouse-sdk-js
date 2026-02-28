import type {
  CryptoAdapter,
  GuardhouseConfig as CoreGuardhouseConfig,
} from "@guardhouse/core";
import type { GuardhouseBrowserAdapter } from "../adapters/BrowserAdapter";
import type { GuardhouseStorageAdapter } from "../adapters/StorageAdapter";

export type FetchLike = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

/**
 * Browser auth options for login and registration sessions.
 */
export interface BrowserLoginOptions {
  ephemeralSession?: boolean;
  timeoutMs?: number;
  scope?: string;
  audience?: string;
  prompt?: string;
  appState?: Record<string, unknown>;
  extraParams?: Record<string, string | number | null | undefined>;
}

/**
 * Supported passkey authenticator transports.
 */
export type PasskeyTransport = "usb" | "nfc" | "ble" | "hybrid" | "internal";

/**
 * WebAuthn allowCredentials item.
 */
export interface PasskeyCredentialDescriptor {
  id: string;
  type: "public-key";
  transports?: PasskeyTransport[];
}

/**
 * WebAuthn credential request options consumed by native passkey libraries.
 */
export interface PasskeyCredentialRequestOptions {
  challenge: string;
  rpId?: string;
  timeout?: number;
  userVerification?: "required" | "preferred" | "discouraged";
  allowCredentials?: PasskeyCredentialDescriptor[];
  extensions?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * WebAuthn assertion response payload.
 */
export interface PasskeyAssertionResponse {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string | null;
  [key: string]: unknown;
}

/**
 * Normalized assertion result from passkey adapter.
 */
export interface PasskeyAssertionResult {
  id: string;
  rawId?: string;
  type: "public-key";
  response: PasskeyAssertionResponse;
  clientExtensionResults?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Adapter interface for native passkey assertion prompts.
 */
export interface GuardhousePasskeyAdapter {
  name?: string;
  get(
    requestOptions: PasskeyCredentialRequestOptions,
  ): Promise<PasskeyAssertionResult>;
}

/**
 * Options for headless passkey login.
 */
export interface LoginWithPasskeyOptions {
  scope?: string;
  audience?: string;
  challengeBody?: Record<string, unknown>;
  assertionBody?: Record<string, unknown>;
}

/**
 * Refresh token request options.
 */
export interface RefreshTokenOptions {
  scope?: string;
  audience?: string;
}

/**
 * Authorization code exchange options.
 */
export interface ExchangeCodeForTokensOptions extends RefreshTokenOptions {
  codeVerifier?: string;
}

/**
 * Session restore options.
 */
export interface RestoreSessionOptions extends RefreshTokenOptions {
  minValiditySeconds?: number;
}

/**
 * Access token retrieval options.
 */
export interface GetAccessTokenOptions {
  autoRefresh?: boolean;
  minValiditySeconds?: number;
}

/**
 * Logout and token revocation options.
 */
export interface GuardhouseLogoutOptions {
  revoke?: boolean;
  revokeAccessToken?: boolean;
  revokeRefreshToken?: boolean;
  throwOnRevokeFailure?: boolean;
}

/**
 * Guardhouse endpoint configuration.
 */
export interface GuardhouseClientEndpoints {
  authorization: string;
  registration: string;
  token: string;
  userInfo: string;
  revocation: string;
  passkeyChallenge: string;
  passkeyAssertion: string;
}

/**
 * Guardhouse client configuration.
 */
export interface GuardhouseClientConfig extends Omit<
  CoreGuardhouseConfig,
  | "storage"
  | "redirectUri"
  | "tokenEndpoint"
  | "userInfoEndpoint"
  | "revocationEndpoint"
> {
  /**
   * Redirect URI used by native deep links.
   */
  redirectUri: string;
  /**
   * Optional API audience (passed to authorization/token requests).
   */
  audience?: string;
  requireBiometrics?: boolean;
  cryptoAdapter?: CryptoAdapter;
  /**
   * @deprecated Use refreshTokenStorage instead.
   */
  storage?: GuardhouseStorageAdapter;
  refreshTokenStorage?: GuardhouseStorageAdapter;
  sessionStorage?: GuardhouseStorageAdapter;
  browser?: GuardhouseBrowserAdapter;
  passkey?: GuardhousePasskeyAdapter;
  fetch?: FetchLike;
  defaultEphemeralSession?: boolean;
  userInfoOnLogin?: boolean;
  endpoints?: Partial<GuardhouseClientEndpoints>;
  chunkSize?: number;
}
