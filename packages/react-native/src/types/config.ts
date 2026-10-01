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
  /** RFC 8707 resource indicators. */
  resource?: string | readonly string[];
  prompt?: string;
  maxAgeSeconds?: number;
  requiredAcrValues?: readonly string[];
  requiredAmrValues?: readonly string[];
  appState?: Record<string, unknown>;
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
  /** Defaults to the saved session scope; an override may only keep or narrow it. */
  scope?: string;
  audience?: string;
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
  /** PKCE random bytes/SHA-256 only. OIDC also requires global Web Crypto. */
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
  /**
   * Include UserInfo in the authenticated user. Historical cold restoration
   * still validates the access token through UserInfo when false, returning sub only.
   */
  userInfoOnLogin?: boolean;
  /** Exact, case-sensitive accepted ACR values. */
  requiredAcrValues?: readonly string[];
  /** Exact, case-sensitive AMR values that must all be present. */
  requiredAmrValues?: readonly string[];
  endpoints?: Partial<GuardhouseClientEndpoints>;
  chunkSize?: number;
}
