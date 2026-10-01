export interface RequestOptions {
  method?: "GET" | "HEAD" | "POST";
  headers?: Headers | Record<string, string> | Array<[string, string]>;
  body?: string;
  token?: string;
  skipAuthHeader?: boolean;
  skipDpopProof?: boolean;
  cacheMode?:
    | "default"
    | "no-store"
    | "reload"
    | "no-cache"
    | "force-cache"
    | "only-if-cached";
  signal?: AbortSignal;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  /**
   * SECURITY WARNING:
   * Never trust id_token claims directly for local authentication decisions.
   * Always validate signature, issuer, audience, and expiration with a JWT/OIDC validation library first.
   */
  id_token?: string;
}

export interface UserInfoResponse {
  readonly sub: string;
  readonly name?: string;
  readonly email?: string;
  readonly picture?: string;
  readonly roles?: readonly string[];
  readonly scopes?: readonly string[];
  readonly [key: string]: unknown;
}

export type IntrospectionResponse =
  | Readonly<{ active: false }>
  | Readonly<{
      active: true;
      scope?: string;
      client_id?: string;
      username?: string;
      token_type?: string;
      exp?: number;
      iat?: number;
      nbf?: number;
      /**
       * For user-context tokens, validate that `sub` is present and matches the expected subject.
       */
      sub?: string;
      aud?: string | string[];
      iss?: string;
      jti?: string;
      [key: string]: unknown;
    }>;

export interface OpenIdConfiguration {
  readonly issuer: string;
  readonly authorization_endpoint?: string;
  readonly token_endpoint?: string;
  readonly userinfo_endpoint?: string;
  readonly jwks_uri?: string;
  readonly introspection_endpoint?: string;
  readonly revocation_endpoint?: string;
  readonly end_session_endpoint?: string;
  readonly pushed_authorization_request_endpoint?: string;
  readonly registration_endpoint?: string;
  readonly authorization_response_iss_parameter_supported?: boolean;
  readonly response_types_supported?: readonly string[];
  readonly response_modes_supported?: readonly string[];
  readonly grant_types_supported?: readonly string[];
  readonly scopes_supported?: readonly string[];
  readonly code_challenge_methods_supported?: readonly string[];
  readonly [key: string]: unknown;
}

export interface AuthorizationPageProtectionResult {
  protected: boolean;
  xFrameOptions?: string;
  frameAncestorsPolicy?: string;
  warnings: string[];
}

import type {
  HistoricalOidcIdentity,
  OidcIdentity,
  VerifiedIdToken,
} from "../token/id-token-verifier";

interface SessionStateBase {
  version: 3;
  issuer: string;
  clientId: string;
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  scope?: string;
  hasRefreshToken: boolean;
}

export interface OAuthSessionState extends SessionStateBase {
  kind: "oauth";
}

export interface OidcSessionState extends SessionStateBase {
  kind: "oidc";
  idToken: string;
  identity: OidcIdentity;
}

export type SessionState = OAuthSessionState | OidcSessionState;

export type AuthorizationCodeExchangeResult =
  | { readonly mode: "oauth2"; readonly tokens: TokenResponse }
  | {
      readonly mode: "oidc";
      readonly tokens: TokenResponse;
      readonly idToken: VerifiedIdToken;
      readonly identity: OidcIdentity;
    };

export interface RefreshOAuthTokenOptions {
  grantedScope?: string;
  requestParameters?: Record<string, string>;
}

export interface RefreshOidcSessionOptions extends RefreshOAuthTokenOptions {
  previousIdToken: string;
  requiredAcrValues?: readonly string[];
  requiredAmrValues?: readonly string[];
}

export type RefreshOidcSessionResult =
  | {
      readonly identityStatus: "current";
      readonly tokens: TokenResponse;
      readonly identity: OidcIdentity;
      readonly idToken: VerifiedIdToken;
    }
  | {
      readonly identityStatus: "historical";
      readonly tokens: TokenResponse;
      readonly identity: HistoricalOidcIdentity;
      readonly idToken?: undefined;
    };

export interface RestoreOidcSessionOptions {
  idToken: string;
  requiredAcrValues?: readonly string[];
  requiredAmrValues?: readonly string[];
}

/** Online restoration evidence, never a current ID-token credential. */
export interface RestoredOidcSession {
  readonly identity: HistoricalOidcIdentity;
  readonly userInfo: UserInfoResponse;
}

export interface ClientCredentialsTokenOptions {
  scope?: string;
  resource?: string | readonly string[];
  audience?: string;
  requestParameters?: Record<string, string>;
}

export interface LogoutRequest {
  postLogoutRedirectUri?: string;
  idTokenHint?: string;
  state?: string;
  federated?: boolean;
}

export interface SecureCookieOptions {
  maxAgeSeconds?: number;
  path?: string;
  sameSite?: "Strict" | "Lax" | "None";
  secure?: boolean;
  /**
   * Domain attributes are forbidden to enforce Host-Only cookies and prevent Cookie Tossing attacks.
   */
  domain?: never;
}

export interface AccountLinkingContext {
  primarySessionActive: boolean;
  secondarySessionActive: boolean;
  primarySubject: string;
  secondarySubject: string;
}

declare const pushedAuthorizationRequestBrand: unique symbol;
export interface PushedAuthorizationRequest {
  readonly requestUri: string;
  readonly expiresIn: number;
  readonly [pushedAuthorizationRequestBrand]: true;
}

export interface DynamicClientRegistrationResponse {
  readonly client_id: string;
  readonly client_secret?: string;
  readonly registration_access_token?: string;
  readonly registration_client_uri?: string;
  readonly [key: string]: unknown;
}

export interface HomeRealmDiscoveryResult {
  emailDomain: string;
  issuer: string;
}

export interface PostMessageTarget {
  postMessage: (message: unknown, targetOrigin: string) => void;
}
