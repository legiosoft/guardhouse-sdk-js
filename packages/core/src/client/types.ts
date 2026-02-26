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
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
  roles?: string[];
  scopes?: string[];
  [key: string]: unknown;
}

export interface IntrospectionResponse {
  active: boolean;
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
}

export interface AuthorizationPageProtectionResult {
  protected: boolean;
  xFrameOptions?: string;
  frameAncestorsPolicy?: string;
  warnings: string[];
}

export interface SessionState {
  accessToken: string;
  tokenType: string;
  expiresAt: number;
  scope?: string;
  idToken?: string;
  hasRefreshToken: boolean;
}

export interface LogoutRequest {
  postLogoutRedirectUri?: string;
  idTokenHint?: string;
  state?: string;
  logoutEndpoint?: string;
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

export interface PushedAuthorizationRequestResult {
  requestUri: string;
  expiresIn?: number;
}

export interface HomeRealmDiscoveryResult {
  emailDomain: string;
  issuer: string;
}

export interface PostMessageTarget {
  postMessage: (message: unknown, targetOrigin: string) => void;
}
