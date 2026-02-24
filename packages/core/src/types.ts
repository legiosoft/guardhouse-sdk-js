export interface GuardhouseConfig {
  authority: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  scope?: string;
  tokenEndpoint?: string;
  userInfoEndpoint?: string;
  introspectionEndpoint?: string;
  revocationEndpoint?: string;
  requestTimeoutMs?: number;
  allowScopeNarrowing?: boolean;
  maxAuthorizationHeaderBytes?: number;
  maxSilentAuthAttempts?: number;
  requireUserInteractionForSensitiveOperations?: boolean;
  allowedPostLogoutRedirectUris?: string[];
  sessionStorageKey?: string;
  dpopProofFactory?: (context: {
    method: string;
    url: string;
    accessToken?: string;
  }) => string | Promise<string>;
  debug?: boolean;
}

export interface User {
  sub: string;
  name?: string;
  email?: string;
  roles?: string[];
  scopes?: string[];
  [key: string]: any;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  alg?: string;
  sig?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  sub?: string;
  aud?: string;
  iss?: string;
  jti?: string;
  roles?: string;
  role?: string[];
}

export interface GuardhouseErrorOptions {
  statusCode?: number;
  cause?: unknown;
}

export class GuardhouseError extends Error {
  public code?: string;
  public statusCode?: number;
  public cause?: unknown;

  constructor(
    message: string,
    code?: string,
    statusCodeOrOptions?: number | GuardhouseErrorOptions,
    options?: GuardhouseErrorOptions,
  ) {
    super(message);
    this.name = "GuardhouseError";
    this.code = code;

    if (typeof statusCodeOrOptions === "number") {
      this.statusCode = statusCodeOrOptions;
      this.cause = options?.cause;
      return;
    }

    this.statusCode = statusCodeOrOptions?.statusCode;
    this.cause = statusCodeOrOptions?.cause;
  }
}

export interface AuthUrlOptions {
  authority: string;
  authorizationEndpoint?: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  debug?: boolean;
  responseType?: string;
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
  prompt?: string;
  audience?: string;
  responseMode?: string;
  formPostCsrfToken?: string;
  maxAge?: number;
  extraParams?: Record<string, string | number | null | undefined>;
}

export interface PKCEPair {
  codeVerifier: string;
  codeChallenge: string;
}
