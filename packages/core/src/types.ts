export interface User {
  readonly sub: string;
  readonly name?: string;
  readonly email?: string;
  readonly picture?: string;
  readonly roles?: readonly string[];
  readonly scopes?: readonly string[];
  readonly [key: string]: unknown;
}

/** @internal Use GuardhouseClient.createAuthorizationRequest for application flows. */
export interface AuthUrlOptions {
  authority: string;
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  requestUri?: string;
  scope?: string;
  allowOfflineAccessScope?: boolean;
  allowAuthorizationWithoutAudience?: boolean;
  debug?: boolean;
  responseType?: "code";
  state: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
  prompt?: string;
  acrValues?: string | string[];
  uiLocales?: string | string[];
  loginHint?: string;
  claims?: Record<string, unknown>;
  audience?: string;
  resource?: string | readonly string[];
  responseMode?: string;
  formPostCsrfToken?: string;
  maxAge?: number;
  extraParams?: Record<string, string | number | null | undefined>;
}
