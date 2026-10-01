export interface OAuthCallbackResult {
  code?: string;
  state?: string;
  iss?: string;
  sessionState?: string;
  response?: string;
  error?: string;
  /**
   * SECURITY WARNING: Treat this value as untrusted user input.
   * HTML-escape it before rendering in the DOM to prevent DOM-XSS.
   */
  errorDescription?: string;
  errorUri?: string;
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
  tokenType?: string;
  expiresIn?: number;
  /**
   * SECURITY WARNING: Treat this value as untrusted user input.
   * HTML-escape it before rendering in the DOM to prevent DOM-XSS.
   */
  scope?: string;
  params: Record<string, string>;
  sanitizedUrl: string;
}

export interface AuthorizationTransaction {
  readonly version: 2;
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly state: string;
  readonly codeVerifier: string;
  readonly codeChallenge: string;
  readonly nonce: string;
  readonly requestedScope: string;
  readonly requestedAudience?: string;
  readonly requestedResources: readonly string[];
  readonly requiredAcrValues: readonly string[];
  readonly requiredAmrValues: readonly string[];
  readonly prompt?: string;
  readonly maxAgeSeconds?: number;
  readonly responseMode: "query" | "form_post";
  readonly applicationState?: unknown;
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly issRequired: boolean;
}

export interface CreateAuthorizationRequestOptions {
  redirectUri: string;
  scope: string;
  audience?: string;
  resource?: string | readonly string[];
  audiencePolicy?: "guardhouse-required" | "oidc-optional";
  prompt?: string;
  maxAgeSeconds?: number;
  responseMode?: "query" | "form_post";
  applicationState?: unknown;
  allowOfflineAccessScope?: boolean;
  requiredAcrValues?: readonly string[];
  requiredAmrValues?: readonly string[];
}

export interface CreatedAuthorizationRequest {
  authorizationUrl: string;
  transaction: AuthorizationTransaction;
}

export type AuthorizationCallbackInput =
  | { readonly mode: "query"; readonly url: string }
  | {
      readonly mode: "form_post";
      readonly url: string;
      readonly body:
        | URLSearchParams
        | Readonly<Record<string, string>>;
    };

declare const validatedAuthorizationCallbackBrand: unique symbol;

interface ValidatedAuthorizationCallbackEvidence {
  /** @internal Runtime evidence is held privately by the validating client. */
  readonly [validatedAuthorizationCallbackBrand]: true;
}

export type ValidatedAuthorizationCallback =
  | (ValidatedAuthorizationCallbackEvidence & {
      readonly type: "authorization_code";
      readonly code: string;
      readonly state: string;
      readonly issuer?: string;
      readonly sessionState?: string;
      readonly sanitizedUrl: string;
    })
  | (ValidatedAuthorizationCallbackEvidence & {
      readonly type: "error";
      readonly error: string;
      readonly errorDescription?: string;
      readonly errorUri?: string;
      readonly state: string;
      readonly issuer?: string;
      readonly sanitizedUrl: string;
    });

export interface FrontChannelLogoutValidationOptions {
  expectedIssuer: string;
  expectedSessionId?: string;
}

export interface RedirectResponse {
  statusCode: 302 | 303 | 307;
  headers: {
    Location?: string;
    location?: string;
    "Cache-Control"?: string;
    "cache-control"?: string;
    Pragma?: string;
    pragma?: string;
    Expires?: string;
    expires?: string;
  } & Record<string, string>;
}
