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
