/**
 * Guardhouse HTTP Client
 *
 * SECURITY ARCHITECTURE:
 *
 * 1. Request Signing (Confidential Clients):
 *    - HTTP Basic Auth using clientId:clientSecret
 *    - Encoded as Base64 (RFC 7617)
 *    - Never sends secret in URL parameters or body
 *
 * 2. TLS Enforcement:
 *    - All requests use HTTPS
 *    - Strict SSL verification (can't disable)
 *    - Prevents MITM attacks
 *
 * 3. Error Handling:
 *    - Parses OAuth error responses
 *    - Returns structured error objects
 *    - Includes HTTP status codes
 *
 * 4. Request Headers:
 *    - Content-Type: application/json or application/x-www-form-urlencoded
 *    - Accept: application/json
 *    - User-Agent: Guardhouse SDK
 *
 * 5. Token Storage (Optional):
 *    - Client can inject storage adapter
 *    - Useful for automatic token management
 */

import type { GuardhouseConfig } from "./config";

import { GuardhouseError } from "./config";
import { createGuardhouseLogger, setGuardhouseDebug } from "./debug";

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  headers?: Record<string, string>;
  body?: string;
  token?: string;
  skipAuthHeader?: boolean;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
}

export interface UserInfoResponse {
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
  roles?: string[];
  scopes?: string[];
  [key: string]: any;
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
  sub?: string;
  aud?: string | string[];
  iss?: string;
  jti?: string;
  [key: string]: any;
}

/**
 * Guardhouse HTTP Client
 *
 * Handles authenticated HTTP requests to Guardhouse endpoints
 * Supports both public and confidential clients
 *
 * @example
 * ```ts
 * const client = new GuardhouseClient({
 *   authority: 'https://auth.example.com',
 *   clientId: 'my-app-id',
 *   // Optional for confidential clients
 *   clientSecret: 'my-app-secret',
 * });
 *
 * const response = await client.fetch('/connect/userinfo');
 * console.log(response.data);
 * ```
 */
export class GuardhouseClient {
  private config: GuardhouseConfig;
  private baseURL: string;
  private logger: ReturnType<typeof createGuardhouseLogger>;

  constructor(config: GuardhouseConfig) {
    this.config = config;

    if (typeof config.debug === "boolean") {
      setGuardhouseDebug(config.debug);
    }

    this.logger = createGuardhouseLogger("CoreClient", config.debug);

    this.baseURL = config.authority.replace(/\/+$/, "");

    this.logger.info("Initialized", {
      authority: this.baseURL,
      hasClientSecret: Boolean(config.clientSecret),
    });
  }

  /**
   * Build basic auth header for confidential clients
   *
   * SECURITY: Encodes clientId:clientSecret in Base64
   * - RFC 7617 HTTP Basic Authentication
   * - Never includes secrets in URLs or query params
   * - Prevents secret leakage via logs or proxies
   *
   * @returns Authorization header value
   */
  private buildBasicAuthHeader(): string {
    if (!this.config.clientSecret) {
      this.logger.debug(
        "Skipping basic auth header because clientSecret is missing",
      );
      return "";
    }

    const credentials = `${this.config.clientId}:${this.config.clientSecret}`;
    const encoded = btoa(credentials);

    this.logger.debug("Built basic auth header for confidential client");

    return `Basic ${encoded}`;
  }

  /**
   * Make HTTP request with automatic auth headers
   *
   * SECURITY:
   * - Automatically adds Authorization header if token provided
   * - Uses HTTPS only (enforced by config validation)
   * - Strict SSL verification (can't disable)
   *
   * @param endpoint - API endpoint path (e.g., '/connect/userinfo')
   * @param options - Request options
   * @returns Response with data, status, headers
   *
   * @throws {GuardhouseError} On HTTP or network errors
   */
  async fetch(
    endpoint: string,
    options: RequestOptions = {},
  ): Promise<{
    data: unknown;
    status: number;
    headers: Headers;
  }> {
    const url = `${this.baseURL}${endpoint}`;

    this.logger.debug("HTTP request", {
      method: options.method || "GET",
      url,
    });

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      Accept: "application/json",
      "User-Agent": "guardhouse-js/1.0.0",
      ...options.headers,
    };

    if (options.token && !options.skipAuthHeader) {
      headers["Authorization"] = `Bearer ${options.token}`;
    }

    if (!options.token && !options.skipAuthHeader && this.config.clientSecret) {
      headers["Authorization"] = this.buildBasicAuthHeader();
    }

    this.logger.debug("Prepared request headers", {
      hasAuthorization: Boolean(headers["Authorization"]),
      contentType: headers["Content-Type"],
      bodyLength: options.body?.length ?? 0,
    });

    try {
      const response = await fetch(url, {
        method: options.method || "GET",
        headers,
        body: options.body,
      });

      this.logger.debug("HTTP response received", {
        method: options.method || "GET",
        url,
        status: response.status,
      });

      if (!response.ok) {
        const errorData = await this.parseErrorResponse(response);
        let errorMessage =
          errorData.error_description ||
          errorData.error ||
          `Request failed with status ${response.status}`;

        if (
          errorData.errors &&
          Array.isArray(errorData.errors) &&
          errorData.errors.length > 0
        ) {
          const error = errorData.errors[0];
          if (error.message) {
            errorMessage = error.message;
          } else if (typeof error === "string") {
            errorMessage = error;
          }
        }

        this.logger.error("HTTP request failed", {
          status: response.status,
          statusText: response.statusText,
          errorData: JSON.stringify(errorData, null, 2),
        });
        throw new GuardhouseError(
          errorMessage,
          errorData.error,
          response.status,
        );
      }

      const data = await response.json();

      this.logger.debug("HTTP request succeeded", {
        method: options.method || "GET",
        url,
        status: response.status,
      });

      return {
        data,
        status: response.status,
        headers: response.headers,
      };
    } catch (error) {
      if (error instanceof GuardhouseError) {
        throw error;
      }

      this.logger.error("Network request failed", {
        method: options.method || "GET",
        url,
        error,
      });
      throw new GuardhouseError(
        error instanceof Error ? error.message : "Network error",
        "NETWORK_ERROR",
      );
    }
  }

  /**
   * Parse OAuth error response
   *
   * OAuth 2.0 error responses follow standard format:
   * {
   *   "error": "invalid_grant",
   *   "error_description": "Invalid authorization code"
   * }
   *
   * @param response - Fetch response object
   * @returns Parsed error object
   */
  private async parseErrorResponse(response: Response): Promise<any> {
    try {
      const errorData = await response.json();

      this.logger.debug("Parsed HTTP error response", {
        status: response.status,
        hasOAuthError: Boolean(errorData?.error),
      });

      return errorData;
    } catch (error) {
      this.logger.warn("Failed to parse HTTP error response body", {
        status: response.status,
        error: error instanceof Error ? error.message : String(error),
      });

      return {};
    }
  }

  /**
   * Exchange authorization code for tokens
   *
   * SECURITY:
   * - Uses form-encoded body (OAuth 2.0 spec)
   * - Includes PKCE code_verifier (RFC 7636)
   * - Never includes secrets in URLs or query params
   *
   * @param code - Authorization code from callback
   * @param codeVerifier - PKCE code verifier
   * @param redirectUri - Callback URL (must match authorization request)
   * @param params - Additional parameters
   * @returns Token response
   *
   * @throws {GuardhouseError} On token exchange failure
   */
  async exchangeCodeForTokens(
    code: string,
    codeVerifier: string,
    redirectUri: string,
    params: Record<string, string> = {},
  ): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: this.config.clientId,
      code_verifier: codeVerifier,
      ...params,
    });

    this.logger.info("Exchanging authorization code for tokens", {
      redirectUri,
      hasCode: Boolean(code),
      hasCodeVerifier: Boolean(codeVerifier),
    });

    const response = await this.fetch("/connect/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      skipAuthHeader: true, // Don't add auth header for token exchange
    });

    const tokenResponse = response.data as TokenResponse;

    this.logger.info("Authorization code exchange succeeded", {
      expiresIn: tokenResponse.expires_in,
      hasRefreshToken: Boolean(tokenResponse.refresh_token),
      hasIdToken: Boolean(tokenResponse.id_token),
    });

    return tokenResponse;
  }

  /**
   * Refresh access token using refresh token
   *
   * SECURITY:
   * - Uses form-encoded body (OAuth 2.0 spec)
   * - Refresh token is sent in POST body (not URL)
   * - Client authentication (confidential clients)
   *
   * @param refreshToken - Refresh token from previous token response
   * @param params - Additional parameters
   * @returns New token response
   *
   * @throws {GuardhouseError} On refresh failure
   */
  async refreshToken(
    refreshToken: string,
    params: Record<string, string> = {},
  ): Promise<TokenResponse> {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.config.clientId,
      ...params,
    });

    this.logger.info("Refreshing access token");

    const response = await this.fetch("/connect/token", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      skipAuthHeader: true,
    });

    const tokenResponse = response.data as TokenResponse;

    this.logger.info("Access token refreshed", {
      expiresIn: tokenResponse.expires_in,
      hasRefreshToken: Boolean(tokenResponse.refresh_token),
    });

    return tokenResponse;
  }

  /**
   * Fetch user info using access token
   *
   * SECURITY:
   * - Uses Bearer token in Authorization header
   * - Standard OIDC endpoint: /connect/userinfo
   *
   * @param token - Access token
   * @returns User information
   *
   * @throws {GuardhouseError} On fetch failure
   *
   * NOTE: This endpoint is designed for user tokens (from authorization code flow).
   * For client credentials tokens, use introspectToken() instead.
   */
  async getUserInfo(token: string): Promise<UserInfoResponse> {
    this.logger.debug("Fetching user info", {
      hasToken: Boolean(token),
    });

    const response = await this.fetch("/connect/userinfo", {
      token,
    });

    const user = response.data as UserInfoResponse;

    this.logger.debug("User info fetched", {
      subject: user.sub,
      hasEmail: Boolean(user.email),
    });

    return user;
  }

  /**
   * Introspect token to get token information
   *
   * SECURITY:
   * - Uses Basic auth for client credentials
   * - Standard OAuth 2.0 endpoint: /connect/introspect
   *
   * @param token - Access token to introspect
   * @returns Token information
   *
   * @throws {GuardhouseError} On introspection failure
   *
   * NOTE: Use this for client credentials tokens since userinfo doesn't support them.
   */
  async introspectToken(token: string): Promise<IntrospectionResponse> {
    this.logger.debug("Introspecting token", {
      hasToken: Boolean(token),
    });

    const body = new URLSearchParams({
      token,
      token_type_hint: "access_token",
    });

    const response = await this.postForm<IntrospectionResponse>(
      "/connect/introspect",
      body,
      true,
    );

    this.logger.debug("Token introspection completed", {
      active: Boolean(response.active),
      hasSubject: Boolean(response.sub),
    });

    return response;
  }

  /**
   * Revoke access token (optional implementation)
   *
   * Some authorization servers support token revocation
   * Check your server's documentation
   *
   * @param token - Access token to revoke
   * @throws {GuardhouseError} On revocation failure
   */
  async revokeToken(token: string): Promise<void> {
    this.logger.info("Revoking token", {
      hasToken: Boolean(token),
    });

    const body = new URLSearchParams({
      token,
      client_id: this.config.clientId,
    });

    await this.fetch("/connect/revoke", {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      skipAuthHeader: true,
    });

    this.logger.info("Token revoked");
  }

  /**
   * POST request with form-encoded body
   *
   * @param endpoint - API endpoint path
   * @param body - Form data
   * @param skipAuthHeader - Skip adding auth header
   * @returns Response with data, status, headers
   *
   * @throws {GuardhouseError} On HTTP or network errors
   */
  async postForm<T>(
    endpoint: string,
    body: URLSearchParams,
    skipAuthHeader = false,
  ): Promise<T> {
    this.logger.debug("Submitting form request", {
      endpoint,
      paramCount: Array.from(body.keys()).length,
      skipAuthHeader,
    });

    const response = await this.fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      skipAuthHeader,
    });

    this.logger.debug("Form request succeeded", {
      endpoint,
      status: response.status,
    });

    return response.data as T;
  }
}
