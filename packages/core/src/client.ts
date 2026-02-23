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

const DEFAULT_ENDPOINTS = {
  token: "/connect/token",
  userInfo: "/connect/userinfo",
  introspection: "/connect/introspect",
  revocation: "/connect/revoke",
};

const RESERVED_TOKEN_BODY_PARAM_KEYS = new Set([
  "grant_type",
  "code",
  "refresh_token",
  "client_id",
  "client_secret",
  "code_verifier",
  "redirect_uri",
]);

export interface RequestOptions {
  method?: "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "PATCH";
  headers?: Headers | Record<string, string> | Array<[string, string]>;
  body?: string;
  token?: string;
  skipAuthHeader?: boolean;
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
  private endpoints: {
    token: string;
    userInfo: string;
    introspection: string;
    revocation: string;
  };

  constructor(config: GuardhouseConfig) {
    this.config = config;

    if (typeof config.debug === "boolean") {
      setGuardhouseDebug(config.debug);
    }

    this.logger = createGuardhouseLogger("CoreClient", config.debug);

    let authorityUrl: URL;
    try {
      authorityUrl = new URL(config.authority);
    } catch (error) {
      throw new GuardhouseError("Invalid authority URL", "INVALID_AUTHORITY", {
        cause: error,
      });
    }

    const isSecureAuthority = authorityUrl.protocol === "https:";
    const localDevelopmentHosts = [
      "localhost",
      "127.0.0.1",
      "::1",
      "[::1]",
      "10.0.2.2",
    ];
    const isLocalDevelopmentAuthority =
      localDevelopmentHosts.includes(authorityUrl.hostname) ||
      authorityUrl.hostname.startsWith("192.168.");

    if (!isSecureAuthority && !isLocalDevelopmentAuthority) {
      throw new GuardhouseError(
        "Authority must use HTTPS protocol (except local development hosts)",
        "INSECURE_AUTHORITY",
      );
    }

    this.baseURL = config.authority.replace(/\/+$/, "");
    this.endpoints = {
      token: config.tokenEndpoint || DEFAULT_ENDPOINTS.token,
      userInfo: config.userInfoEndpoint || DEFAULT_ENDPOINTS.userInfo,
      introspection:
        config.introspectionEndpoint || DEFAULT_ENDPOINTS.introspection,
      revocation: config.revocationEndpoint || DEFAULT_ENDPOINTS.revocation,
    };

    if (typeof fetch !== "function") {
      this.logger.warn(
        "Global fetch API is unavailable. Node.js versions older than 18 need a fetch polyfill (for example, undici or node-fetch).",
      );
    }

    this.logger.info("Initialized", {
      authority: this.baseURL,
      hasClientSecret: Boolean(config.clientSecret),
    });
  }

  private shouldSendUserAgentHeader(): boolean {
    const runtime = globalThis as typeof globalThis & {
      navigator?: { product?: string };
      window?: unknown;
    };
    const isReactNative = runtime.navigator?.product === "ReactNative";

    return typeof runtime.window === "undefined" || isReactNative;
  }

  private sanitizeTokenBodyParams(
    params: Record<string, string | null | undefined>,
  ): {
    safeParams: Record<string, string>;
    blockedKeys: string[];
  } {
    const safeParams: Record<string, string> = {};
    const blockedKeys: string[] = [];

    for (const [key, value] of Object.entries(params)) {
      if (RESERVED_TOKEN_BODY_PARAM_KEYS.has(key)) {
        blockedKeys.push(key);
        continue;
      }

      if (value === undefined || value === null || value === "") {
        continue;
      }

      safeParams[key] = value;
    }

    return { safeParams, blockedKeys };
  }

  private isAbsoluteEndpointWithinBase(endpoint: string): boolean {
    const baseUrl = new URL(this.baseURL);
    const endpointUrl = new URL(endpoint);

    if (endpointUrl.origin !== baseUrl.origin) {
      return false;
    }

    const basePath = baseUrl.pathname.replace(/\/+$/, "");
    const endpointPath = endpointUrl.pathname.replace(/\/+$/, "");

    if (basePath === "") {
      return true;
    }

    return endpointPath === basePath || endpointPath.startsWith(`${basePath}/`);
  }

  private buildRequestUrl(endpoint: string): string {
    if (/^https?:\/\//i.test(endpoint)) {
      if (!this.isAbsoluteEndpointWithinBase(endpoint)) {
        throw new GuardhouseError(
          "Absolute endpoint URL is outside the configured authority",
          "UNSAFE_ENDPOINT_URL",
        );
      }

      return endpoint;
    }

    return `${this.baseURL}/${endpoint.replace(/^\/+/, "")}`;
  }

  private encodeBase64(value: string): string {
    if (typeof Buffer !== "undefined") {
      return Buffer.from(value, "utf8").toString("base64");
    }

    if (typeof btoa === "function") {
      return btoa(value);
    }

    throw new GuardhouseError(
      "Base64 encoding is not available in this environment",
      "BASE64_UNAVAILABLE",
    );
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

    const credentials = `${encodeURIComponent(this.config.clientId)}:${encodeURIComponent(this.config.clientSecret)}`;
    const encoded = this.encodeBase64(credentials);

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
    const url = this.buildRequestUrl(endpoint);
    const method = (options.method || "GET").toUpperCase();

    this.logger.debug("HTTP request", {
      method,
      url,
    });

    const headers = new Headers(options.headers);

    if (!headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }

    if (!headers.has("Accept")) {
      headers.set("Accept", "application/json");
    }

    if (this.shouldSendUserAgentHeader()) {
      if (!headers.has("User-Agent")) {
        headers.set("User-Agent", "guardhouse-js/1.0.0");
      }
    } else {
      headers.delete("User-Agent");
    }

    if (options.token && !options.skipAuthHeader) {
      headers.set("Authorization", `Bearer ${options.token}`);
    }

    if (!options.token && !options.skipAuthHeader && this.config.clientSecret) {
      headers.set("Authorization", this.buildBasicAuthHeader());
    }

    this.logger.debug("Prepared request headers", {
      hasAuthorization: Boolean(headers.get("Authorization")),
      contentType: headers.get("Content-Type"),
      bodyLength: options.body?.length ?? 0,
    });

    if (options.body && (method === "GET" || method === "HEAD")) {
      throw new GuardhouseError(
        "Cannot send a GET or HEAD request with a body",
        "INVALID_REQUEST",
      );
    }

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: options.body,
        signal: options.signal,
      });

      this.logger.debug("HTTP response received", {
        method,
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

      let data: unknown = null;

      if (
        response.status !== 204 &&
        response.status !== 205 &&
        response.headers.get("Content-Length") !== "0"
      ) {
        const text = await response.text();

        if (text) {
          try {
            data = JSON.parse(text);
          } catch (error) {
            this.logger.warn("Response body is not valid JSON", {
              status: response.status,
              error: error instanceof Error ? error.message : String(error),
            });
            data = text;
          }
        }
      }

      this.logger.debug("HTTP request succeeded", {
        method,
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
        method,
        url,
        error,
      });
      throw new GuardhouseError(
        error instanceof Error ? error.message : "Network error",
        "NETWORK_ERROR",
        { cause: error },
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
    const contentType =
      response.headers.get("Content-Type")?.toLowerCase() || "";

    try {
      const rawBody = await response.text();

      if (!rawBody) {
        return {};
      }

      if (contentType.includes("json")) {
        try {
          const errorData = JSON.parse(rawBody);

          this.logger.debug("Parsed HTTP error response", {
            status: response.status,
            hasOAuthError: Boolean(errorData?.error),
          });

          return errorData;
        } catch {
          return {
            error: "server_error",
            error_description: rawBody.slice(0, 200),
          };
        }
      }

      if (
        contentType.includes("text/html") ||
        contentType.includes("text/plain")
      ) {
        return {
          error: "server_error",
          error_description: rawBody.slice(0, 200),
        };
      }

      try {
        return JSON.parse(rawBody);
      } catch {
        return {
          error: "server_error",
          error_description: rawBody.slice(0, 200),
        };
      }
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
   * - id_token must be cryptographically validated before trusting claims
   *
   * SECURITY WARNING:
   * If the token response contains an id_token, treat it as untrusted until you
   * validate signature, issuer (iss), audience (aud), and expiration (exp).
   * Never start a local authenticated session from unvalidated id_token claims.
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
    const { safeParams, blockedKeys } = this.sanitizeTokenBodyParams(params);

    if (blockedKeys.length > 0) {
      this.logger.warn("Ignoring reserved token request keys in params", {
        blockedKeys,
      });
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    });

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    for (const [key, value] of Object.entries(safeParams)) {
      body.set(key, value);
    }

    this.logger.info("Exchanging authorization code for tokens", {
      redirectUri,
      hasCode: Boolean(code),
      hasCodeVerifier: Boolean(codeVerifier),
    });

    const response = await this.fetch(this.endpoints.token, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
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
    const { safeParams, blockedKeys } = this.sanitizeTokenBodyParams(params);

    if (blockedKeys.length > 0) {
      this.logger.warn("Ignoring reserved token request keys in params", {
        blockedKeys,
      });
    }

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    for (const [key, value] of Object.entries(safeParams)) {
      body.set(key, value);
    }

    this.logger.info("Refreshing access token");

    const response = await this.fetch(this.endpoints.token, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
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

    const response = await this.fetch(this.endpoints.userInfo, {
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

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    const response = await this.postForm<IntrospectionResponse>(
      this.endpoints.introspection,
      body,
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
  async revokeToken(
    token: string,
    tokenTypeHint?: "access_token" | "refresh_token",
  ): Promise<void> {
    this.logger.info("Revoking token", {
      hasToken: Boolean(token),
    });

    const body = new URLSearchParams({ token });

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    if (tokenTypeHint) {
      body.set("token_type_hint", tokenTypeHint);
    }

    await this.fetch(this.endpoints.revocation, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
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
