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
import {
  enforceSecureHttpUrl,
  isLocalDevelopmentHostname,
  sanitizeUrlForLogs,
  validateRedirectUri,
} from "./security";

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

const TOKEN_PARAM_KEY_PATTERN = /^[A-Za-z0-9._~-]+$/;
const PKCE_CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]+$/;

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
  private requestTimeoutMs: number | null;
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

    try {
      enforceSecureHttpUrl(authorityUrl, "Authority");
    } catch (error) {
      throw new GuardhouseError(
        error instanceof Error ? error.message : "Invalid authority URL",
        "INSECURE_AUTHORITY",
        { cause: error },
      );
    }

    const runtime = globalThis as typeof globalThis & {
      navigator?: { product?: string };
      window?: unknown;
    };
    const isReactNativeRuntime = runtime.navigator?.product === "ReactNative";
    const isBrowserRuntime =
      typeof runtime.window !== "undefined" && !isReactNativeRuntime;

    if (config.clientSecret && (isBrowserRuntime || isReactNativeRuntime)) {
      throw new GuardhouseError(
        "clientSecret must not be used in browser or React Native runtimes",
        "INSECURE_CLIENT_SECRET_USAGE",
      );
    }

    const configuredTimeout = config.requestTimeoutMs ?? 30000;
    if (!Number.isFinite(configuredTimeout) || configuredTimeout < 0) {
      throw new GuardhouseError(
        "requestTimeoutMs must be a non-negative number",
        "INVALID_TIMEOUT",
      );
    }

    this.requestTimeoutMs = configuredTimeout === 0 ? null : configuredTimeout;

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
      authority: sanitizeUrlForLogs(this.baseURL),
      hasClientSecret: Boolean(config.clientSecret),
      requestTimeoutMs: this.requestTimeoutMs,
      allowsHttp: authorityUrl.protocol === "http:",
      localAuthority: isLocalDevelopmentHostname(authorityUrl.hostname),
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

    for (const [rawKey, rawValue] of Object.entries(params)) {
      const key = rawKey.trim();

      if (!key) {
        continue;
      }

      const normalizedKey = key.toLowerCase();
      if (RESERVED_TOKEN_BODY_PARAM_KEYS.has(normalizedKey)) {
        blockedKeys.push(rawKey);
        continue;
      }

      if (!TOKEN_PARAM_KEY_PATTERN.test(key)) {
        blockedKeys.push(rawKey);
        continue;
      }

      if (rawValue === undefined || rawValue === null || rawValue === "") {
        continue;
      }

      safeParams[key] = rawValue;
    }

    return { safeParams, blockedKeys };
  }

  private requireNonEmptyString(value: string, fieldName: string): string {
    if (typeof value !== "string" || value.trim() === "") {
      throw new GuardhouseError(`${fieldName} is required`, "INVALID_REQUEST");
    }

    return value.trim();
  }

  private validatePkceCodeVerifier(codeVerifier: string): string {
    const normalizedVerifier = this.requireNonEmptyString(
      codeVerifier,
      "codeVerifier",
    );

    if (
      normalizedVerifier.length < 43 ||
      normalizedVerifier.length > 128 ||
      !PKCE_CODE_VERIFIER_PATTERN.test(normalizedVerifier)
    ) {
      throw new GuardhouseError(
        "codeVerifier must be 43-128 characters and contain only RFC7636 unreserved characters",
        "INVALID_PKCE_VERIFIER",
      );
    }

    return normalizedVerifier;
  }

  private createRequestAbortContext(signal?: AbortSignal): {
    signal?: AbortSignal;
    timedOut: () => boolean;
    cleanup: () => void;
  } {
    const timeoutMs = this.requestTimeoutMs;

    if (!signal && timeoutMs === null) {
      return {
        signal: undefined,
        timedOut: () => false,
        cleanup: () => undefined,
      };
    }

    const controller = new AbortController();
    let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
    let didTimeout = false;

    const forwardAbort = () => {
      if (!controller.signal.aborted) {
        controller.abort();
      }
    };

    if (signal) {
      if (signal.aborted) {
        forwardAbort();
      } else {
        signal.addEventListener("abort", forwardAbort, { once: true });
      }
    }

    if (typeof timeoutMs === "number" && timeoutMs > 0) {
      timeoutHandle = setTimeout(() => {
        didTimeout = true;
        controller.abort();
      }, timeoutMs);
    }

    return {
      signal: controller.signal,
      timedOut: () => didTimeout,
      cleanup: () => {
        if (timeoutHandle) {
          clearTimeout(timeoutHandle);
        }

        if (signal) {
          signal.removeEventListener("abort", forwardAbort);
        }
      },
    };
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
    if (
      /^[a-z][a-z0-9+.-]*:\/\//i.test(endpoint) &&
      !/^https?:\/\//i.test(endpoint)
    ) {
      throw new GuardhouseError(
        "Endpoint URL must use http or https",
        "UNSAFE_ENDPOINT_URL",
      );
    }

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
      if (typeof TextEncoder !== "function") {
        throw new GuardhouseError(
          "TextEncoder is not available in this environment",
          "BASE64_UNAVAILABLE",
        );
      }

      const bytes = new TextEncoder().encode(value);
      let binary = "";
      for (const byte of bytes) {
        binary += String.fromCharCode(byte);
      }
      return btoa(binary);
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
      url: sanitizeUrlForLogs(url),
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

    const abortContext = this.createRequestAbortContext(options.signal);

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: options.body,
        signal: abortContext.signal ?? options.signal,
      });

      this.logger.debug("HTTP response received", {
        method,
        url: sanitizeUrlForLogs(url),
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
          errorCode: errorData.error,
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
        url: sanitizeUrlForLogs(url),
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

      if (abortContext.timedOut()) {
        throw new GuardhouseError(
          `Request timed out after ${this.requestTimeoutMs}ms`,
          "REQUEST_TIMEOUT",
          { cause: error },
        );
      }

      this.logger.error("Network request failed", {
        method,
        url: sanitizeUrlForLogs(url),
        error,
      });
      throw new GuardhouseError(
        error instanceof Error ? error.message : "Network error",
        "NETWORK_ERROR",
        { cause: error },
      );
    } finally {
      abortContext.cleanup();
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
    const normalizedCode = this.requireNonEmptyString(code, "code");
    const normalizedCodeVerifier = this.validatePkceCodeVerifier(codeVerifier);
    const normalizedRedirectUri = validateRedirectUri(redirectUri).toString();

    const { safeParams, blockedKeys } = this.sanitizeTokenBodyParams(params);

    if (blockedKeys.length > 0) {
      this.logger.warn("Ignoring reserved token request keys in params", {
        blockedKeys,
      });
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: normalizedCode,
      redirect_uri: normalizedRedirectUri,
      code_verifier: normalizedCodeVerifier,
    });

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    for (const [key, value] of Object.entries(safeParams)) {
      body.set(key, value);
    }

    this.logger.info("Exchanging authorization code for tokens", {
      redirectUri: sanitizeUrlForLogs(normalizedRedirectUri),
      hasCode: true,
      hasCodeVerifier: true,
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
    const normalizedRefreshToken = this.requireNonEmptyString(
      refreshToken,
      "refreshToken",
    );

    const { safeParams, blockedKeys } = this.sanitizeTokenBodyParams(params);

    if (blockedKeys.length > 0) {
      this.logger.warn("Ignoring reserved token request keys in params", {
        blockedKeys,
      });
    }

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: normalizedRefreshToken,
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
    const normalizedToken = this.requireNonEmptyString(token, "token");

    this.logger.debug("Fetching user info", {
      hasToken: true,
    });

    const response = await this.fetch(this.endpoints.userInfo, {
      token: normalizedToken,
    });

    const user = response.data as UserInfoResponse;

    this.logger.debug("User info fetched", {
      hasSubject: Boolean(user.sub),
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
    const normalizedToken = this.requireNonEmptyString(token, "token");

    this.logger.debug("Introspecting token", {
      hasToken: true,
    });

    const body = new URLSearchParams({
      token: normalizedToken,
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
    tokenTypeHint: "access_token" | "refresh_token" = "access_token",
  ): Promise<void> {
    const normalizedToken = this.requireNonEmptyString(token, "token");

    this.logger.info("Revoking token", {
      hasToken: true,
    });

    const body = new URLSearchParams({ token: normalizedToken });

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    body.set("token_type_hint", tokenTypeHint);

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
