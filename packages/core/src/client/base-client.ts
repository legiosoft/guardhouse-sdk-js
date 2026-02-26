import type { GuardhouseConfig } from "../config";
import { GuardhouseError } from "../config";
import { createGuardhouseLogger, setGuardhouseDebug } from "../debug";
import {
  enforceNonSpoofableHostname,
  enforceSecureHttpUrl,
  isLocalDevelopmentHostname,
  isUnsafeObjectKey,
  sanitizeUrlForLogs,
  validateAndNormalizeRedirectUri,
} from "../security";

import {
  ALLOWED_HTTP_METHODS,
  BLOCKED_REGISTRATION_METADATA_KEYS,
  DEFAULT_DISCOVERY_CACHE_TTL_MS,
  DEFAULT_ENDPOINTS,
  DEFAULT_MAX_AUTH_HEADER_BYTES,
  DEFAULT_MAX_SILENT_AUTH_ATTEMPTS,
  DEFAULT_SESSION_STORAGE_KEY,
  DISCOVERY_ENDPOINT_KEYS,
  MAX_DISCOVERY_CACHE_TTL_MS,
  MAX_DPOP_PROOF_LENGTH,
  MAX_TOKEN_PARAM_KEY_LENGTH,
  MAX_TOKEN_PARAM_VALUE_LENGTH,
  PKCE_CODE_VERIFIER_PATTERN,
  REGISTRATION_METADATA_KEY_PATTERN,
  RESERVED_TOKEN_BODY_PARAM_KEYS,
  SAFE_HTTP_METHODS,
  TOKEN_PARAM_KEY_PATTERN,
} from "./constants";
import type { RequestOptions, SessionState, TokenResponse } from "./types";

export class GuardhouseClientBase {
  protected config: GuardhouseConfig;
  protected baseURL: string;
  protected logger: ReturnType<typeof createGuardhouseLogger>;
  protected requestTimeoutMs: number | null;
  protected discoveryCacheTtlMs: number;
  protected maxAuthorizationHeaderBytes: number;
  protected maxSilentAuthAttempts: number;
  protected sessionStorageKey: string;
  protected sessionState: SessionState | null;
  protected silentAuthAttemptCount: number;
  protected discoveryCache: Map<
    string,
    {
      expiresAt: number;
      data: Record<string, unknown>;
      context?: {
        authority: string;
        clientId: string;
      };
    }
  >;
  protected endpoints: {
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
      enforceNonSpoofableHostname(authorityUrl, "Authority");
    } catch (error) {
      throw new GuardhouseError(
        error instanceof Error ? error.message : "Invalid authority URL",
        "INSECURE_AUTHORITY",
        { cause: error },
      );
    }

    const runtimeWithProcess = globalThis as typeof globalThis & {
      process?: {
        env?: {
          NODE_TLS_REJECT_UNAUTHORIZED?: string;
        };
      };
    };
    if (runtimeWithProcess.process?.env?.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
      throw new GuardhouseError(
        "NODE_TLS_REJECT_UNAUTHORIZED=0 is blocked for security reasons",
        "INSECURE_TLS_OVERRIDE",
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

    if (config.requireDpopForAccessTokenRequests && !config.dpopProofFactory) {
      throw new GuardhouseError(
        "requireDpopForAccessTokenRequests=true requires dpopProofFactory",
        "DPOP_REQUIRED",
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
    const configuredDiscoveryCacheTtlMs =
      config.discoveryCacheTtlMs ?? DEFAULT_DISCOVERY_CACHE_TTL_MS;

    if (
      !Number.isFinite(configuredDiscoveryCacheTtlMs) ||
      configuredDiscoveryCacheTtlMs < 0 ||
      configuredDiscoveryCacheTtlMs > MAX_DISCOVERY_CACHE_TTL_MS
    ) {
      throw new GuardhouseError(
        `discoveryCacheTtlMs must be between 0 and ${MAX_DISCOVERY_CACHE_TTL_MS}`,
        "INVALID_DISCOVERY_CACHE_TTL",
      );
    }

    this.discoveryCacheTtlMs = configuredDiscoveryCacheTtlMs;
    this.maxAuthorizationHeaderBytes =
      config.maxAuthorizationHeaderBytes ?? DEFAULT_MAX_AUTH_HEADER_BYTES;
    this.maxSilentAuthAttempts =
      config.maxSilentAuthAttempts ?? DEFAULT_MAX_SILENT_AUTH_ATTEMPTS;
    this.sessionStorageKey =
      config.sessionStorageKey ?? DEFAULT_SESSION_STORAGE_KEY;
    this.sessionState = null;
    this.silentAuthAttemptCount = 0;
    this.discoveryCache = new Map();

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
      discoveryCacheTtlMs: this.discoveryCacheTtlMs,
      maxAuthorizationHeaderBytes: this.maxAuthorizationHeaderBytes,
      maxSilentAuthAttempts: this.maxSilentAuthAttempts,
      allowUnsafeHttpMethods: Boolean(config.allowUnsafeHttpMethods),
      requireDpopForAccessTokenRequests: Boolean(
        config.requireDpopForAccessTokenRequests,
      ),
      allowsHttp: authorityUrl.protocol === "http:",
      localAuthority: isLocalDevelopmentHostname(authorityUrl.hostname),
      hasStorageAdapter: Boolean(config.storage),
      hasDpopProofFactory: Boolean(config.dpopProofFactory),
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

  protected sanitizeTokenBodyParams(
    params: Record<string, string | null | undefined>,
  ): {
    safeParams: Record<string, string>;
    blockedKeys: string[];
  } {
    const safeParams = Object.create(null) as Record<string, string>;
    const blockedKeys: string[] = [];

    for (const [rawKey, rawValue] of Object.entries(params)) {
      const key = rawKey.trim();

      if (!key) {
        continue;
      }

      if (key.length > MAX_TOKEN_PARAM_KEY_LENGTH) {
        blockedKeys.push(rawKey);
        continue;
      }

      if (isUnsafeObjectKey(key)) {
        blockedKeys.push(rawKey);
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

      if (rawValue.length > MAX_TOKEN_PARAM_VALUE_LENGTH) {
        blockedKeys.push(rawKey);
        continue;
      }

      safeParams[key] = rawValue;
    }

    return { safeParams, blockedKeys };
  }

  protected requireNonEmptyString(value: string, fieldName: string): string {
    if (typeof value !== "string" || value.trim() === "") {
      throw new GuardhouseError(`${fieldName} is required`, "INVALID_REQUEST");
    }

    return value.trim();
  }

  protected validatePkceCodeVerifier(codeVerifier: string): string {
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

  protected assertAllowedHttpMethod(method: string): void {
    if (!ALLOWED_HTTP_METHODS.has(method)) {
      throw new GuardhouseError(
        `HTTP method "${method}" is not supported`,
        "INVALID_HTTP_METHOD",
      );
    }

    if (!this.config.allowUnsafeHttpMethods && !SAFE_HTTP_METHODS.has(method)) {
      throw new GuardhouseError(
        `HTTP method "${method}" is blocked by default to prevent verb tampering; set allowUnsafeHttpMethods=true only if you explicitly require it`,
        "HTTP_METHOD_NOT_ALLOWED",
      );
    }
  }

  protected sanitizeClientRegistrationMetadata(
    metadata: Record<string, unknown>,
  ): {
    safeMetadata: Record<string, unknown>;
    blockedKeys: string[];
  } {
    const safeMetadata = Object.create(null) as Record<string, unknown>;
    const blockedKeys: string[] = [];

    for (const [rawKey, value] of Object.entries(metadata)) {
      const key = rawKey.trim();

      if (!key) {
        continue;
      }

      const normalizedKey = key.toLowerCase();

      if (
        isUnsafeObjectKey(key) ||
        !REGISTRATION_METADATA_KEY_PATTERN.test(key) ||
        BLOCKED_REGISTRATION_METADATA_KEYS.has(normalizedKey) ||
        normalizedKey.startsWith("guardhouse_") ||
        normalizedKey.startsWith("_")
      ) {
        blockedKeys.push(rawKey);
        continue;
      }

      safeMetadata[key] = value;
    }

    return {
      safeMetadata,
      blockedKeys,
    };
  }

  protected normalizePostMessageTargetOrigin(targetOrigin: string): string {
    const normalizedTargetOrigin = this.requireNonEmptyString(
      targetOrigin,
      "targetOrigin",
    );

    if (normalizedTargetOrigin === "*") {
      throw new GuardhouseError(
        "postMessage targetOrigin must be an explicit trusted origin",
        "UNSAFE_POSTMESSAGE_TARGET_ORIGIN",
      );
    }

    let parsedTargetOrigin: URL;

    try {
      parsedTargetOrigin = new URL(normalizedTargetOrigin);
      enforceSecureHttpUrl(parsedTargetOrigin, "postMessage targetOrigin");
      enforceNonSpoofableHostname(
        parsedTargetOrigin,
        "postMessage targetOrigin",
      );
    } catch (error) {
      throw new GuardhouseError(
        "postMessage targetOrigin must be a valid http/https origin",
        "UNSAFE_POSTMESSAGE_TARGET_ORIGIN",
        { cause: error },
      );
    }

    return parsedTargetOrigin.origin;
  }

  protected assertTrustedDiscoveryMetadata(
    discoveryData: Record<string, unknown>,
    authorityUrl: URL,
  ): void {
    const issuer = discoveryData["issuer"];

    if (typeof issuer === "string" && issuer.trim() !== "") {
      try {
        const issuerUrl = new URL(issuer);
        enforceSecureHttpUrl(issuerUrl, "Discovery issuer");
        enforceNonSpoofableHostname(issuerUrl, "Discovery issuer");

        if (issuerUrl.origin !== authorityUrl.origin) {
          throw new GuardhouseError(
            "Discovery issuer origin does not match configured authority",
            "DISCOVERY_ISSUER_MISMATCH",
          );
        }
      } catch (error) {
        if (error instanceof GuardhouseError) {
          throw error;
        }

        throw new GuardhouseError(
          "Discovery issuer is invalid",
          "DISCOVERY_ERROR",
          {
            cause: error,
          },
        );
      }
    }

    for (const key of DISCOVERY_ENDPOINT_KEYS) {
      const endpointValue = discoveryData[key];

      if (endpointValue === undefined || endpointValue === null) {
        continue;
      }

      if (typeof endpointValue !== "string" || endpointValue.trim() === "") {
        throw new GuardhouseError(
          `Discovery metadata field "${key}" must be a non-empty string when present`,
          "DISCOVERY_ERROR",
        );
      }

      let endpointUrl: URL;
      try {
        endpointUrl = new URL(endpointValue);
        enforceSecureHttpUrl(endpointUrl, `Discovery ${key}`);
        enforceNonSpoofableHostname(endpointUrl, `Discovery ${key}`);
      } catch (error) {
        throw new GuardhouseError(
          `Discovery metadata field "${key}" is invalid`,
          "DISCOVERY_ERROR",
          { cause: error },
        );
      }

      if (endpointUrl.origin !== authorityUrl.origin) {
        throw new GuardhouseError(
          `Discovery metadata field "${key}" must remain on the configured authority origin`,
          "DISCOVERY_ENDPOINT_ORIGIN_MISMATCH",
        );
      }
    }
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

  private ensureHeaderWithinLimit(
    headerName: string,
    headerValue: string,
  ): void {
    const byteLength =
      typeof Buffer !== "undefined"
        ? Buffer.byteLength(headerValue, "utf8")
        : typeof TextEncoder === "function"
          ? new TextEncoder().encode(headerValue).length
          : headerValue.length;

    if (byteLength > this.maxAuthorizationHeaderBytes) {
      this.logger.error("Header length exceeds configured limit", {
        headerName,
        byteLength,
        limit: this.maxAuthorizationHeaderBytes,
      });

      throw new GuardhouseError(
        `${headerName} header exceeds maximum allowed size`,
        "HEADER_TOO_LARGE",
      );
    }
  }

  private async createDpopProof(
    method: string,
    url: string,
    accessToken: string | undefined,
    skipDpopProof: boolean,
  ): Promise<string | null> {
    if (!this.config.dpopProofFactory || skipDpopProof) {
      return null;
    }

    const proof = await this.config.dpopProofFactory({
      method,
      url,
      accessToken,
    });

    if (typeof proof !== "string" || proof.trim() === "") {
      throw new GuardhouseError(
        "dpopProofFactory returned an invalid proof",
        "INVALID_DPOP_PROOF",
      );
    }

    const normalizedProof = proof.trim();
    if (normalizedProof.length > MAX_DPOP_PROOF_LENGTH) {
      throw new GuardhouseError(
        "DPoP proof is too large",
        "INVALID_DPOP_PROOF",
      );
    }

    this.ensureHeaderWithinLimit("DPoP", normalizedProof);
    return normalizedProof;
  }

  protected buildSessionStateFromTokenResponse(
    tokenResponse: TokenResponse,
  ): SessionState {
    return {
      accessToken: tokenResponse.access_token,
      tokenType: tokenResponse.token_type,
      expiresAt: Date.now() + tokenResponse.expires_in * 1000,
      scope: tokenResponse.scope,
      idToken: tokenResponse.id_token,
      hasRefreshToken: Boolean(tokenResponse.refresh_token),
    };
  }

  protected resetSilentAuthAttemptCounter(): void {
    this.silentAuthAttemptCount = 0;
  }

  protected maybeClearSensitiveCallbackUrl(
    callbackUrl: string,
    sanitizedUrl: string,
  ): void {
    const hasFragment = callbackUrl.includes("#");

    if (!hasFragment || sanitizedUrl === callbackUrl) {
      return;
    }

    const runtime = globalThis as typeof globalThis & {
      history?: {
        replaceState?: (data: unknown, unused: string, url?: string) => void;
      };
    };

    const replaceState = runtime.history?.replaceState;
    if (typeof replaceState !== "function") {
      return;
    }

    try {
      replaceState.call(runtime.history, null, "", sanitizedUrl);
    } catch {
      // noop
    }
  }

  private parseScope(scope: string | undefined): Set<string> {
    if (!scope) {
      return new Set<string>();
    }

    return new Set(
      scope
        .split(/\s+/)
        .map((value) => value.trim())
        .filter((value) => value.length > 0),
    );
  }

  protected assertNoScopeEscalation(
    requestedScope: string | undefined,
    grantedScope: string | undefined,
  ): void {
    if (!requestedScope) {
      return;
    }

    const requested = this.parseScope(requestedScope);

    if (!grantedScope) {
      this.logger.warn(
        "Token response did not include scope; unable to verify full scope consistency",
        {
          requestedScope,
        },
      );
      return;
    }

    const granted = this.parseScope(grantedScope);
    const unexpected: string[] = [];
    const missing: string[] = [];

    for (const scope of granted) {
      if (!requested.has(scope)) {
        unexpected.push(scope);
      }
    }

    for (const scope of requested) {
      if (!granted.has(scope)) {
        missing.push(scope);
      }
    }

    if (unexpected.length > 0) {
      this.logger.error("Token response scope escalation detected", {
        requestedScope,
        grantedScope,
        unexpectedScopes: unexpected,
      });

      throw new GuardhouseError(
        "Token response included scopes that were not explicitly requested",
        "SCOPE_ESCALATION_DETECTED",
      );
    }

    if (missing.length > 0) {
      this.logger.warn("Token response scope narrowing detected", {
        requestedScope,
        grantedScope,
        missingScopes: missing,
      });

      if (!this.config.allowScopeNarrowing) {
        throw new GuardhouseError(
          "Token response is missing one or more requested scopes",
          "SCOPE_NARROWING_DETECTED",
        );
      }
    }
  }

  protected getFrameAncestorsDirective(cspHeader: string): string | undefined {
    const directives = cspHeader
      .split(";")
      .map((directive) => directive.trim())
      .filter((directive) => directive.length > 0);

    const frameAncestors = directives.find((directive) =>
      directive.toLowerCase().startsWith("frame-ancestors"),
    );

    return frameAncestors;
  }

  protected assertRecentUserInteraction(operationName: string): void {
    if (!this.config.requireUserInteractionForSensitiveOperations) {
      return;
    }

    const runtime = globalThis as typeof globalThis & {
      navigator?: {
        userActivation?: {
          isActive?: boolean;
        };
      };
    };

    const isActive = runtime.navigator?.userActivation?.isActive;
    if (isActive === false) {
      throw new GuardhouseError(
        `${operationName} requires recent user interaction`,
        "USER_INTERACTION_REQUIRED",
      );
    }
  }

  protected assertAllowedPostLogoutRedirect(redirectUri: string): void {
    const allowlist = this.config.allowedPostLogoutRedirectUris;

    if (!allowlist || allowlist.length === 0) {
      return;
    }

    const normalizedRedirectUri = validateAndNormalizeRedirectUri(redirectUri);
    const isAllowed = allowlist.some(
      (allowedUri) =>
        validateAndNormalizeRedirectUri(allowedUri) === normalizedRedirectUri,
    );

    if (!isAllowed) {
      throw new GuardhouseError(
        "post_logout_redirect_uri is not in allowedPostLogoutRedirectUris",
        "UNSAFE_LOGOUT_REDIRECT_URI",
      );
    }
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

  protected buildRequestUrl(endpoint: string): string {
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
    this.assertAllowedHttpMethod(method);

    this.logger.debug("HTTP request", {
      method,
      url: sanitizeUrlForLogs(url),
    });

    const headers = new Headers(options.headers);
    const dpopProof = await this.createDpopProof(
      method,
      url,
      options.token,
      Boolean(options.skipDpopProof),
    );

    if (
      options.token &&
      this.config.requireDpopForAccessTokenRequests &&
      !dpopProof
    ) {
      throw new GuardhouseError(
        "DPoP proof is required for access-token authenticated requests",
        "DPOP_REQUIRED",
      );
    }

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

    if (dpopProof) {
      headers.set("DPoP", dpopProof);
    }

    if (options.token && !options.skipAuthHeader) {
      const authScheme = dpopProof ? "DPoP" : "Bearer";
      const authorizationValue = `${authScheme} ${options.token}`;
      this.ensureHeaderWithinLimit("Authorization", authorizationValue);
      headers.set("Authorization", authorizationValue);
    }

    if (!options.token && !options.skipAuthHeader && this.config.clientSecret) {
      const authorizationValue = this.buildBasicAuthHeader();
      this.ensureHeaderWithinLimit("Authorization", authorizationValue);
      headers.set("Authorization", authorizationValue);
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
        cache: options.cacheMode,
        signal: abortContext.signal ?? options.signal,
      });

      this.logger.debug("HTTP response received", {
        method,
        url: sanitizeUrlForLogs(url),
        status: response.status,
      });

      if (!response.ok) {
        const errorData = await this.parseErrorResponse(response);
        const errorCode =
          typeof errorData.error === "string"
            ? errorData.error
            : "server_error";
        const errorMessage =
          typeof errorData.error === "string"
            ? `Request failed (${errorCode})`
            : `Request failed with status ${response.status}`;

        this.logger.error("HTTP request failed", {
          status: response.status,
          statusText: response.statusText,
          errorCode,
        });
        throw new GuardhouseError(errorMessage, errorCode, response.status);
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
      throw new GuardhouseError("Network request failed", "NETWORK_ERROR", {
        cause: error,
      });
    } finally {
      abortContext.cleanup();
    }
  }

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
