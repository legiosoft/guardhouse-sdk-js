/**
 * Guardhouse Configuration
 *
 * SECURITY ARCHITECTURE:
 *
 * 1. Client-Server Model:
 *    - Client ID identifies your application
 *    - Client Secret used for confidential clients (backend services)
 *    - Public clients (mobile apps, SPAs) don't use secrets
 *
 * 2. URL Construction:
 *    - All URLs are constructed from authority base
 *    - Prevents SSRF/URL injection
 *    - Ensures HTTPS (in production)
 *
 * 3. Configuration Validation:
 *    - Authority must be HTTPS in production
 *    - Client ID is required
 *    - Client Secret optional (public clients don't need it)
 */

import { createGuardhouseLogger } from "./debug";
import {
  enforceNonSpoofableHostname,
  enforceSecureHttpUrl,
  isLocalDevelopmentHostname,
  sanitizeUrlForLogs,
  validateAndNormalizeRedirectUri,
} from "./security";

export interface DPoPProofContext {
  method: string;
  url: string;
  accessToken?: string;
}

export type DPoPProofFactory = (
  context: DPoPProofContext,
) => string | Promise<string>;

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
  discoveryCacheTtlMs?: number;
  allowUnsafeHttpMethods?: boolean;
  requireDpopForAccessTokenRequests?: boolean;
  allowScopeNarrowing?: boolean;
  maxAuthorizationHeaderBytes?: number;
  maxSilentAuthAttempts?: number;
  requireUserInteractionForSensitiveOperations?: boolean;
  allowedPostLogoutRedirectUris?: string[];
  sessionStorageKey?: string;
  dpopProofFactory?: DPoPProofFactory;
  storage?: StorageAdapter;
  debug?: boolean;
}

export interface StorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

const ABSOLUTE_URI_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:/;

function isAbsoluteUri(value: string): boolean {
  return ABSOLUTE_URI_PATTERN.test(value);
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

export class ConfigValidationError extends GuardhouseError {
  constructor(message: string) {
    super(message, "CONFIG_ERROR");
    this.name = "ConfigValidationError";
  }
}

/**
 * Validate Guardhouse configuration
 *
 * SECURITY: Prevents misconfiguration that could lead to security issues
 *
 * @param config - Configuration to validate
 * @throws {ConfigValidationError} If configuration is invalid
 */
export function validateConfig(config: GuardhouseConfig): void {
  const logger = createGuardhouseLogger("Config", config.debug);
  const hasClientSecret = Boolean(config.clientSecret);

  logger.debug("Validating configuration", {
    authority: sanitizeUrlForLogs(config.authority),
    hasClientSecret,
  });

  if (typeof config.authority !== "string" || config.authority.trim() === "") {
    throw new ConfigValidationError("Authority is required");
  }

  if (typeof config.clientId !== "string" || config.clientId.trim() === "") {
    throw new ConfigValidationError("Client ID is required");
  }

  if (
    config.requestTimeoutMs !== undefined &&
    (!Number.isFinite(config.requestTimeoutMs) || config.requestTimeoutMs < 0)
  ) {
    throw new ConfigValidationError(
      "requestTimeoutMs must be a non-negative number",
    );
  }

  if (
    config.discoveryCacheTtlMs !== undefined &&
    (!Number.isFinite(config.discoveryCacheTtlMs) ||
      config.discoveryCacheTtlMs < 0)
  ) {
    throw new ConfigValidationError(
      "discoveryCacheTtlMs must be a non-negative number",
    );
  }

  if (
    config.maxAuthorizationHeaderBytes !== undefined &&
    (!Number.isFinite(config.maxAuthorizationHeaderBytes) ||
      config.maxAuthorizationHeaderBytes < 512)
  ) {
    throw new ConfigValidationError(
      "maxAuthorizationHeaderBytes must be at least 512",
    );
  }

  if (
    config.sessionStorageKey !== undefined &&
    (typeof config.sessionStorageKey !== "string" ||
      config.sessionStorageKey.trim() === "")
  ) {
    throw new ConfigValidationError(
      "sessionStorageKey must be a non-empty string",
    );
  }

  if (
    config.dpopProofFactory !== undefined &&
    typeof config.dpopProofFactory !== "function"
  ) {
    throw new ConfigValidationError("dpopProofFactory must be a function");
  }

  if (
    config.allowUnsafeHttpMethods !== undefined &&
    typeof config.allowUnsafeHttpMethods !== "boolean"
  ) {
    throw new ConfigValidationError("allowUnsafeHttpMethods must be a boolean");
  }

  if (
    config.requireDpopForAccessTokenRequests !== undefined &&
    typeof config.requireDpopForAccessTokenRequests !== "boolean"
  ) {
    throw new ConfigValidationError(
      "requireDpopForAccessTokenRequests must be a boolean",
    );
  }

  if (
    config.allowScopeNarrowing !== undefined &&
    typeof config.allowScopeNarrowing !== "boolean"
  ) {
    throw new ConfigValidationError("allowScopeNarrowing must be a boolean");
  }

  if (
    config.maxSilentAuthAttempts !== undefined &&
    (!Number.isInteger(config.maxSilentAuthAttempts) ||
      config.maxSilentAuthAttempts < 1 ||
      config.maxSilentAuthAttempts > 20)
  ) {
    throw new ConfigValidationError(
      "maxSilentAuthAttempts must be an integer between 1 and 20",
    );
  }

  if (
    config.requireUserInteractionForSensitiveOperations !== undefined &&
    typeof config.requireUserInteractionForSensitiveOperations !== "boolean"
  ) {
    throw new ConfigValidationError(
      "requireUserInteractionForSensitiveOperations must be a boolean",
    );
  }

  if (config.allowedPostLogoutRedirectUris !== undefined) {
    if (!Array.isArray(config.allowedPostLogoutRedirectUris)) {
      throw new ConfigValidationError(
        "allowedPostLogoutRedirectUris must be an array",
      );
    }

    for (const uri of config.allowedPostLogoutRedirectUris) {
      if (typeof uri !== "string" || uri.trim() === "") {
        throw new ConfigValidationError(
          "allowedPostLogoutRedirectUris must contain non-empty strings",
        );
      }

      try {
        validateAndNormalizeRedirectUri(uri);
      } catch (error) {
        throw new ConfigValidationError(
          `allowedPostLogoutRedirectUris contains an invalid URI: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }
  }

  try {
    const url = new URL(config.authority);

    enforceSecureHttpUrl(url, "Authority");
    enforceNonSpoofableHostname(url, "Authority");

    const endpointConfigs: Array<[string, string | undefined]> = [
      ["tokenEndpoint", config.tokenEndpoint],
      ["userInfoEndpoint", config.userInfoEndpoint],
      ["introspectionEndpoint", config.introspectionEndpoint],
      ["revocationEndpoint", config.revocationEndpoint],
    ];

    for (const [endpointName, endpointValue] of endpointConfigs) {
      if (typeof endpointValue !== "string" || endpointValue.trim() === "") {
        continue;
      }

      const normalizedEndpoint = endpointValue.trim();
      if (!isAbsoluteUri(normalizedEndpoint)) {
        continue;
      }

      let endpointUrl: URL;
      try {
        endpointUrl = new URL(normalizedEndpoint);
      } catch {
        throw new ConfigValidationError(
          `${endpointName} must be a valid absolute URL`,
        );
      }

      try {
        enforceSecureHttpUrl(endpointUrl, endpointName);
        enforceNonSpoofableHostname(endpointUrl, endpointName);
      } catch (error) {
        throw new ConfigValidationError(
          `${endpointName} is invalid: ${error instanceof Error ? error.message : String(error)}`,
        );
      }
    }

    // SECURITY: Prevent SSRF (Server-Side Request Forgery)
    if (config.clientSecret && !isLocalDevelopmentHostname(url.hostname)) {
      logger.warn(
        "Using client_secret with non-localhost authority. Ensure you trust this server.",
      );
    }

    logger.debug("Configuration validated successfully", {
      authority: sanitizeUrlForLogs(url.toString()),
      hasClientSecret,
      requestTimeoutMs: config.requestTimeoutMs,
      discoveryCacheTtlMs: config.discoveryCacheTtlMs,
      allowUnsafeHttpMethods: config.allowUnsafeHttpMethods,
      requireDpopForAccessTokenRequests:
        config.requireDpopForAccessTokenRequests,
      allowScopeNarrowing: config.allowScopeNarrowing,
      maxAuthorizationHeaderBytes: config.maxAuthorizationHeaderBytes,
      maxSilentAuthAttempts: config.maxSilentAuthAttempts,
      requireUserInteractionForSensitiveOperations:
        config.requireUserInteractionForSensitiveOperations,
      allowedPostLogoutRedirectUriCount:
        config.allowedPostLogoutRedirectUris?.length ?? 0,
      hasDpopProofFactory: Boolean(config.dpopProofFactory),
      clientSecretRedacted: hasClientSecret,
    });
  } catch (error) {
    if (error instanceof ConfigValidationError) {
      throw error;
    }

    logger.error("Configuration validation failed", {
      error: error instanceof Error ? error.message : String(error),
    });

    throw new ConfigValidationError(`Invalid authority URL: ${error}`);
  }
}

/**
 * Construct URL safely
 *
 * SECURITY: Prevents URL injection and SSRF
 */
export function buildUrl(
  config: GuardhouseConfig,
  path: string,
  params: Record<string, string> = {},
): string {
  const logger = createGuardhouseLogger("Config", config.debug);

  logger.debug("Building URL", {
    path,
    queryParamCount: Object.keys(params).length,
  });

  try {
    if (typeof path !== "string" || path.trim() === "") {
      throw new GuardhouseError("Path is required", "URL_BUILD_ERROR");
    }

    const normalizedInputPath = path.trim();

    if (/^https?:\/\//i.test(normalizedInputPath)) {
      throw new GuardhouseError(
        "Path must be relative to the configured authority",
        "URL_BUILD_ERROR",
      );
    }

    if (normalizedInputPath.includes("..")) {
      throw new GuardhouseError(
        "Path must not contain directory traversal sequences",
        "URL_BUILD_ERROR",
      );
    }

    if (normalizedInputPath.includes("//")) {
      throw new GuardhouseError(
        "Path must not contain repeated slash segments",
        "URL_BUILD_ERROR",
      );
    }

    const url = new URL(config.authority);
    const normalizedPath = normalizedInputPath.startsWith("/")
      ? normalizedInputPath
      : `/${normalizedInputPath}`;
    const basePath = url.pathname.replace(/\/+$/, "");

    url.pathname = `${basePath}${normalizedPath}`;

    // Add query parameters
    Object.entries(params).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });

    const builtUrl = url.toString();
    logger.debug("Built URL", {
      path,
      queryParamCount: Object.keys(params).length,
      url: sanitizeUrlForLogs(builtUrl),
    });

    return builtUrl;
  } catch (error) {
    logger.error("Failed to build URL", {
      path,
      error: error instanceof Error ? error.message : String(error),
    });

    throw new GuardhouseError(
      `Failed to build URL: ${error instanceof Error ? error.message : "Unknown error"}`,
      "URL_BUILD_ERROR",
    );
  }
}
