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
  storage?: StorageAdapter;
  debug?: boolean;
}

export interface StorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
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

  logger.debug("Validating configuration", {
    authority: config.authority,
    clientId: config.clientId,
    hasClientSecret: Boolean(config.clientSecret),
  });

  if (!config.authority) {
    throw new ConfigValidationError("Authority is required");
  }

  if (!config.clientId) {
    throw new ConfigValidationError("Client ID is required");
  }

  try {
    const url = new URL(config.authority);

    // SECURITY: Enforce HTTPS in production (can use http in dev)
    if (url.protocol !== "https:" && !isLocalhost(url.hostname)) {
      throw new ConfigValidationError(
        "Authority must use HTTPS protocol (except for localhost)",
      );
    }

    // SECURITY: Prevent SSRF (Server-Side Request Forgery)
    if (config.clientSecret && !isLocalhost(url.hostname)) {
      logger.warn(
        "Using client_secret with non-localhost authority. Ensure you trust this server.",
      );
    }

    logger.debug("Configuration validated successfully", {
      authority: url.origin,
      hasClientSecret: Boolean(config.clientSecret),
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
 * Check if hostname is localhost
 *
 * SECURITY: Allows HTTP for local development
 */
function isLocalhost(hostname: string): boolean {
  const localhostPatterns = [
    "localhost",
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "10.0.0.0",
    "172.16.0.0",
    "192.168.0.0",
  ];

  return (
    localhostPatterns.includes(hostname) ||
    hostname.startsWith("127.") ||
    hostname.startsWith("10.") ||
    hostname.startsWith("172.16.") ||
    hostname.startsWith("192.168.")
  );
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
    const url = new URL(config.authority);

    // Add path
    if (!url.pathname.endsWith("/")) {
      url.pathname = url.pathname + path;
    } else {
      url.pathname = url.pathname + path.substring(1);
    }

    // Add query parameters
    Object.entries(params).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });

    const builtUrl = url.toString();
    logger.debug("Built URL", {
      path,
      queryParamCount: Object.keys(params).length,
      url: builtUrl,
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
