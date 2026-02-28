import { GuardhouseError as CoreGuardhouseError } from "@guardhouse/core";

export type GuardhouseErrorCode =
  | "CONFIG_ERROR"
  | "BROWSER_ERROR"
  | "PASSKEY_ERROR"
  | "STATE_MISMATCH"
  | "INVALID_CALLBACK"
  | "TOKEN_RESPONSE_ERROR"
  | "NETWORK_ERROR"
  | "TOKEN_REQUEST_FAILED"
  | "MISSING_REFRESH_TOKEN"
  | "PASSKEY_ADAPTER_MISSING"
  | "BROWSER_ADAPTER_MISSING"
  | "REVOCATION_FAILED"
  | "STORAGE_ERROR";

/**
 * Base error for all Guardhouse SDK failures.
 */
export class GuardhouseError extends CoreGuardhouseError {
  public readonly details?: unknown;

  constructor(
    message: string,
    public readonly code: GuardhouseErrorCode,
    public readonly statusCode?: number,
    details?: unknown,
  ) {
    super(message, code, { statusCode, cause: details });

    this.name = "GuardhouseError";
    this.details = details;
  }
}

/**
 * Authentication and protocol-level failure.
 */
export class GuardhouseAuthError extends GuardhouseError {
  constructor(
    message: string,
    code: GuardhouseErrorCode,
    statusCode?: number,
    details?: unknown,
  ) {
    super(message, code, statusCode, details);
    this.name = "GuardhouseAuthError";
  }
}

/**
 * HTTP/network transport failure.
 */
export class GuardhouseNetworkError extends GuardhouseError {
  constructor(message: string, details?: unknown) {
    super(message, "NETWORK_ERROR", undefined, details);
    this.name = "GuardhouseNetworkError";
  }
}

/**
 * Storage layer failure.
 */
export class GuardhouseStorageError extends GuardhouseError {
  constructor(message: string, details?: unknown) {
    super(message, "STORAGE_ERROR", undefined, details);
    this.name = "GuardhouseStorageError";
  }
}

/**
 * Configuration or dependency injection error.
 */
export class GuardhouseConfigurationError extends GuardhouseError {
  constructor(message: string, details?: unknown) {
    super(message, "CONFIG_ERROR", undefined, details);
    this.name = "GuardhouseConfigurationError";
  }
}

/**
 * Backward-compatible alias preserved for existing consumers.
 */
export class GuardhouseClientError extends GuardhouseAuthError {}
