import { parseOAuthCallbackUrl } from "@guardhouse/core";
import {
  createRedirectUriDescriptor,
  matchesRedirectUri,
  type RedirectUriDescriptor,
} from "./idToken";
import {
  GuardhouseAuthError,
  GuardhouseConfigurationError,
} from "../types/errors";

/**
 * Converts unknown error values to readable strings.
 */
export function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

/**
 * Normalizes empty strings to undefined.
 */
export function trimToUndefined(
  value: string | null | undefined,
): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

/**
 * Parses positive integers from numbers or numeric strings.
 */
export function parsePositiveInteger(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isInteger(value) && value > 0) {
    return value;
  }

  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10);

    if (Number.isInteger(parsed) && parsed > 0) {
      return parsed;
    }
  }

  return undefined;
}

/**
 * Removes undefined/null/empty string fields from object payloads.
 */
export function compactRecord(
  input: Record<string, unknown>,
): Record<string, unknown> {
  const output: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(input)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }

    output[key] = value;
  }

  return output;
}

/**
 * Validates and normalizes authority URL.
 */
export function sanitizeAuthority(authority: string): string {
  const parsed = new URL(authority);
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");

  if (parsed.pathname === "") {
    parsed.pathname = "/";
  }

  return parsed.toString();
}

/**
 * Resolves a relative/absolute endpoint against authority.
 */
export function resolveEndpoint(authority: string, endpoint: string): string {
  const normalizedEndpoint = trimToUndefined(endpoint);

  if (!normalizedEndpoint) {
    throw new GuardhouseConfigurationError("Endpoint cannot be empty");
  }

  try {
    return new URL(normalizedEndpoint, authority).toString();
  } catch (error) {
    throw new GuardhouseConfigurationError(
      `Invalid endpoint URL: ${toErrorMessage(error)}`,
      error,
    );
  }
}

/**
 * Creates a reusable redirect URI matcher descriptor.
 */
export function createRedirectMatcher(
  redirectUri: string,
): RedirectUriDescriptor {
  return createRedirectUriDescriptor(redirectUri);
}

/**
 * Checks whether callback URL matches the configured redirect URI descriptor.
 */
export function isMatchingRedirectUri(
  callbackUrl: string,
  descriptor: RedirectUriDescriptor,
): boolean {
  return matchesRedirectUri(callbackUrl, descriptor);
}

/**
 * Parses and validates OAuth callback URL.
 */
export function parseAuthorizationCallback(
  callbackUrl: string,
  redirectUriDescriptor: RedirectUriDescriptor,
): { code: string; state: string } {
  if (!isMatchingRedirectUri(callbackUrl, redirectUriDescriptor)) {
    throw new GuardhouseAuthError(
      "Callback URL does not match configured redirect URI",
      "INVALID_CALLBACK",
    );
  }

  const callback = parseOAuthCallbackUrl(callbackUrl);

  if (callback.error) {
    throw new GuardhouseAuthError(
      `OAuth callback returned an error: ${callback.errorDescription ?? callback.error}`,
      "INVALID_CALLBACK",
      undefined,
      callback,
    );
  }

  if (!callback.code || !callback.state) {
    throw new GuardhouseAuthError(
      "OAuth callback is missing required code/state parameters",
      "INVALID_CALLBACK",
      undefined,
      callback,
    );
  }

  return {
    code: callback.code,
    state: callback.state,
  };
}
