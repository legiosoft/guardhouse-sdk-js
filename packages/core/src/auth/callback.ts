import { isUnsafeObjectKey } from "../security";

import {
  AUTHORIZATION_URL_SENSITIVE_KEYS,
  MAX_CALLBACK_URL_LENGTH,
  OAUTH_CALLBACK_SENSITIVE_KEYS,
  UNSAFE_FRAGMENT_VALUE_PATTERN,
} from "./constants";
import type { OAuthCallbackResult } from "./types";

const MAX_EXPIRES_IN_SECONDS = 2_147_483_647;
const URL_BYPASS_CHAR_PATTERN = /[\\\u0000-\u001F\u007F]/g;

type IPv4Octets = [number, number, number, number];

function hasAnyParams(params: URLSearchParams): boolean {
  return params.keys().next().done === false;
}

function collectSensitiveParamKeys(
  params: URLSearchParams,
  sensitiveKeys: Set<string>,
): string[] {
  const keysToDelete: string[] = [];

  for (const key of params.keys()) {
    if (sensitiveKeys.has(key.toLowerCase())) {
      keysToDelete.push(key);
    }
  }

  return keysToDelete;
}

function getHashParams(url: URL): URLSearchParams | undefined {
  if (!url.hash) {
    return undefined;
  }

  return new URLSearchParams(url.hash.replace(/^#/, ""));
}

function hasCallbackParam(
  searchParams: URLSearchParams,
  hashParams: URLSearchParams | undefined,
  key: string,
): boolean {
  const lowerKey = key.toLowerCase();

  for (const currentKey of searchParams.keys()) {
    if (currentKey.toLowerCase() === lowerKey) {
      return true;
    }
  }

  if (hashParams) {
    for (const currentKey of hashParams.keys()) {
      if (currentKey.toLowerCase() === lowerKey) {
        return true;
      }
    }
  }

  return false;
}

function isErrorOnlyCallback(
  searchParams: URLSearchParams,
  hashParams: URLSearchParams | undefined,
): boolean {
  return (
    hasCallbackParam(searchParams, hashParams, "error") &&
    !hasCallbackParam(searchParams, hashParams, "code") &&
    !hasCallbackParam(searchParams, hashParams, "access_token") &&
    !hasCallbackParam(searchParams, hashParams, "id_token") &&
    !hasCallbackParam(searchParams, hashParams, "state")
  );
}

function usesAmbiguousIPv4Notation(uri: string): boolean {
  const authorityMatch = uri.match(/^[A-Za-z][A-Za-z0-9+.-]*:\/\/([^/?#]*)/);
  if (!authorityMatch) {
    return false;
  }

  const authority = authorityMatch[1];
  const hostWithOptionalPort = authority.includes("@")
    ? authority.slice(authority.lastIndexOf("@") + 1)
    : authority;

  if (!hostWithOptionalPort || hostWithOptionalPort.startsWith("[")) {
    return false;
  }

  const host = hostWithOptionalPort.replace(/:\d{1,5}$/, "").toLowerCase();
  if (!host) {
    return false;
  }

  if (/^0x[0-9a-f]+$/i.test(host) || /^\d+$/.test(host)) {
    return true;
  }

  const segments = host.split(".");
  if (segments.length !== 4) {
    return false;
  }

  if (
    !segments.every((segment) => /^(?:\d+|0x[0-9a-f]+|0[0-7]+)$/i.test(segment))
  ) {
    return false;
  }

  return segments.some(
    (segment) =>
      /^0x[0-9a-f]+$/i.test(segment) ||
      (segment.length > 1 && segment.startsWith("0")),
  );
}

function parseIPv4Octets(hostname: string): IPv4Octets | undefined {
  const segments = hostname.split(".");
  if (segments.length !== 4) {
    return undefined;
  }

  const octets: number[] = [];
  for (const segment of segments) {
    if (!/^\d{1,3}$/.test(segment)) {
      return undefined;
    }

    if (segment.length > 1 && segment.startsWith("0")) {
      return undefined;
    }

    const parsed = Number(segment);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > 255) {
      return undefined;
    }

    octets.push(parsed);
  }

  return [octets[0], octets[1], octets[2], octets[3]];
}

function isInternalIPv4Octets([first, second]: IPv4Octets): boolean {
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  );
}

function isInternalIPv4Address(hostname: string): boolean {
  const octets = parseIPv4Octets(hostname);
  return octets ? isInternalIPv4Octets(octets) : false;
}

function isInternalIPv6Address(hostname: string): boolean {
  const withoutBrackets =
    hostname.startsWith("[") && hostname.endsWith("]")
      ? hostname.slice(1, -1)
      : hostname;
  const normalized = withoutBrackets.toLowerCase();

  if (!normalized.includes(":")) {
    return false;
  }

  if (normalized === "::" || normalized === "::1") {
    return true;
  }

  if (/^(fc|fd)[0-9a-f:]*$/.test(normalized)) {
    return true;
  }

  if (/^fe[89ab][0-9a-f:]*$/.test(normalized)) {
    return true;
  }

  const mappedIPv4Match = normalized.match(
    /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/,
  );
  if (mappedIPv4Match) {
    return isInternalIPv4Address(mappedIPv4Match[1]);
  }

  const mappedHexMatch = normalized.match(
    /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/,
  );
  if (!mappedHexMatch) {
    return false;
  }

  const high = Number.parseInt(mappedHexMatch[1], 16);
  const low = Number.parseInt(mappedHexMatch[2], 16);
  if (!Number.isFinite(high) || !Number.isFinite(low)) {
    return false;
  }

  const octets: IPv4Octets = [
    (high >> 8) & 0xff,
    high & 0xff,
    (low >> 8) & 0xff,
    low & 0xff,
  ];
  return isInternalIPv4Octets(octets);
}

function isInternalHostname(hostnameRaw: string): boolean {
  const normalized = hostnameRaw.toLowerCase().replace(/\.+$/, "");

  if (normalized === "localhost" || normalized.endsWith(".localhost")) {
    return true;
  }

  if (normalized.endsWith(".local")) {
    return true;
  }

  return isInternalIPv4Address(normalized) || isInternalIPv6Address(normalized);
}

function parseAndValidateErrorUri(
  errorUriRaw: string | null,
): string | undefined {
  if (errorUriRaw === null) {
    return undefined;
  }

  const normalizedErrorUri = errorUriRaw.trim();
  if (normalizedErrorUri === "") {
    return undefined;
  }

  const sanitizedForParsing = normalizedErrorUri
    .replace(URL_BYPASS_CHAR_PATTERN, "")
    .trim();
  if (sanitizedForParsing === "") {
    throw new Error("OAuth callback contains an invalid error_uri value");
  }

  if (usesAmbiguousIPv4Notation(sanitizedForParsing)) {
    throw new Error("OAuth callback contains an unsafe error_uri value");
  }

  let parsedErrorUri: URL;
  try {
    parsedErrorUri = new URL(sanitizedForParsing);
  } catch {
    throw new Error("OAuth callback contains an invalid error_uri value");
  }

  const protocol = parsedErrorUri.protocol.toLowerCase();
  if (
    protocol === "javascript:" ||
    protocol === "data:" ||
    protocol === "file:"
  ) {
    throw new Error("OAuth callback contains an unsafe error_uri value");
  }

  if (protocol !== "https:") {
    throw new Error("OAuth callback contains an invalid error_uri value");
  }

  const hostname = parsedErrorUri.hostname;
  if (isInternalHostname(hostname)) {
    throw new Error("OAuth callback contains an unsafe error_uri value");
  }

  return parsedErrorUri.toString();
}

function mergeCallbackParams(url: URL): URLSearchParams {
  const merged = new URLSearchParams();
  const seenKeys = new Set<string>();

  const appendUnique = (params: URLSearchParams): void => {
    const keys = new Set(params.keys());

    for (const key of keys) {
      const values = params.getAll(key);
      const normalizedKey = key.toLowerCase();

      if (values.length > 1 || seenKeys.has(normalizedKey)) {
        throw new Error(
          `OAuth callback contains duplicate parameter values for "${key}"`,
        );
      }

      const value = values[0] ?? "";
      merged.set(key, value);
      seenKeys.add(normalizedKey);
    }
  };

  const searchHasParams = hasAnyParams(url.searchParams);
  const hashParams = getHashParams(url);
  const hashHasParams = hashParams ? hasAnyParams(hashParams) : false;

  if (searchHasParams && hashHasParams) {
    throw new Error(
      "OAuth callback must not contain parameters in both query and fragment",
    );
  }

  if (searchHasParams) {
    appendUnique(url.searchParams);
  }

  if (hashParams && hashHasParams) {
    for (const value of hashParams.values()) {
      if (UNSAFE_FRAGMENT_VALUE_PATTERN.test(value)) {
        throw new Error("OAuth callback fragment contains unsafe content");
      }
    }

    appendUnique(hashParams);
  }

  return merged;
}

export function sanitizeOAuthCallbackUrl(callbackUrl: string): string {
  const url = new URL(callbackUrl);
  const hashParams = getHashParams(url);

  if (isErrorOnlyCallback(url.searchParams, hashParams)) {
    url.search = "";
    url.hash = "";
    url.username = "";
    url.password = "";
    return url.toString();
  }

  const searchKeysToDelete = collectSensitiveParamKeys(
    url.searchParams,
    OAUTH_CALLBACK_SENSITIVE_KEYS,
  );
  for (const key of searchKeysToDelete) {
    url.searchParams.delete(key);
  }

  if (hashParams) {
    const hashKeysToDelete = collectSensitiveParamKeys(
      hashParams,
      OAUTH_CALLBACK_SENSITIVE_KEYS,
    );
    for (const key of hashKeysToDelete) {
      hashParams.delete(key);
    }

    const sanitizedHash = hashParams.toString();
    url.hash = sanitizedHash ? `#${sanitizedHash}` : "";
  }

  return url.toString();
}

export function sanitizeAuthorizationUrlForHistory(authUrl: string): string {
  const parsed = new URL(authUrl);

  const searchKeysToDelete = collectSensitiveParamKeys(
    parsed.searchParams,
    AUTHORIZATION_URL_SENSITIVE_KEYS,
  );
  for (const key of searchKeysToDelete) {
    parsed.searchParams.delete(key);
  }

  parsed.hash = "";
  parsed.password = "";
  parsed.username = "";

  return parsed.toString();
}

export function parseOAuthCallbackUrl(
  callbackUrl: string,
): OAuthCallbackResult {
  if (typeof callbackUrl !== "string" || callbackUrl.trim() === "") {
    throw new Error("callbackUrl is required");
  }

  if (callbackUrl.length > MAX_CALLBACK_URL_LENGTH) {
    throw new Error("callbackUrl exceeds maximum supported length");
  }

  const parsedUrl = new URL(callbackUrl);
  const mergedParams = mergeCallbackParams(parsedUrl);

  const params = Object.create(null) as Record<string, string>;
  mergedParams.forEach((value, key) => {
    const normalizedKey = key.toLowerCase();

    if (isUnsafeObjectKey(normalizedKey)) {
      throw new Error(`OAuth callback contains unsafe parameter key "${key}"`);
    }

    params[normalizedKey] = value;
  });

  const errorUri = parseAndValidateErrorUri(params["error_uri"] ?? null);

  const expiresInRaw = params["expires_in"];
  let expiresIn: number | undefined;
  if (expiresInRaw !== undefined && expiresInRaw !== "") {
    const parsedExpiresIn = Number(expiresInRaw);
    if (
      !Number.isFinite(parsedExpiresIn) ||
      !Number.isInteger(parsedExpiresIn) ||
      parsedExpiresIn <= 0 ||
      parsedExpiresIn > MAX_EXPIRES_IN_SECONDS
    ) {
      throw new Error("OAuth callback contains an invalid expires_in value");
    }
    expiresIn = parsedExpiresIn;
  }

  return {
    code: params["code"] ?? undefined,
    state: params["state"] ?? undefined,
    iss: params["iss"] ?? undefined,
    sessionState: params["session_state"] ?? undefined,
    response: params["response"] ?? undefined,
    error: params["error"] ?? undefined,
    errorDescription: params["error_description"] ?? undefined,
    errorUri,
    accessToken: params["access_token"] ?? undefined,
    idToken: params["id_token"] ?? undefined,
    refreshToken: params["refresh_token"] ?? undefined,
    tokenType: params["token_type"] ?? undefined,
    expiresIn,
    scope: params["scope"] ?? undefined,
    params,
    sanitizedUrl: sanitizeOAuthCallbackUrl(callbackUrl),
  };
}
