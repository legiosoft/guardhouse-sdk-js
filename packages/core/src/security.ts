const LOOPBACK_HOSTNAMES = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "10.0.2.2",
]);

const DANGEROUS_PROTOCOLS = new Set([
  "javascript:",
  "data:",
  "vbscript:",
  "file:",
]);
const UNSAFE_OBJECT_KEYS = new Set(["__proto__", "prototype", "constructor"]);
const PUNYCODE_LABEL_PREFIX = "xn--";

const MAX_SAFE_COMPARE_BYTES = 4096;

function toUtf8Bytes(value: string): Uint8Array {
  if (typeof TextEncoder === "function") {
    return new TextEncoder().encode(value);
  }

  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(value, "utf8"));
  }

  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    bytes[index] = value.charCodeAt(index) & 0xff;
  }
  return bytes;
}

function normalizeHostname(hostname: string): string {
  const lowered = hostname.trim().toLowerCase();

  if (lowered.startsWith("[") && lowered.endsWith("]")) {
    return lowered.slice(1, -1);
  }

  return lowered;
}

export function isLocalDevelopmentHostname(hostname: string): boolean {
  const normalized = normalizeHostname(hostname);

  if (LOOPBACK_HOSTNAMES.has(normalized)) {
    return true;
  }

  if (normalized.startsWith("127.")) {
    return true;
  }

  return normalized.endsWith(".localhost");
}

export function enforceSecureHttpUrl(url: URL, label: string): void {
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error(`${label} must use an http or https protocol.`);
  }

  if (url.protocol === "http:" && !isLocalDevelopmentHostname(url.hostname)) {
    throw new Error(`${label} must use HTTPS unless it targets localhost.`);
  }
}

export function enforceNonSpoofableHostname(url: URL, label: string): void {
  const hostname = normalizeHostname(url.hostname);

  const hasPunycodeLabel = hostname
    .split(".")
    .some((entry) => entry.toLowerCase().startsWith(PUNYCODE_LABEL_PREFIX));

  if (hasPunycodeLabel) {
    throw new Error(
      `${label} hostname uses an internationalized domain label that is blocked to prevent Unicode homograph spoofing`,
    );
  }
}

export function isUnsafeObjectKey(key: string): boolean {
  return UNSAFE_OBJECT_KEYS.has(key.trim().toLowerCase());
}

export function validateRedirectUri(redirectUri: string): URL {
  if (typeof redirectUri !== "string" || redirectUri.trim() === "") {
    throw new Error("redirectUri is required");
  }

  if (redirectUri.includes("*")) {
    throw new Error("redirectUri must not contain wildcard characters");
  }

  let parsed: URL;

  try {
    parsed = new URL(redirectUri);
  } catch {
    throw new Error("redirectUri must be a valid absolute URI");
  }

  const protocol = parsed.protocol.toLowerCase();

  if (DANGEROUS_PROTOCOLS.has(protocol)) {
    throw new Error("redirectUri uses an unsafe protocol");
  }

  if (protocol === "http:") {
    if (!isLocalDevelopmentHostname(parsed.hostname)) {
      throw new Error("redirectUri must use HTTPS unless it targets localhost");
    }
  } else if (protocol !== "https:") {
    throw new Error(
      "redirectUri must use HTTPS or localhost HTTP; custom URI schemes are not allowed",
    );
  }

  if (parsed.username || parsed.password) {
    throw new Error("redirectUri must not include username or password");
  }

  if (parsed.hash) {
    throw new Error("redirectUri must not include a URL fragment");
  }

  return parsed;
}

export function validateAndNormalizeRedirectUri(redirectUri: string): string {
  const normalizedRedirectUri = redirectUri.trim();
  validateRedirectUri(normalizedRedirectUri);
  return normalizedRedirectUri;
}

export function sanitizeUrlForLogs(value: string): string {
  try {
    const url = new URL(value);

    if (url.origin !== "null") {
      return `${url.origin}${url.pathname}`;
    }

    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return value;
  }
}

export function timingSafeEqual(left: string, right: string): boolean {
  const leftBytes = toUtf8Bytes(left);
  const rightBytes = toUtf8Bytes(right);

  if (
    leftBytes.length > MAX_SAFE_COMPARE_BYTES ||
    rightBytes.length > MAX_SAFE_COMPARE_BYTES
  ) {
    return false;
  }

  const compareLength = Math.max(leftBytes.length, rightBytes.length);
  let mismatch = leftBytes.length ^ rightBytes.length;

  for (let index = 0; index < compareLength; index += 1) {
    const leftByte = index < leftBytes.length ? leftBytes[index] : 0;
    const rightByte = index < rightBytes.length ? rightBytes[index] : 0;
    mismatch |= leftByte ^ rightByte;
  }

  return mismatch === 0;
}
