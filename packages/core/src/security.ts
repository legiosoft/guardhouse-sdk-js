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

type TimingSafeComparable = string | Uint8Array;

export function toUtf8Bytes(value: string): Uint8Array {
  if (typeof TextEncoder === "function") {
    return new TextEncoder().encode(value);
  }

  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(value, "utf8"));
  }

  throw new Error("A valid UTF-8 encoder is unavailable in this environment.");
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

  if (/^127(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}$/.test(normalized)) {
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
  } else if (protocol !== "https:" && !protocol.endsWith(":")) {
    throw new Error("redirectUri must use a valid URI protocol");
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

function toTimingSafeBytes(value: TimingSafeComparable): Uint8Array {
  return typeof value === "string" ? toUtf8Bytes(value) : value;
}

export function timingSafeEqual(
  left: TimingSafeComparable,
  right: TimingSafeComparable,
): boolean {
  const leftBytes = toTimingSafeBytes(left);
  const rightBytes = toTimingSafeBytes(right);

  if (leftBytes.length !== rightBytes.length) {
    return false;
  }

  if (leftBytes.length > MAX_SAFE_COMPARE_BYTES) {
    return false;
  }

  let mismatch = 0;

  for (let index = 0; index < leftBytes.length; index += 1) {
    mismatch |= leftBytes[index] ^ rightBytes[index];
  }

  return mismatch === 0;
}
