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
    if (!/^[a-z][a-z0-9+.-]*:$/.test(protocol)) {
      throw new Error("redirectUri protocol is invalid");
    }
  }

  if (parsed.username || parsed.password) {
    throw new Error("redirectUri must not include username or password");
  }

  if (parsed.hash) {
    throw new Error("redirectUri must not include a URL fragment");
  }

  return parsed;
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
