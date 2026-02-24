const defaultOrigin = "http://localhost:3000";
const runtimeOrigin =
  typeof window !== "undefined" && window.location.origin
    ? window.location.origin
    : defaultOrigin;

function normalizeRedirectUri(rawValue: string): string {
  const value = rawValue.trim();

  try {
    const parsed = new URL(value);
    const normalizedPath =
      parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "");

    return `${parsed.origin}${normalizedPath}${parsed.search}${parsed.hash}`;
  } catch {
    return value.replace(/\/+$/, "");
  }
}

const authority =
  import.meta.env.VITE_AUTHORITY?.trim() || "https://auth.example.com";
const clientId = import.meta.env.VITE_CLIENT_ID?.trim() || "your-client-id";
const redirectUri = normalizeRedirectUri(
  import.meta.env.VITE_REDIRECT_URI?.trim() || runtimeOrigin,
);
const apiBaseUrl =
  import.meta.env.VITE_API_BASE_URL?.trim().replace(/\/+$/, "") ||
  "http://localhost:3001";
const scope =
  import.meta.env.VITE_SCOPE?.trim() || "openid profile email offline_access";
const audience = import.meta.env.VITE_AUDIENCE?.trim() || undefined;
const allowAuthorizationWithoutAudience =
  import.meta.env.VITE_ALLOW_AUTH_WITHOUT_AUDIENCE?.trim().toLowerCase() ===
    "true" || !audience;
const allowOfflineAccessScope =
  import.meta.env.VITE_ALLOW_OFFLINE_ACCESS_SCOPE?.trim().toLowerCase() ===
    "true" ||
  scope
    .trim()
    .split(/\s+/)
    .some((entry: string) => entry.toLowerCase() === "offline_access");

export const appConfig = {
  authority,
  clientId,
  redirectUri,
  scope,
  audience,
  allowAuthorizationWithoutAudience,
  allowOfflineAccessScope,
  apiBaseUrl,
};
