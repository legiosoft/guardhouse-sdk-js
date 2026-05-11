const defaultOrigin = "http://localhost:3000";
const runtimeOrigin =
  typeof window !== "undefined" && window.location.origin
    ? window.location.origin
    : defaultOrigin;

const authority =
  import.meta.env.VITE_AUTHORITY?.trim() || "https://auth.example.com";
const normalizedAuthority = authority.replace(/\/+$/, "");
const clientId = import.meta.env.VITE_CLIENT_ID?.trim() || "your-client-id";
const redirectUri = import.meta.env.VITE_REDIRECT_URI?.trim() || runtimeOrigin;
const postLogoutRedirectUri =
  import.meta.env.VITE_POST_LOGOUT_REDIRECT_URI?.trim() || redirectUri;
const userInfoEndpoint =
  import.meta.env.VITE_USERINFO_ENDPOINT?.trim() ||
  `${normalizedAuthority}/connect/userinfo`;
const apiServerUrl = (
  import.meta.env.VITE_API_SERVER_URL?.trim() ||
  import.meta.env.VITE_API_BASE_URL?.trim() ||
  "https://localhost:5001"
).replace(/\/+$/, "");
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
  postLogoutRedirectUri,
  userInfoEndpoint,
  scope,
  audience,
  allowAuthorizationWithoutAudience,
  allowOfflineAccessScope,
  apiServerUrl,
  apiBaseUrl: apiServerUrl,
};
