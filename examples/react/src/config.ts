const authority =
  import.meta.env.VITE_AUTHORITY?.trim() || "https://auth.example.com";
const clientId = import.meta.env.VITE_CLIENT_ID?.trim() || "your-client-id";
const redirectUri =
  import.meta.env.VITE_REDIRECT_URI?.trim() || "http://localhost:5173";
const scope =
  import.meta.env.VITE_SCOPE?.trim() || "openid profile email offline_access";
const apiBaseUrl =
  import.meta.env.VITE_API_BASE_URL?.trim().replace(/\/+$/, "") ||
  "http://localhost:3001";

export const appConfig = {
  authority,
  clientId,
  redirectUri,
  scope,
  apiBaseUrl,
};
