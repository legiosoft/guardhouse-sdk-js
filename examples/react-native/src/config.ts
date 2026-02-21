import { Platform } from "react-native";
import {
  GH_AUTHORITY,
  GH_CLIENT_ID,
  GH_REDIRECT_URI,
  GH_SCOPE,
  GH_API_BASE_URL_ANDROID,
  GH_API_BASE_URL_IOS,
} from "@env";

function parseScopes(input: string | undefined): string[] {
  return (input || "openid profile email offline_access")
    .split(/\s+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

const authority = GH_AUTHORITY?.trim() || "https://auth.example.com";
const clientId = GH_CLIENT_ID?.trim() || "your-client-id";
const redirectUri =
  GH_REDIRECT_URI?.trim() || "com.example.guardhouse://callback";
const scopes = parseScopes(GH_SCOPE);
const apiBaseUrl =
  (Platform.OS === "android" ? GH_API_BASE_URL_ANDROID : GH_API_BASE_URL_IOS)
    ?.trim()
    .replace(/\/+$/, "") ||
  (Platform.OS === "android"
    ? "http://10.0.2.2:3001"
    : "http://localhost:3001");

export const appConfig = {
  authority,
  clientId,
  redirectUri,
  scopes,
  apiBaseUrl,
};
