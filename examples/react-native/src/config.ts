import { Platform } from "react-native";
import {
  GH_AUTHORITY,
  GH_AUDIENCE,
  GH_AUTHORIZATION_ENDPOINT,
  GH_CLIENT_ID,
  GH_PASSKEY_ASSERTION_ENDPOINT,
  GH_PASSKEY_CHALLENGE_ENDPOINT,
  GH_REGISTRATION_ENDPOINT,
  GH_REDIRECT_URI,
  GH_REVOCATION_ENDPOINT,
  GH_SCOPE,
  GH_TOKEN_ENDPOINT,
  GH_API_BASE_URL_ANDROID,
  GH_API_BASE_URL_IOS,
  GH_JWKS_URI,
  GH_REQUIRED_ACR_VALUES,
  GH_REQUIRED_AMR_VALUES,
  GH_REQUIRE_WEBAUTHN,
  GH_REQUIRE_PHISHING_RESISTANT_MFA,
  GH_ALLOW_INSECURE_ID_TOKEN_VALIDATION,
} from "@env";

function parseScopes(input: string | undefined): string[] {
  return (input || "openid profile email offline_access")
    .split(/\s+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

function parseList(input: string | undefined): string[] | undefined {
  if (!input) {
    return undefined;
  }

  const values = input
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter(Boolean);

  return values.length > 0 ? values : undefined;
}

function parseBoolean(input: string | undefined): boolean | undefined {
  if (!input) {
    return undefined;
  }

  const normalized = input.trim().toLowerCase();
  if (normalized === "true" || normalized === "1" || normalized === "yes") {
    return true;
  }

  if (normalized === "false" || normalized === "0" || normalized === "no") {
    return false;
  }

  return undefined;
}

const authority = GH_AUTHORITY?.trim() || "https://auth.example.com";
const clientId = GH_CLIENT_ID?.trim() || "your-client-id";
const redirectUri =
  GH_REDIRECT_URI?.trim() || "com.example.guardhouse://callback";
const scope = GH_SCOPE?.trim() || "openid profile email offline_access";
const scopes = parseScopes(scope);
const audience = GH_AUDIENCE?.trim() || undefined;

const authorizationEndpoint =
  GH_AUTHORIZATION_ENDPOINT?.trim() || "/connect/authorize";
const registrationEndpoint =
  GH_REGISTRATION_ENDPOINT?.trim() || "/account/signup?returnUrl=";
const tokenEndpoint = GH_TOKEN_ENDPOINT?.trim() || "/connect/token";
const revocationEndpoint =
  GH_REVOCATION_ENDPOINT?.trim() || "/connect/revocation";
const passkeyChallengeEndpoint =
  GH_PASSKEY_CHALLENGE_ENDPOINT?.trim() || "/connect/webauthn/challenge";
const passkeyAssertionEndpoint =
  GH_PASSKEY_ASSERTION_ENDPOINT?.trim() || "/connect/webauthn/verify";

const jwksUri = GH_JWKS_URI?.trim() || undefined;
const requiredAcrValues = parseList(GH_REQUIRED_ACR_VALUES);
const requiredAmrValues = parseList(GH_REQUIRED_AMR_VALUES);
const requireWebAuthn = parseBoolean(GH_REQUIRE_WEBAUTHN);
const requirePhishingResistantMfa = parseBoolean(
  GH_REQUIRE_PHISHING_RESISTANT_MFA,
);
const allowInsecureIdTokenValidation =
  parseBoolean(GH_ALLOW_INSECURE_ID_TOKEN_VALIDATION) ?? true;
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
  scope,
  scopes,
  audience,
  authorizationEndpoint,
  registrationEndpoint,
  tokenEndpoint,
  revocationEndpoint,
  passkeyChallengeEndpoint,
  passkeyAssertionEndpoint,
  jwksUri,
  requiredAcrValues,
  requiredAmrValues,
  requireWebAuthn,
  requirePhishingResistantMfa,
  allowInsecureIdTokenValidation,
  apiBaseUrl,
};
