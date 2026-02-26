import { decodeJWT } from "@guardhouse/core";
import type { StorageAdapter } from "./types";

const UNSAFE_QUERY_PARAM_KEYS = new Set([
  "__proto__",
  "prototype",
  "constructor",
]);

function isUnsafeQueryParamKey(key: string): boolean {
  return UNSAFE_QUERY_PARAM_KEYS.has(key.trim().toLowerCase());
}

export class SessionStorageAdapter implements StorageAdapter {
  async getItem(key: string): Promise<string | null> {
    if (typeof window === "undefined") return null;
    return sessionStorage.getItem(key);
  }

  async setItem(key: string, value: string): Promise<void> {
    if (typeof window === "undefined") return;
    sessionStorage.setItem(key, value);
  }

  async removeItem(key: string): Promise<void> {
    if (typeof window === "undefined") return;
    sessionStorage.removeItem(key);
  }
}

export class InMemoryStorageAdapter implements StorageAdapter {
  private store = new Map<string, string>();

  async getItem(key: string): Promise<string | null> {
    return this.store.get(key) || null;
  }

  async setItem(key: string, value: string): Promise<void> {
    this.store.set(key, value);
  }

  async removeItem(key: string): Promise<void> {
    this.store.delete(key);
  }
}

export const StorageKeys = {
  OIDC_SESSION: "gh_oidc_session",
  ACCESS_TOKEN: "gh_access_token",
  REFRESH_TOKEN: "gh_refresh_token",
  ID_TOKEN: "gh_id_token",
  EXPIRES_AT: "gh_expires_at",
  USER: "gh_user",
  CODE_VERIFIER: "gh_code_verifier",
  STATE: "gh_state",
  LOGOUT_STATE: "gh_logout_state",
  NONCE: "gh_nonce",
  REQUESTED_SCOPE: "gh_requested_scope",
  REQUESTED_AUDIENCE: "gh_requested_audience",
  PROMPT: "gh_prompt",
  APP_STATE: "gh_app_state",
};

export function generateRandomString(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);

  return Array.from(array, (byte) => String.fromCharCode(byte)).join("");
}

export function generateBase64UrlEncodedString(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);

  const base64 = btoa(
    Array.from(array, (byte) => String.fromCharCode(byte)).join(""),
  );
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function parseQueryParams(queryString: string): Record<string, string> {
  const params = Object.create(null) as Record<string, string>;

  if (!queryString) {
    return params;
  }

  const search = queryString.startsWith("?")
    ? queryString.slice(1)
    : queryString;
  const searchParams = new URLSearchParams(search);

  for (const [key, value] of searchParams.entries()) {
    if (isUnsafeQueryParamKey(key)) {
      continue;
    }

    params[key] = value;
  }

  return params;
}

export function removeQueryParams(): void {
  if (typeof window === "undefined") return;

  const url = new URL(window.location.href);
  const searchParams = url.searchParams;

  searchParams.delete("code");
  searchParams.delete("state");
  searchParams.delete("session_state");
  searchParams.delete("id_token");
  searchParams.delete("access_token");
  searchParams.delete("refresh_token");
  searchParams.delete("token_type");
  searchParams.delete("expires_in");
  searchParams.delete("scope");
  searchParams.delete("error");
  searchParams.delete("error_description");
  searchParams.delete("iss");
  searchParams.delete("sid");

  const rawHash = url.hash.startsWith("#") ? url.hash.slice(1) : url.hash;
  if (rawHash.includes("=") || rawHash.includes("&")) {
    const hashParams = new URLSearchParams(rawHash);

    hashParams.delete("code");
    hashParams.delete("state");
    hashParams.delete("session_state");
    hashParams.delete("id_token");
    hashParams.delete("access_token");
    hashParams.delete("refresh_token");
    hashParams.delete("token_type");
    hashParams.delete("expires_in");
    hashParams.delete("scope");
    hashParams.delete("error");
    hashParams.delete("error_description");
    hashParams.delete("iss");
    hashParams.delete("sid");

    const sanitizedHash = hashParams.toString();
    url.hash = sanitizedHash ? `#${sanitizedHash}` : "";
  }

  window.history.replaceState(window.history.state, "", url.toString());
}

export function validateIdToken(
  idToken: string,
  nonce: string,
  issuer: string,
  audience: string,
): Record<string, unknown> {
  const { payload } = decodeJWT(idToken);

  if (typeof payload.nonce !== "string" || payload.nonce !== nonce) {
    throw new Error("ID token nonce does not match");
  }

  if (typeof payload.iss !== "string" || payload.iss !== issuer) {
    throw new Error("ID token issuer does not match");
  }

  if (Array.isArray(payload.aud)) {
    if (!payload.aud.includes(audience)) {
      throw new Error("ID token audience does not match");
    }
  } else if (typeof payload.aud !== "string" || payload.aud !== audience) {
    throw new Error("ID token audience does not match");
  }

  if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
    throw new Error("ID token expiration claim is missing or invalid");
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now - 60) {
    throw new Error("ID token has expired");
  }

  if (typeof payload.sub !== "string" || payload.sub.trim() === "") {
    throw new Error("ID token subject is missing or invalid");
  }

  return payload;
}
