import { StorageAdapter } from "./types";

export class LocalStorageAdapter implements StorageAdapter {
  async getItem(key: string): Promise<string | null> {
    if (typeof window === "undefined") return null;
    return localStorage.getItem(key);
  }

  async setItem(key: string, value: string): Promise<void> {
    if (typeof window === "undefined") return;
    localStorage.setItem(key, value);
  }

  async removeItem(key: string): Promise<void> {
    if (typeof window === "undefined") return;
    localStorage.removeItem(key);
  }
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
  ACCESS_TOKEN: "gh_access_token",
  REFRESH_TOKEN: "gh_refresh_token",
  ID_TOKEN: "gh_id_token",
  EXPIRES_AT: "gh_expires_at",
  USER: "gh_user",
  CODE_VERIFIER: "gh_code_verifier",
  STATE: "gh_state",
  NONCE: "gh_nonce",
};

export function generateRandomString(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);

  return Array.from(array, (byte) => String.fromCharCode(byte)).join("");
}

export function generateBase64UrlEncodedString(length: number): string {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);

  let base64 = btoa(String.fromCharCode(...array));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function parseQueryParams(queryString: string): Record<string, string> {
  const params: Record<string, string> = {};
  const pairs = queryString.substring(1).split("&");

  for (const pair of pairs) {
    const [key, value] = pair.split("=");
    if (key) {
      params[decodeURIComponent(key)] = value ? decodeURIComponent(value) : "";
    }
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
  searchParams.delete("error");
  searchParams.delete("error_description");

  window.history.replaceState(window.history.state, "", url.toString());
}

export function validateIdToken(
  idToken: string,
  nonce: string,
  issuer: string,
  audience: string,
): any {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid ID token format");
  }

  const payload = JSON.parse(
    atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
  );

  if (payload.nonce !== nonce) {
    throw new Error("ID token nonce does not match");
  }

  if (payload.iss !== issuer) {
    throw new Error("ID token issuer does not match");
  }

  if (Array.isArray(payload.aud)) {
    if (!payload.aud.includes(audience)) {
      throw new Error("ID token audience does not match");
    }
  } else if (payload.aud !== audience) {
    throw new Error("ID token audience does not match");
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) {
    throw new Error("ID token has expired");
  }

  return payload;
}
