import * as Keychain from "react-native-keychain";
import { jwtDecode, JwtPayload } from "jwt-decode";

interface IdTokenPayload extends JwtPayload {
  nonce?: string;
  name?: string;
  email?: string;
  picture?: string;
  [key: string]: any;
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
  APP_STATE: "gh_app_state",
};

export class SecureStorageAdapter {
  async getItem(key: string): Promise<string | null> {
    try {
      const result = await Keychain.getGenericPassword({ service: key });
      if (result) {
        return result.password;
      }
      return null;
    } catch (error) {
      console.error(
        `SecureStorageAdapter.getItem error for key ${key}:`,
        error,
      );
      return null;
    }
  }

  async setItem(key: string, value: string): Promise<void> {
    try {
      await Keychain.setGenericPassword(key, value, {
        service: key,
        accessControl: Keychain.ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
      });
    } catch (error) {
      console.error(
        `SecureStorageAdapter.setItem error for key ${key}:`,
        error,
      );
      throw error;
    }
  }

  async removeItem(key: string): Promise<void> {
    try {
      await Keychain.resetGenericPassword({ service: key });
    } catch (error) {
      console.error(
        `SecureStorageAdapter.removeItem error for key ${key}:`,
        error,
      );
    }
  }

  async clear(): Promise<void> {
    try {
      const services = await Keychain.getAllGenericPasswordServices();
      for (const service of services) {
        if (service.startsWith("gh_")) {
          await Keychain.resetGenericPassword({ service });
        }
      }
    } catch (error) {
      console.error("SecureStorageAdapter.clear error:", error);
    }
  }
}

export function generateBase64UrlEncodedString(length: number): string {
  const array = new Uint8Array(length);

  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    crypto.getRandomValues(array);
  } else if (typeof window !== "undefined" && window.crypto?.getRandomValues) {
    window.crypto.getRandomValues(array);
  } else {
    throw new Error("CSPRNG not available in this environment");
  }

  let base64 = btoa(String.fromCharCode(...array));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export function parseQueryParams(queryString: string): Record<string, string> {
  const params: Record<string, string> = {};
  const pairs = queryString.substring(1).split("&");

  for (const pair of pairs) {
    const [key, value] = pair.split("=");
    if (key) {
      try {
        params[decodeURIComponent(key)] = value
          ? decodeURIComponent(value)
          : "";
      } catch (error) {
        console.warn("Failed to decode query parameter:", key);
        params[key] = value || "";
      }
    }
  }

  return params;
}

export function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);

    const allowedProtocols = ["https:", "myapp:", "com.myapp:", "com.example:"];
    if (!allowedProtocols.includes(parsed.protocol)) {
      throw new Error(`Invalid URL protocol: ${parsed.protocol}`);
    }

    return parsed.toString();
  } catch (error) {
    console.error("URL sanitization failed:", error);
    throw new Error("Invalid URL provided");
  }
}

export function redactToken(token: string): string {
  if (!token || token.length < 20) {
    return "***";
  }
  return `${token.substring(0, 8)}...${token.substring(token.length - 8)}`;
}

export function validateIdToken(
  idToken: string,
  nonce: string,
  issuer: string,
  audience: string,
): IdTokenPayload {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid ID token format");
  }

  const header = JSON.parse(
    atob(parts[0].replace(/-/g, "+").replace(/_/g, "/")),
  );

  if (header.alg === "none") {
    throw new Error("JWT 'none' algorithm is not allowed");
  }

  const allowedAlgorithms = [
    "RS256",
    "RS384",
    "RS512",
    "HS256",
    "HS384",
    "HS512",
    "ES256",
    "ES384",
    "ES512",
  ];
  if (!allowedAlgorithms.includes(header.alg)) {
    throw new Error(`Unsupported JWT algorithm: ${header.alg}`);
  }

  const payload: IdTokenPayload = jwtDecode(idToken);

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

  if (payload.nbf && payload.nbf > now) {
    throw new Error("ID token not yet valid");
  }

  if (payload.iat && payload.iat > now + 300) {
    throw new Error("ID token issued too far in the future");
  }

  return payload;
}

export function validateUrlProtocol(url: string): boolean {
  try {
    const parsed = new URL(url);

    if (parsed.protocol === "http:") {
      console.warn("HTTP protocol detected, should use HTTPS");
      return false;
    }

    return true;
  } catch (error) {
    console.error("URL protocol validation failed:", error);
    return false;
  }
}

export function logSecurityEvent(
  event: string,
  details?: Record<string, any>,
): void {
  const sanitizedDetails = details
    ? Object.entries(details).reduce(
        (acc, [key, value]) => {
          if (
            key.toLowerCase().includes("token") ||
            key.toLowerCase().includes("secret") ||
            key.toLowerCase().includes("password")
          ) {
            acc[key] = "***";
          } else if (key.toLowerCase().includes("url")) {
            try {
              const url = new URL(value);
              acc[key] = url.origin + url.pathname;
            } catch {
              acc[key] = "***";
            }
          } else {
            acc[key] = value;
          }
          return acc;
        },
        {} as Record<string, any>,
      )
    : {};

  console.log(`[Guardhouse Security] ${event}`, sanitizedDetails);
}
