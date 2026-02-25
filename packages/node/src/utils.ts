import crypto from "crypto";
import { GuardhouseConstants } from "./constants";

export function base64UrlEncode(buffer: Buffer | Uint8Array): string {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

export function base64UrlDecode(str: string): Buffer {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  return Buffer.from(base64, "base64");
}

export function getTokenHash(token: string): string {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export function sanitizeToken(token: string): string {
  return token.trim();
}

export function validateHttpsUrl(url: string, errorMessage: string): void {
  const urlObj = new URL(url);
  if (urlObj.protocol !== GuardhouseConstants.Schemes.Https) {
    throw new Error(
      `${errorMessage}. URL must use HTTPS. Protocol: ${urlObj.protocol}`,
    );
  }
}

export function validateTrustedAuthority(
  authority: string,
  expectedAuthority: string,
): void {
  const authUrl = new URL(authority);
  const expectedUrl = new URL(expectedAuthority);

  if (authUrl.hostname !== expectedUrl.hostname) {
    throw new Error(
      `JWKS authority hostname (${authUrl.hostname}) does not match configured authority (${expectedUrl.hostname})`,
    );
  }
}

export function maskSecret(secret: string): string {
  if (secret.length <= 8) {
    return "********";
  }
  return `${secret.substring(0, 4)}****${secret.substring(secret.length - 4)}`;
}

export function generateCorrelationId(): string {
  return `gh_${Date.now()}_${crypto.randomBytes(8).toString("hex")}`;
}

export function validateJwksContentType(contentType: string): void {
  const validTypes = [
    GuardhouseConstants.ContentTypes.Json,
    GuardhouseConstants.ContentTypes.JwkSet,
  ];

  if (!validTypes.includes(contentType)) {
    throw new Error(
      `Invalid JWKS response Content-Type: ${contentType}. Expected one of: ${validTypes.join(", ")}`,
    );
  }
}

export function validateMaxTokenAge(exp: number, maxAgeSeconds: number): void {
  const now = Math.floor(Date.now() / 1000);
  const tokenAge = exp - now;

  if (tokenAge > maxAgeSeconds) {
    throw new Error(
      `Token expiration (${tokenAge}s) exceeds maximum allowed age (${maxAgeSeconds}s)`,
    );
  }
}

export function parseErrorResponse(responseContent: string): string {
  try {
    const errorDoc = JSON.parse(responseContent);
    const error = errorDoc.error;
    const errorDescription = errorDoc.error_description;

    if (error) {
      if (errorDescription) {
        return `Error: ${error}. Description: ${errorDescription}`;
      }
      return `Error: ${error}`;
    }
  } catch {
    return "Authentication failed";
  }

  return "Authentication failed";
}

export function safeMerge<T extends object>(target: T, source: Partial<T>): T {
  const result = { ...target };

  for (const key in source) {
    if (Object.prototype.hasOwnProperty.call(source, key)) {
      (result as any)[key] = (source as any)[key];
    }
  }

  return result;
}

export function buildClaimsFromIntrospection(
  introspectionResult: any,
): Record<string, any> {
  const claims: Record<string, any> = {};
  const roles = new Set<string>();

  if (introspectionResult.sub) {
    claims.sub = introspectionResult.sub;
  }

  if (introspectionResult.username) {
    claims.username = introspectionResult.username;
    claims.name = introspectionResult.username;
  }

  if (introspectionResult.email) {
    claims.email = introspectionResult.email;
  }

  if (Array.isArray(introspectionResult.role)) {
    introspectionResult.role.forEach((role: string) => roles.add(role));
  } else if (typeof introspectionResult.role === "string") {
    roles.add(introspectionResult.role);
  }

  if (introspectionResult.roles) {
    const roleArray = introspectionResult.roles.split(" ").filter(Boolean);
    roleArray.forEach((role: string) => roles.add(role));
  }

  if (roles.size > 0) {
    claims.roles = Array.from(roles);
  }

  if (introspectionResult.scope) {
    claims.scopes = introspectionResult.scope.split(" ").filter(Boolean);
  }

  if (introspectionResult.client_id) {
    claims.clientId = introspectionResult.client_id;
  }

  if (introspectionResult.aud) {
    claims.aud = introspectionResult.aud.split(" ").filter(Boolean);
  }

  if (introspectionResult.iss) {
    claims.iss = introspectionResult.iss;
  }

  if (introspectionResult.jti) {
    claims.jti = introspectionResult.jti;
  }

  if (introspectionResult.exp) {
    claims.exp = introspectionResult.exp;
  }

  if (introspectionResult.iat) {
    claims.iat = introspectionResult.iat;
  }

  if (introspectionResult.nbf) {
    claims.nbf = introspectionResult.nbf;
  }

  return claims;
}

export function createWWWAuthenticateHeader(
  realm: string,
  error?: string,
  errorDescription?: string,
): string {
  let header = `Bearer realm="${realm}"`;
  if (error) {
    header += `, error="${error}"`;
  }
  if (errorDescription) {
    header += `, error_description="${errorDescription}"`;
  }
  return header;
}

export function stripStackTrace(error: Error): string {
  return error.message;
}
