/**
 * Token Service
 *
 * SECURITY ARCHITECTURE:
 *
 * 1. JWT Decoding (without verification):
 *    - Parse JWT header and payload
 *    - Signature verification typically done by backend/resource server
 *    - We perform claim validation (exp, nbf, iss, aud)
 *
 * 2. Claim Validation:
 *    - exp: Token expiration time
 *    - nbf: Not before time (token validity window)
 *    - iss: Issuer validation (must match configured authority)
 *    - aud: Audience validation (must match client_id)
 *    - nonce: Replay protection validation
 *
 * 3. Algorithm Whitelisting:
 *    - Reject 'none' algorithm (critical security check)
 *    - Whitelist secure algorithms (RS256, HS256, etc.)
 *    - Prevents algorithm confusion attacks
 *
 * 4. Security Notes:
 *    - JWT decode does NOT verify signature (done by backend)
 *    - We validate claims for security (exp, nbf, iss, aud, nonce)
 *    - This provides defense-in-depth
 *    - Don't assume token is valid just because it decodes
 */

import { createGuardhouseLogger } from "./debug";

export interface JWTPayload {
  sub?: string;
  name?: string;
  email?: string;
  picture?: string;
  iss?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  nonce?: string;
  roles?: string[];
  scopes?: string[];
  [key: string]: any;
}

export interface JWTHeader {
  alg: string;
  typ?: string;
  kid?: string;
}

export interface DecodedJWT {
  header: JWTHeader;
  payload: JWTPayload;
}

export interface TokenValidationResult {
  valid: boolean;
  expired: boolean;
  notBeforeValid: boolean;
  issuerValid: boolean;
  audienceValid: boolean;
  nonceValid: boolean;
  errors: string[];
}

/**
 * Allowed JWT signing algorithms
 *
 * SECURITY: Only allow cryptographically secure algorithms
 *
 * Whitelisted:
 * - RS*: RSA signatures (asymmetric)
 * - HS*: HMAC signatures (symmetric, shared secret)
 * - ES*: Elliptic Curve signatures (asymmetric)
 *
 * BLOCKED:
 * - 'none': Allows unsigned tokens (CRITICAL SECURITY RISK)
 * - Any other algorithm not in whitelist
 *
 * Why whitelist?
 * - Prevents algorithm confusion attacks
 * - Prevents downgrade attacks
 * - Meets OWASP JWT security guidelines
 */
const ALLOWED_ALGORITHMS: string[] = [
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

/**
 * Decode JWT token (header + payload)
 *
 * SECURITY: Does NOT verify signature
 * Backend/resource server should verify signature
 * We perform claim validation separately
 *
 * @param token - JWT token string
 * @returns Decoded JWT with header and payload
 * @throws {Error} If token format is invalid
 */
export function decodeJWT(token: string): DecodedJWT {
  if (!token || typeof token !== "string") {
    throw new Error("Token must be a non-empty string");
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    throw new Error("Invalid JWT format. Expected 3 parts separated by dots");
  }

  try {
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));

    return {
      header,
      payload,
    };
  } catch (error) {
    throw new Error(
      `Failed to decode JWT: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Validate JWT claims
 *
 * SECURITY: Validates critical claims without verifying signature
 *
 * Checked claims:
 * 1. exp: Token expiration
 * 2. nbf: Not before time
 * 3. iss: Issuer must match authority
 * 4. aud: Audience must match client_id
 * 5. nonce: Must match expected value (replay protection)
 *
 * @param decodedJWT - Decoded JWT from decodeJWT()
 * @param options - Validation options
 * @returns Validation result with details
 */
export interface TokenValidationOptions {
  issuer?: string;
  audience?: string;
  nonce?: string;
  clockSkewTolerance?: number;
  debug?: boolean;
}

export function validateToken(
  decodedJWT: DecodedJWT,
  options: TokenValidationOptions = {},
): TokenValidationResult {
  const {
    issuer,
    audience,
    nonce,
    clockSkewTolerance = 30, // 30 seconds default skew tolerance
    debug,
  } = options;

  const logger = createGuardhouseLogger("Token", debug);

  const result: TokenValidationResult = {
    valid: true,
    expired: false,
    notBeforeValid: true,
    issuerValid: true,
    audienceValid: true,
    nonceValid: true,
    errors: [],
  };

  const now = Math.floor(Date.now() / 1000);

  // SECURITY: Check 'none' algorithm (CRITICAL)
  if (decodedJWT.header.alg === "none") {
    result.valid = false;
    result.errors.push('JWT "none" algorithm is not allowed');
    logger.error('CRITICAL: JWT uses "none" algorithm');
  }

  // SECURITY: Check algorithm whitelist
  if (!ALLOWED_ALGORITHMS.includes(decodedJWT.header.alg)) {
    result.valid = false;
    result.errors.push(
      `JWT algorithm "${decodedJWT.header.alg}" is not allowed`,
    );
    logger.warn(`Unknown JWT algorithm: ${decodedJWT.header.alg}`);
  }

  // SECURITY: Validate expiration (exp claim)
  if (decodedJWT.payload.exp) {
    if (decodedJWT.payload.exp < now - clockSkewTolerance) {
      result.expired = true;
      result.valid = false;
      result.errors.push("Token has expired");
    }
  }

  // SECURITY: Validate not before time (nbf claim)
  if (decodedJWT.payload.nbf) {
    if (decodedJWT.payload.nbf > now + clockSkewTolerance) {
      result.notBeforeValid = false;
      result.valid = false;
      result.errors.push("Token is not yet valid (nbf claim)");
    }
  }

  // SECURITY: Validate issuer (iss claim)
  if (issuer && decodedJWT.payload.iss) {
    if (decodedJWT.payload.iss !== issuer) {
      result.issuerValid = false;
      result.valid = false;
      result.errors.push(
        `Token issuer "${decodedJWT.payload.iss}" does not match expected "${issuer}"`,
      );
      logger.warn(
        `Issuer mismatch: expected ${issuer}, got ${decodedJWT.payload.iss}`,
      );
    }
  }

  // SECURITY: Validate audience (aud claim)
  if (audience && decodedJWT.payload.aud) {
    const audArray = Array.isArray(decodedJWT.payload.aud)
      ? decodedJWT.payload.aud
      : [decodedJWT.payload.aud];

    if (!audArray.includes(audience)) {
      result.audienceValid = false;
      result.valid = false;
      result.errors.push(
        `Token audience does not contain expected "${audience}"`,
      );
      logger.warn(
        `Audience mismatch: expected ${audience}, got ${audArray.join(", ")}`,
      );
    }
  }

  // SECURITY: Validate nonce (replay protection)
  if (nonce && decodedJWT.payload.nonce) {
    if (decodedJWT.payload.nonce !== nonce) {
      result.nonceValid = false;
      result.valid = false;
      result.errors.push(
        `Token nonce "${decodedJWT.payload.nonce}" does not match expected "${nonce}"`,
      );
      logger.warn(
        `Nonce mismatch: expected ${nonce}, got ${decodedJWT.payload.nonce}`,
      );
    }
  }

  logger.debug("Token validation completed", {
    valid: result.valid,
    errorCount: result.errors.length,
  });

  return result;
}

/**
 * Check if token is expired
 *
 * Faster than full validation for quick checks
 *
 * @param decodedJWT - Decoded JWT from decodeJWT()
 * @param clockSkewTolerance - Clock skew tolerance in seconds (default: 30)
 * @returns true if token is expired
 */
export function isTokenExpired(
  decodedJWT: DecodedJWT,
  clockSkewTolerance: number = 30,
): boolean {
  if (!decodedJWT.payload.exp) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);

  return decodedJWT.payload.exp < now - clockSkewTolerance;
}

/**
 * Base64URL decode
 *
 * RFC 4648 Base64URL encoding
 * - Replace '-' with '+'
 * - Replace '_' with '/'
 * - Add padding as needed
 *
 * @param encoded - Base64URL encoded string
 * @returns Decoded string
 */
function base64UrlDecode(encoded: string): string {
  let base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");

  while (base64.length % 4) {
    base64 += "=";
  }

  try {
    return atob(base64);
  } catch (error) {
    throw new Error(
      `Failed to decode Base64URL: ${error instanceof Error ? error.message : "Unknown error"}`,
    );
  }
}

/**
 * Get remaining time until token expiration
 *
 * @param decodedJWT - Decoded JWT from decodeJWT()
 * @param clockSkewTolerance - Clock skew tolerance in seconds
 * @returns Seconds until expiration, or null if no exp claim
 */
export function getTokenExpiresIn(
  decodedJWT: DecodedJWT,
  clockSkewTolerance: number = 30,
): number | null {
  if (!decodedJWT.payload.exp) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = decodedJWT.payload.exp - now - clockSkewTolerance;

  return expiresIn > 0 ? expiresIn : 0;
}
