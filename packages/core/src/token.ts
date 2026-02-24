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
import { timingSafeEqual } from "./security";

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
  jku?: string;
  crit?: string[];
  [key: string]: unknown;
}

export interface DecodedJWT {
  header: JWTHeader;
  payload: JWTPayload;
}

export interface TokenValidationResult {
  valid: boolean;
  signatureVerified: boolean;
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

const BASE64_URL_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAX_JWT_LENGTH = 8192;
const MAX_JWT_SEGMENT_LENGTH = 4096;
const MAX_JWT_DEPTH = 16;

export type ExpectedJwkKeyType = "RSA" | "EC" | "oct";

function isAlgorithmCompatibleWithKeyType(
  algorithm: string,
  keyType: ExpectedJwkKeyType,
): boolean {
  if (keyType === "RSA") {
    return algorithm.startsWith("RS");
  }

  if (keyType === "EC") {
    return algorithm.startsWith("ES");
  }

  return algorithm.startsWith("HS");
}

function assertJsonDepthWithinLimit(
  value: unknown,
  maxDepth: number,
  currentDepth = 0,
): void {
  if (currentDepth > maxDepth) {
    throw new Error("JWT JSON structure exceeds maximum nesting depth");
  }

  if (value === null || typeof value !== "object") {
    return;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      assertJsonDepthWithinLimit(item, maxDepth, currentDepth + 1);
    }
    return;
  }

  for (const item of Object.values(value)) {
    assertJsonDepthWithinLimit(item, maxDepth, currentDepth + 1);
  }
}

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
export function decodeJWT(
  token: string,
  options: { debug?: boolean } = {},
): DecodedJWT {
  const logger = createGuardhouseLogger("Token", options.debug);

  logger.debug("Decoding JWT", {
    tokenLength: token?.length ?? 0,
  });

  if (!token || typeof token !== "string") {
    logger.error("Token decode failed: token is empty or not a string");
    throw new Error("Token must be a non-empty string");
  }

  if (token.length > MAX_JWT_LENGTH) {
    logger.error("Token decode failed: token exceeds maximum length", {
      tokenLength: token.length,
      maxLength: MAX_JWT_LENGTH,
    });
    throw new Error("JWT exceeds maximum supported length");
  }

  const parts = token.split(".");

  if (parts.length !== 3) {
    logger.error("Token decode failed: invalid JWT structure", {
      partCount: parts.length,
    });
    throw new Error("Invalid JWT format. Expected 3 parts separated by dots");
  }

  const [headerPart, payloadPart, signaturePart] = parts;

  if (!signaturePart) {
    logger.error("Token decode failed: missing JWS signature part");
    throw new Error("Invalid JWT format. Token must contain a signature part");
  }

  if (
    headerPart.length > MAX_JWT_SEGMENT_LENGTH ||
    payloadPart.length > MAX_JWT_SEGMENT_LENGTH ||
    signaturePart.length > MAX_JWT_SEGMENT_LENGTH
  ) {
    logger.error("Token decode failed: JWT segment too large", {
      headerLength: headerPart.length,
      payloadLength: payloadPart.length,
      signatureLength: signaturePart.length,
    });
    throw new Error("JWT segment exceeds maximum supported length");
  }

  if (
    !BASE64_URL_SEGMENT_PATTERN.test(headerPart) ||
    !BASE64_URL_SEGMENT_PATTERN.test(payloadPart) ||
    !BASE64_URL_SEGMENT_PATTERN.test(signaturePart)
  ) {
    logger.error("Token decode failed: invalid Base64URL segment detected");
    throw new Error("JWT contains invalid Base64URL encoding");
  }

  try {
    const header = JSON.parse(base64UrlDecode(headerPart));
    const payload = JSON.parse(base64UrlDecode(payloadPart));
    assertJsonDepthWithinLimit(header, MAX_JWT_DEPTH);
    assertJsonDepthWithinLimit(payload, MAX_JWT_DEPTH);

    logger.debug("JWT decoded", {
      algorithm: header?.alg,
      hasSubject: Boolean(payload?.sub),
    });

    return {
      header,
      payload,
    };
  } catch (error) {
    logger.error("Token decode failed", {
      error: error instanceof Error ? error.message : String(error),
    });
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
  signatureVerified?: boolean;
  trustedJkuOrigins?: string[];
  supportedCriticalHeaders?: string[];
  expectedKeyType?: ExpectedJwkKeyType;
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
    signatureVerified = false,
    trustedJkuOrigins = [],
    supportedCriticalHeaders = [],
    expectedKeyType,
    clockSkewTolerance = 30, // 30 seconds default skew tolerance
    debug,
  } = options;

  if (!Number.isFinite(clockSkewTolerance) || clockSkewTolerance < 0) {
    throw new Error("clockSkewTolerance must be a non-negative number");
  }

  const logger = createGuardhouseLogger("Token", debug);

  const result: TokenValidationResult = {
    valid: true,
    signatureVerified,
    expired: false,
    notBeforeValid: true,
    issuerValid: true,
    audienceValid: true,
    nonceValid: true,
    errors: [],
  };

  const now = Math.floor(Date.now() / 1000);

  if (!signatureVerified) {
    result.valid = false;
    result.errors.push("JWT signature has not been cryptographically verified");
    logger.warn(
      "Token claims were checked, but signature verification was not confirmed",
    );
  }

  const algorithm = decodedJWT.header.alg;
  const jkuHeader = decodedJWT.header.jku;

  if (typeof algorithm !== "string" || algorithm.trim() === "") {
    result.valid = false;
    result.errors.push("JWT header is missing a valid alg value");
    logger.error("JWT validation failed: missing alg header");
    return result;
  }

  // SECURITY: Check 'none' algorithm (CRITICAL)
  if (algorithm === "none") {
    result.valid = false;
    result.errors.push('JWT "none" algorithm is not allowed');
    logger.error('CRITICAL: JWT uses "none" algorithm');
  }

  // SECURITY: Check algorithm whitelist
  if (!ALLOWED_ALGORITHMS.includes(algorithm)) {
    result.valid = false;
    result.errors.push(`JWT algorithm "${algorithm}" is not allowed`);
    logger.warn(`Unknown JWT algorithm: ${algorithm}`);
  }

  if (
    expectedKeyType &&
    !isAlgorithmCompatibleWithKeyType(algorithm, expectedKeyType)
  ) {
    result.valid = false;
    result.errors.push(
      `JWT algorithm "${algorithm}" is not compatible with expected key type "${expectedKeyType}"`,
    );
    logger.error("JWT algorithm/key-type mismatch detected", {
      algorithm,
      expectedKeyType,
    });
  }

  if (typeof jkuHeader === "string" && jkuHeader.trim() !== "") {
    let jkuUrl: URL;
    try {
      jkuUrl = new URL(jkuHeader);
    } catch {
      result.valid = false;
      result.errors.push("JWT header contains an invalid jku URL");
      logger.error("Invalid jku value in JWT header");
      return result;
    }

    const normalizedTrustedOrigins = trustedJkuOrigins.map((origin) =>
      origin.trim(),
    );

    if (!normalizedTrustedOrigins.includes(jkuUrl.origin)) {
      result.valid = false;
      result.errors.push(
        `JWT jku origin "${jkuUrl.origin}" is not in trustedJkuOrigins`,
      );
      logger.error("Untrusted jku origin detected", {
        jkuOrigin: jkuUrl.origin,
      });
    }
  }

  const criticalHeaders = decodedJWT.header.crit;
  if (criticalHeaders !== undefined) {
    if (
      !Array.isArray(criticalHeaders) ||
      criticalHeaders.some((entry) => typeof entry !== "string")
    ) {
      result.valid = false;
      result.errors.push("JWT crit header must be an array of strings");
      logger.error("Invalid JWT crit header format");
      return result;
    }

    const supportedCriticalHeaderSet = new Set<string>([
      "b64",
      ...supportedCriticalHeaders.map((entry) => entry.trim()),
    ]);

    for (const criticalHeader of criticalHeaders) {
      if (!(criticalHeader in decodedJWT.header)) {
        result.valid = false;
        result.errors.push(
          `JWT crit header references missing parameter "${criticalHeader}"`,
        );
      }

      if (!supportedCriticalHeaderSet.has(criticalHeader)) {
        result.valid = false;
        result.errors.push(
          `JWT crit header contains unsupported parameter "${criticalHeader}"`,
        );
      }
    }
  }

  // SECURITY: Validate expiration (exp claim)
  if (
    decodedJWT.payload.exp !== undefined &&
    typeof decodedJWT.payload.exp !== "number"
  ) {
    result.valid = false;
    result.errors.push("Token exp claim must be a number");
  } else if (typeof decodedJWT.payload.exp === "number") {
    if (decodedJWT.payload.exp < now - clockSkewTolerance) {
      result.expired = true;
      result.valid = false;
      result.errors.push("Token has expired");
    }
  }

  // SECURITY: Validate not before time (nbf claim)
  if (
    decodedJWT.payload.nbf !== undefined &&
    typeof decodedJWT.payload.nbf !== "number"
  ) {
    result.notBeforeValid = false;
    result.valid = false;
    result.errors.push("Token nbf claim must be a number");
  } else if (typeof decodedJWT.payload.nbf === "number") {
    if (decodedJWT.payload.nbf > now + clockSkewTolerance) {
      result.notBeforeValid = false;
      result.valid = false;
      result.errors.push("Token is not yet valid (nbf claim)");
    }
  }

  // SECURITY: Validate issuer (iss claim)
  if (issuer) {
    if (!decodedJWT.payload.iss) {
      result.issuerValid = false;
      result.valid = false;
      result.errors.push("Token is missing required issuer (iss) claim");
      logger.warn("Issuer claim is missing");
    } else if (decodedJWT.payload.iss !== issuer) {
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
  if (audience) {
    if (!decodedJWT.payload.aud) {
      result.audienceValid = false;
      result.valid = false;
      result.errors.push("Token is missing required audience (aud) claim");
      logger.warn("Audience claim is missing");
    } else {
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
  }

  // SECURITY: Validate nonce (replay protection)
  if (nonce) {
    if (!decodedJWT.payload.nonce) {
      result.nonceValid = false;
      result.valid = false;
      result.errors.push("Token is missing required nonce claim");
      logger.warn("Nonce claim is missing");
    } else if (!timingSafeEqual(decodedJWT.payload.nonce, nonce)) {
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
  debug?: boolean,
): boolean {
  if (!Number.isFinite(clockSkewTolerance) || clockSkewTolerance < 0) {
    throw new Error("clockSkewTolerance must be a non-negative number");
  }

  const logger = createGuardhouseLogger("Token", debug);

  if (typeof decodedJWT.payload.exp !== "number") {
    logger.debug("Token does not contain exp claim; treating token as active");
    return false;
  }

  const now = Math.floor(Date.now() / 1000);
  const expired = decodedJWT.payload.exp < now - clockSkewTolerance;

  logger.debug("Token expiration checked", {
    expired,
    exp: decodedJWT.payload.exp,
    now,
    clockSkewTolerance,
  });

  return expired;
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
function decodeBase64ToBytes(base64: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(base64, "base64"));
  }

  if (typeof atob === "function") {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
  }

  throw new Error("Base64 decoder is unavailable in this environment");
}

function decodeUtf8(bytes: Uint8Array): string {
  if (typeof TextDecoder === "function") {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  }

  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("utf8");
  }

  let fallback = "";
  for (const byte of bytes) {
    fallback += String.fromCharCode(byte);
  }
  return fallback;
}

function base64UrlDecode(encoded: string): string {
  let base64 = encoded.replace(/-/g, "+").replace(/_/g, "/");

  while (base64.length % 4) {
    base64 += "=";
  }

  try {
    const bytes = decodeBase64ToBytes(base64);
    return decodeUtf8(bytes);
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
  debug?: boolean,
): number | null {
  if (!Number.isFinite(clockSkewTolerance) || clockSkewTolerance < 0) {
    throw new Error("clockSkewTolerance must be a non-negative number");
  }

  const logger = createGuardhouseLogger("Token", debug);

  if (typeof decodedJWT.payload.exp !== "number") {
    logger.debug("Token does not contain exp claim; expiresIn unavailable");
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = decodedJWT.payload.exp - now - clockSkewTolerance;

  logger.debug("Computed token expiration window", {
    expiresIn,
    exp: decodedJWT.payload.exp,
    now,
    clockSkewTolerance,
  });

  return expiresIn > 0 ? expiresIn : 0;
}
