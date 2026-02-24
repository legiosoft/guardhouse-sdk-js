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
  azp?: string;
  acr?: string;
  amr?: string[];
  auth_time?: number;
  at_hash?: string;
  c_hash?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  nonce?: string;
  sid?: string;
  cnf?: {
    jkt?: string;
    [key: string]: unknown;
  };
  profile?: Record<string, unknown>;
  address?: Record<string, unknown>;
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
  azpValid: boolean;
  kidValid: boolean;
  jwkMetadataValid: boolean;
  nonceValid: boolean;
  acrValid: boolean;
  authTimeValid: boolean;
  amrValid: boolean;
  jtiValid: boolean;
  cnfValid: boolean;
  nestedClaimsTrusted: boolean;
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
  "EdDSA",
];

const BASE64_URL_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
const MAX_JWT_LENGTH = 8192;
const MAX_JWT_SEGMENT_LENGTH = 4096;
const MAX_JWT_DEPTH = 16;
const MAX_TRACKED_JTI = 4096;
const PHISHING_RESISTANT_AMR_VALUES = new Set([
  "hwk",
  "fido",
  "fido2",
  "webauthn",
]);
const consumedJtiSet = new Set<string>();
const consumedJtiQueue: string[] = [];

export type ExpectedJwkKeyType = "RSA" | "EC" | "oct" | "OKP";

export interface JwkMetadata {
  kid?: string;
  kty?: string;
  use?: string;
  alg?: string;
  key_ops?: string[];
  [key: string]: unknown;
}

export interface JwkMetadataValidationOptions {
  tokenAlgorithm: string;
  expectedKid?: string;
  expectedKeyType?: ExpectedJwkKeyType;
  requireUseSig?: boolean;
  requireAlgMatch?: boolean;
}

export interface JwkMetadataValidationResult {
  valid: boolean;
  kidValid: boolean;
  keyTypeValid: boolean;
  useValid: boolean;
  algValid: boolean;
  keyOpsValid: boolean;
  errors: string[];
}

function normalizeJwkKeyType(rawKeyType: unknown): ExpectedJwkKeyType | null {
  if (typeof rawKeyType !== "string") {
    return null;
  }

  const normalized = rawKeyType.trim();
  if (!normalized) {
    return null;
  }

  if (normalized === "oct") {
    return "oct";
  }

  const upper = normalized.toUpperCase();
  if (upper === "RSA" || upper === "EC" || upper === "OKP") {
    return upper;
  }

  return null;
}

export function validateJwkMetadataForToken(
  jwk: JwkMetadata,
  options: JwkMetadataValidationOptions,
): JwkMetadataValidationResult {
  const {
    tokenAlgorithm,
    expectedKid,
    expectedKeyType,
    requireUseSig = true,
    requireAlgMatch = true,
  } = options;

  const normalizedTokenAlgorithm = tokenAlgorithm.trim();
  if (!normalizedTokenAlgorithm) {
    throw new Error("tokenAlgorithm is required for JWK metadata validation");
  }

  const result: JwkMetadataValidationResult = {
    valid: true,
    kidValid: true,
    keyTypeValid: true,
    useValid: true,
    algValid: true,
    keyOpsValid: true,
    errors: [],
  };

  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) {
    return {
      ...result,
      valid: false,
      kidValid: false,
      keyTypeValid: false,
      useValid: false,
      algValid: false,
      keyOpsValid: false,
      errors: ["JWK metadata must be a JSON object"],
    };
  }

  const normalizedExpectedKid =
    typeof expectedKid === "string" && expectedKid.trim() !== ""
      ? expectedKid.trim()
      : undefined;
  const normalizedJwkKid =
    typeof jwk.kid === "string" && jwk.kid.trim() !== ""
      ? jwk.kid.trim()
      : undefined;

  if (normalizedExpectedKid) {
    if (
      !normalizedJwkKid ||
      !timingSafeEqual(normalizedJwkKid, normalizedExpectedKid)
    ) {
      result.valid = false;
      result.kidValid = false;
      result.errors.push("JWK kid does not match JWT kid");
    }
  }

  const normalizedJwkKeyType = normalizeJwkKeyType(jwk.kty);
  if (!normalizedJwkKeyType) {
    result.valid = false;
    result.keyTypeValid = false;
    result.errors.push("JWK kty is missing or unsupported");
  } else {
    if (expectedKeyType && normalizedJwkKeyType !== expectedKeyType) {
      result.valid = false;
      result.keyTypeValid = false;
      result.errors.push(
        `JWK kty "${normalizedJwkKeyType}" does not match expected "${expectedKeyType}"`,
      );
    }

    if (
      !isAlgorithmCompatibleWithKeyType(
        normalizedTokenAlgorithm,
        normalizedJwkKeyType,
      )
    ) {
      result.valid = false;
      result.keyTypeValid = false;
      result.errors.push(
        `JWK key type "${normalizedJwkKeyType}" is not compatible with JWT algorithm "${normalizedTokenAlgorithm}"`,
      );
    }
  }

  const normalizedUse =
    typeof jwk.use === "string" ? jwk.use.trim().toLowerCase() : "";

  if (requireUseSig) {
    if (normalizedUse !== "sig") {
      result.valid = false;
      result.useValid = false;
      result.errors.push('JWK use must be "sig" for signature validation');
    }
  } else if (normalizedUse && normalizedUse !== "sig") {
    result.valid = false;
    result.useValid = false;
    result.errors.push('JWK use must be "sig" when provided');
  }

  const normalizedJwkAlg = typeof jwk.alg === "string" ? jwk.alg.trim() : "";

  if (requireAlgMatch) {
    if (
      !normalizedJwkAlg ||
      !timingSafeEqual(normalizedJwkAlg, normalizedTokenAlgorithm)
    ) {
      result.valid = false;
      result.algValid = false;
      result.errors.push(
        `JWK alg must exactly match JWT algorithm "${normalizedTokenAlgorithm}"`,
      );
    }
  } else if (
    normalizedJwkAlg &&
    !timingSafeEqual(normalizedJwkAlg, normalizedTokenAlgorithm)
  ) {
    result.valid = false;
    result.algValid = false;
    result.errors.push(
      `JWK alg "${normalizedJwkAlg}" does not match JWT algorithm "${normalizedTokenAlgorithm}"`,
    );
  }

  if (jwk.key_ops !== undefined) {
    if (
      !Array.isArray(jwk.key_ops) ||
      jwk.key_ops.some((operation) => typeof operation !== "string")
    ) {
      result.valid = false;
      result.keyOpsValid = false;
      result.errors.push("JWK key_ops must be an array of strings");
    } else {
      const operations = jwk.key_ops.map((operation) =>
        operation.trim().toLowerCase(),
      );

      if (!operations.includes("verify")) {
        result.valid = false;
        result.keyOpsValid = false;
        result.errors.push(
          'JWK key_ops must include "verify" for signature validation',
        );
      }

      if (
        operations.includes("encrypt") ||
        operations.includes("decrypt") ||
        operations.includes("wrapkey") ||
        operations.includes("unwrapkey")
      ) {
        result.valid = false;
        result.keyOpsValid = false;
        result.errors.push(
          "JWK key_ops contains encryption operations and is unsafe for signature validation",
        );
      }
    }
  }

  return result;
}

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

  if (keyType === "OKP") {
    return algorithm === "EdDSA";
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

function consumeJti(jti: string): boolean {
  if (consumedJtiSet.has(jti)) {
    return false;
  }

  consumedJtiSet.add(jti);
  consumedJtiQueue.push(jti);

  if (consumedJtiQueue.length > MAX_TRACKED_JTI) {
    const evicted = consumedJtiQueue.shift();
    if (evicted) {
      consumedJtiSet.delete(evicted);
    }
  }

  return true;
}

type NodeRequireFunction = (moduleId: string) => any;

function tryLoadNodeCrypto(): any | null {
  try {
    const dynamicRequire = Function(
      "return typeof require !== 'undefined' ? require : null;",
    )() as NodeRequireFunction | null;

    if (typeof dynamicRequire !== "function") {
      return null;
    }

    return dynamicRequire("crypto");
  } catch {
    return null;
  }
}

function base64UrlEncodeBytes(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  if (typeof btoa !== "function") {
    throw new Error("Base64 encoder is unavailable in this environment");
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function resolveHashBitLength(algorithm: string): 256 | 384 | 512 | null {
  if (algorithm === "EdDSA") {
    return 512;
  }

  if (algorithm.endsWith("256")) {
    return 256;
  }

  if (algorithm.endsWith("384")) {
    return 384;
  }

  if (algorithm.endsWith("512")) {
    return 512;
  }

  return null;
}

async function digestBytes(
  input: string,
  hashBitLength: 256 | 384 | 512,
): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  const data =
    typeof TextEncoder === "function"
      ? new TextEncoder().encode(input)
      : typeof Buffer !== "undefined"
        ? new Uint8Array(Buffer.from(input, "utf8"))
        : (() => {
            throw new Error("UTF-8 encoder is unavailable in this environment");
          })();

  if (subtle) {
    const digest = await subtle.digest(`SHA-${hashBitLength}`, data);
    return new Uint8Array(digest);
  }

  const nodeCrypto = tryLoadNodeCrypto();
  if (nodeCrypto) {
    const hash = nodeCrypto.createHash(`sha${hashBitLength}`);
    hash.update(Buffer.from(data));
    return new Uint8Array(hash.digest());
  }

  throw new Error("Cryptographic hash function is unavailable");
}

async function computeOidcHashClaim(
  value: string,
  algorithm: string,
): Promise<string> {
  const hashBitLength = resolveHashBitLength(algorithm);

  if (!hashBitLength) {
    throw new Error(
      `Unsupported signing algorithm for hash validation: ${algorithm}`,
    );
  }

  const digest = await digestBytes(value, hashBitLength);
  const leftHalf = digest.slice(0, digest.length / 2);

  return base64UrlEncodeBytes(leftHalf);
}

export function resetJtiReplayCache(): void {
  consumedJtiSet.clear();
  consumedJtiQueue.length = 0;
}

function timingSafeIncludes(candidates: string[], expected: string): boolean {
  let match = false;

  for (const candidate of candidates) {
    if (timingSafeEqual(candidate, expected)) {
      match = true;
    }
  }

  return match;
}

function collectNestedClaimPaths(
  value: Record<string, unknown>,
  basePath: string,
  depth = 0,
): string[] {
  if (depth > 4) {
    return [basePath];
  }

  const paths: string[] = [];

  for (const [key, entryValue] of Object.entries(value)) {
    const path = `${basePath}.${key}`;

    if (
      entryValue &&
      typeof entryValue === "object" &&
      !Array.isArray(entryValue)
    ) {
      paths.push(
        ...collectNestedClaimPaths(
          entryValue as Record<string, unknown>,
          path,
          depth + 1,
        ),
      );
      continue;
    }

    paths.push(path);
  }

  return paths;
}

export async function validateOidcHashClaims(
  decodedJWT: DecodedJWT,
  options: OidcHashValidationOptions = {},
): Promise<OidcHashValidationResult> {
  const {
    accessToken,
    authorizationCode,
    requireAtHash = false,
    requireCHash = false,
    debug,
  } = options;

  const logger = createGuardhouseLogger("Token", debug);
  const result: OidcHashValidationResult = {
    valid: true,
    atHashValid: true,
    cHashValid: true,
    errors: [],
  };

  const algorithm = decodedJWT.header.alg;

  if (typeof decodedJWT.payload.at_hash === "string") {
    if (!accessToken) {
      result.valid = false;
      result.atHashValid = false;
      result.errors.push("at_hash is present but access token is missing");
    } else {
      const expectedAtHash = await computeOidcHashClaim(accessToken, algorithm);

      if (!timingSafeEqual(expectedAtHash, decodedJWT.payload.at_hash)) {
        result.valid = false;
        result.atHashValid = false;
        result.errors.push("at_hash validation failed");
      }
    }
  } else if (decodedJWT.payload.at_hash !== undefined) {
    result.valid = false;
    result.atHashValid = false;
    result.errors.push("id_token at_hash claim must be a string");
  } else if (requireAtHash) {
    result.valid = false;
    result.atHashValid = false;
    result.errors.push("id_token is missing required at_hash claim");
  }

  if (typeof decodedJWT.payload.c_hash === "string") {
    if (!authorizationCode) {
      result.valid = false;
      result.cHashValid = false;
      result.errors.push("c_hash is present but authorization code is missing");
    } else {
      const expectedCHash = await computeOidcHashClaim(
        authorizationCode,
        algorithm,
      );

      if (!timingSafeEqual(expectedCHash, decodedJWT.payload.c_hash)) {
        result.valid = false;
        result.cHashValid = false;
        result.errors.push("c_hash validation failed");
      }
    }
  } else if (decodedJWT.payload.c_hash !== undefined) {
    result.valid = false;
    result.cHashValid = false;
    result.errors.push("id_token c_hash claim must be a string");
  } else if (requireCHash) {
    result.valid = false;
    result.cHashValid = false;
    result.errors.push("id_token is missing required c_hash claim");
  }

  if (!result.valid) {
    logger.warn("OIDC hash claim validation failed", {
      atHashValid: result.atHashValid,
      cHashValid: result.cHashValid,
      errorCount: result.errors.length,
    });
  }

  return result;
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

  if (parts.length === 5) {
    logger.error("Token decode failed: encrypted JWT (JWE) is not supported");
    throw new Error(
      "Encrypted JWT (JWE) is not supported by decodeJWT; decrypt before validation",
    );
  }

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
  clientId?: string;
  nonce?: string;
  signatureVerified?: boolean;
  trustedJkuOrigins?: string[];
  supportedCriticalHeaders?: string[];
  allowedAlgorithms?: string[];
  expectedKid?: string;
  allowedKids?: string[];
  resolvedJwk?: JwkMetadata;
  expectedKeyType?: ExpectedJwkKeyType;
  requiredAcrValues?: string[];
  maxAgeSeconds?: number;
  requiredAmrValues?: string[];
  requirePhishingResistantMfa?: boolean;
  requiredCnfJkt?: string;
  enforceUniqueJti?: boolean;
  trustedNestedClaimPaths?: string[];
  allowUntrustedNestedClaims?: boolean;
  clockSkewTolerance?: number;
  debug?: boolean;
}

export interface OidcHashValidationOptions {
  accessToken?: string;
  authorizationCode?: string;
  requireAtHash?: boolean;
  requireCHash?: boolean;
  debug?: boolean;
}

export interface OidcHashValidationResult {
  valid: boolean;
  atHashValid: boolean;
  cHashValid: boolean;
  errors: string[];
}

export function validateToken(
  decodedJWT: DecodedJWT,
  options: TokenValidationOptions = {},
): TokenValidationResult {
  const {
    issuer,
    audience,
    clientId,
    nonce,
    signatureVerified = false,
    trustedJkuOrigins = [],
    supportedCriticalHeaders = [],
    allowedAlgorithms,
    expectedKid,
    allowedKids = [],
    resolvedJwk,
    expectedKeyType,
    requiredAcrValues = [],
    maxAgeSeconds,
    requiredAmrValues = [],
    requirePhishingResistantMfa = false,
    requiredCnfJkt,
    enforceUniqueJti = false,
    trustedNestedClaimPaths = [],
    allowUntrustedNestedClaims = false,
    clockSkewTolerance = 30, // 30 seconds default skew tolerance
    debug,
  } = options;

  if (!Number.isFinite(clockSkewTolerance) || clockSkewTolerance < 0) {
    throw new Error("clockSkewTolerance must be a non-negative number");
  }

  if (
    maxAgeSeconds !== undefined &&
    (!Number.isFinite(maxAgeSeconds) || maxAgeSeconds < 0)
  ) {
    throw new Error("maxAgeSeconds must be a non-negative number");
  }

  const logger = createGuardhouseLogger("Token", debug);
  const allowedAlgorithmSet = new Set(
    (allowedAlgorithms && allowedAlgorithms.length > 0
      ? allowedAlgorithms
      : ALLOWED_ALGORITHMS
    ).map((value) => value.trim()),
  );

  const result: TokenValidationResult = {
    valid: true,
    signatureVerified,
    expired: false,
    notBeforeValid: true,
    issuerValid: true,
    audienceValid: true,
    azpValid: true,
    kidValid: true,
    jwkMetadataValid: true,
    nonceValid: true,
    acrValid: true,
    authTimeValid: true,
    amrValid: true,
    jtiValid: true,
    cnfValid: true,
    nestedClaimsTrusted: true,
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
  const kidHeader = decodedJWT.header.kid;

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
  if (!allowedAlgorithmSet.has(algorithm)) {
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

  if (resolvedJwk) {
    const jwkMetadataValidation = validateJwkMetadataForToken(resolvedJwk, {
      tokenAlgorithm: algorithm,
      expectedKid: typeof kidHeader === "string" ? kidHeader.trim() : undefined,
      expectedKeyType,
    });

    if (!jwkMetadataValidation.valid) {
      result.jwkMetadataValid = false;
      result.valid = false;
      result.errors.push(
        ...jwkMetadataValidation.errors.map(
          (error) => `JWK metadata validation failed: ${error}`,
        ),
      );
    }
  }

  if (expectedKid !== undefined || allowedKids.length > 0) {
    const normalizedKid =
      typeof kidHeader === "string" ? kidHeader.trim() : undefined;

    if (!normalizedKid) {
      result.kidValid = false;
      result.valid = false;
      result.errors.push("JWT kid validation failed");
    } else {
      const normalizedAllowedKids =
        allowedKids.length > 0
          ? allowedKids.map((value) => value.trim()).filter((value) => value)
          : expectedKid
            ? [expectedKid.trim()]
            : [];

      if (!timingSafeIncludes(normalizedAllowedKids, normalizedKid)) {
        result.kidValid = false;
        result.valid = false;
        result.errors.push("JWT kid validation failed");
      }
    }
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

  if (requiredAcrValues.length > 0) {
    const normalizedRequiredAcrValues = requiredAcrValues
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    const tokenAcr =
      typeof decodedJWT.payload.acr === "string"
        ? decodedJWT.payload.acr.trim()
        : undefined;

    if (!tokenAcr) {
      result.acrValid = false;
      result.valid = false;
      result.errors.push("Token is missing required acr claim");
    } else if (!normalizedRequiredAcrValues.includes(tokenAcr)) {
      result.acrValid = false;
      result.valid = false;
      result.errors.push(
        `Token acr "${tokenAcr}" does not satisfy required ACR values`,
      );
    }
  }

  if (enforceUniqueJti) {
    const tokenJti =
      typeof decodedJWT.payload.jti === "string"
        ? decodedJWT.payload.jti.trim()
        : undefined;

    if (!tokenJti) {
      result.jtiValid = false;
      result.valid = false;
      result.errors.push("Token is missing required jti claim");
    } else if (!consumeJti(tokenJti)) {
      result.jtiValid = false;
      result.valid = false;
      result.errors.push("Token jti has already been used");
    }
  }

  if (maxAgeSeconds !== undefined) {
    if (typeof decodedJWT.payload.auth_time !== "number") {
      result.authTimeValid = false;
      result.valid = false;
      result.errors.push(
        "Token is missing auth_time claim required for max_age validation",
      );
    } else if (
      now - decodedJWT.payload.auth_time >
      maxAgeSeconds + clockSkewTolerance
    ) {
      result.authTimeValid = false;
      result.valid = false;
      result.errors.push("Token auth_time exceeds allowed max_age");
    }
  }

  const hasAmrRequirement =
    requiredAmrValues.length > 0 || requirePhishingResistantMfa;
  if (hasAmrRequirement) {
    const amrValues = decodedJWT.payload.amr;

    if (
      !Array.isArray(amrValues) ||
      amrValues.some((value) => typeof value !== "string")
    ) {
      result.amrValid = false;
      result.valid = false;
      result.errors.push("Token amr claim must be an array of strings");
    } else {
      const normalizedAmrValues = amrValues.map((value) => value.trim());

      for (const requiredValue of requiredAmrValues) {
        const normalizedRequiredValue = requiredValue.trim();

        if (
          normalizedRequiredValue &&
          !normalizedAmrValues.includes(normalizedRequiredValue)
        ) {
          result.amrValid = false;
          result.valid = false;
          result.errors.push(
            `Token amr claim does not include required value "${normalizedRequiredValue}"`,
          );
        }
      }

      if (requirePhishingResistantMfa) {
        const hasPhishingResistantAmr = normalizedAmrValues.some((value) =>
          PHISHING_RESISTANT_AMR_VALUES.has(value.toLowerCase()),
        );

        if (!hasPhishingResistantAmr) {
          result.amrValid = false;
          result.valid = false;
          result.errors.push(
            "Token amr claim does not indicate phishing-resistant MFA",
          );
        }
      }
    }
  }

  if (requiredCnfJkt) {
    const expectedJkt = requiredCnfJkt.trim();
    const actualJkt =
      typeof decodedJWT.payload.cnf?.jkt === "string"
        ? decodedJWT.payload.cnf.jkt.trim()
        : "";

    if (!actualJkt) {
      result.cnfValid = false;
      result.valid = false;
      result.errors.push("Token is missing cnf.jkt claim");
    } else if (!timingSafeEqual(actualJkt, expectedJkt)) {
      result.cnfValid = false;
      result.valid = false;
      result.errors.push("Token cnf.jkt does not match expected binding");
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

  const expectedAuthorizedParty =
    typeof clientId === "string" && clientId.trim() !== ""
      ? clientId.trim()
      : audience;

  const tokenAudience = decodedJWT.payload.aud;
  const tokenAudienceArray = Array.isArray(tokenAudience)
    ? tokenAudience
    : tokenAudience
      ? [tokenAudience]
      : [];
  const tokenAzp =
    typeof decodedJWT.payload.azp === "string"
      ? decodedJWT.payload.azp.trim()
      : undefined;

  if (tokenAudienceArray.length > 1 && !tokenAzp) {
    result.azpValid = false;
    result.valid = false;
    result.errors.push(
      "Token with multiple audiences must include an azp claim",
    );
  }

  if (tokenAzp && expectedAuthorizedParty) {
    if (!timingSafeEqual(tokenAzp, expectedAuthorizedParty)) {
      result.azpValid = false;
      result.valid = false;
      result.errors.push(
        `Token azp "${tokenAzp}" does not match expected client identifier`,
      );
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

  const nestedClaimPaths: string[] = [];

  if (
    decodedJWT.payload.profile &&
    typeof decodedJWT.payload.profile === "object" &&
    !Array.isArray(decodedJWT.payload.profile)
  ) {
    nestedClaimPaths.push(
      ...collectNestedClaimPaths(
        decodedJWT.payload.profile as Record<string, unknown>,
        "profile",
      ),
    );
  }

  if (
    decodedJWT.payload.address &&
    typeof decodedJWT.payload.address === "object" &&
    !Array.isArray(decodedJWT.payload.address)
  ) {
    nestedClaimPaths.push(
      ...collectNestedClaimPaths(
        decodedJWT.payload.address as Record<string, unknown>,
        "address",
      ),
    );
  }

  if (nestedClaimPaths.length > 0) {
    const normalizedTrustedPaths = trustedNestedClaimPaths
      .map((path) => path.trim())
      .filter((path) => path.length > 0);

    if (allowUntrustedNestedClaims) {
      result.nestedClaimsTrusted = false;
      logger.warn(
        "Nested profile/address claims present and explicitly allowed without trust mapping",
      );
    } else {
      for (const claimPath of nestedClaimPaths) {
        if (!timingSafeIncludes(normalizedTrustedPaths, claimPath)) {
          result.nestedClaimsTrusted = false;
          result.valid = false;
          result.errors.push(`Nested claim path is not trusted: ${claimPath}`);
        }
      }
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
