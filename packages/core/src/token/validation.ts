import { createGuardhouseLogger } from "../debug";
import { timingSafeEqual } from "../security";

import {
  ALLOWED_OIDC_ALGORITHMS,
  PHISHING_RESISTANT_AMR_VALUES,
} from "./constants";
import {
  isAlgorithmCompatibleWithKeyType,
  validateJwkMetadataForToken,
} from "./jwk";
import type {
  DecodedJWT,
  TokenValidationOptions,
  TokenValidationResult,
} from "./types";

const DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 60;
const MAX_TOTAL_NESTED_CLAIM_KEYS = 100;

interface NestedClaimTraversalState {
  keyCount: number;
  maxTotalKeys: number;
}

function normalizeAudienceClaim(aud: unknown): string[] | null {
  if (aud === undefined) {
    return [];
  }

  if (typeof aud === "string") {
    const normalized = aud.trim();
    return normalized ? [normalized] : null;
  }

  if (!Array.isArray(aud)) {
    return null;
  }

  const normalizedAudience: string[] = [];

  for (const value of aud) {
    if (typeof value !== "string") {
      return null;
    }

    const normalized = value.trim();
    if (!normalized) {
      return null;
    }

    normalizedAudience.push(normalized);
  }

  return normalizedAudience;
}

function collectNestedClaimPaths(
  value: Record<string, unknown>,
  basePath: string,
  depth = 0,
  traversalState: NestedClaimTraversalState = {
    keyCount: 0,
    maxTotalKeys: MAX_TOTAL_NESTED_CLAIM_KEYS,
  },
): string[] {
  if (depth > 4) {
    return [basePath];
  }

  const paths: string[] = [];

  for (const [key, entryValue] of Object.entries(value)) {
    traversalState.keyCount += 1;
    if (traversalState.keyCount > traversalState.maxTotalKeys) {
      throw new Error("Token nested claims exceed maximum supported key count");
    }

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
          traversalState,
        ),
      );
      continue;
    }

    paths.push(path);
  }

  return paths;
}

/**
 * Validate JWT claims.
 *
 * SECURITY: Validates critical claims without verifying signature.
 */
export function validateToken(
  decodedJWT: DecodedJWT,
  options: TokenValidationOptions = {},
): TokenValidationResult {
  const {
    issuer,
    audience,
    clientId,
    nonce,
    verifiedSignature,
    signatureVerified: signatureVerifiedFlag = false,
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
    jtiReplayCache,
    trustedNestedClaimPaths = [],
    allowUntrustedNestedClaims = false,
    clockSkewTolerance = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
    debug,
  } = options;

  const signatureVerified =
    (verifiedSignature?.verified ?? false) || signatureVerifiedFlag;

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
      : ALLOWED_OIDC_ALGORITHMS
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

  const tokenSubject =
    typeof decodedJWT.payload.sub === "string"
      ? decodedJWT.payload.sub.trim()
      : "";

  if (!tokenSubject) {
    result.valid = false;
    result.errors.push("Token is missing mandatory subject (sub) claim.");
  }

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

  if (signatureVerifiedFlag && !verifiedSignature) {
    logger.warn(
      "signatureVerified boolean was provided without verifiedSignature proof",
      {
        recommendation:
          "Provide verifiedSignature for type-safe verification context",
      },
    );
  }

  if (typeof algorithm !== "string" || algorithm.trim() === "") {
    result.valid = false;
    result.errors.push("JWT header is missing a valid alg value");
    logger.error("JWT validation failed: missing alg header");
    return result;
  }

  if (verifiedSignature) {
    const normalizedProofAlgorithm =
      typeof verifiedSignature.algorithm === "string"
        ? verifiedSignature.algorithm.trim()
        : "";
    const normalizedHeaderKid =
      typeof kidHeader === "string" ? kidHeader.trim() : undefined;
    const normalizedProofKid =
      typeof verifiedSignature.kid === "string"
        ? verifiedSignature.kid.trim()
        : undefined;

    if (!normalizedProofAlgorithm || normalizedProofAlgorithm !== algorithm) {
      result.valid = false;
      result.signatureVerified = false;
      result.errors.push(
        "verifiedSignature algorithm does not match JWT header alg",
      );
    }

    if (normalizedProofKid && normalizedProofKid !== normalizedHeaderKid) {
      result.valid = false;
      result.kidValid = false;
      result.errors.push("verifiedSignature kid does not match JWT header kid");
    }

    if (
      expectedKeyType &&
      verifiedSignature.keyType &&
      verifiedSignature.keyType !== expectedKeyType
    ) {
      result.valid = false;
      result.jwkMetadataValid = false;
      result.errors.push(
        "verifiedSignature keyType does not match expected key type",
      );
    }
  }

  if (algorithm === "none") {
    result.valid = false;
    result.errors.push('JWT "none" algorithm is not allowed');
    logger.error('CRITICAL: JWT uses "none" algorithm');
  }

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

      if (!normalizedAllowedKids.includes(normalizedKid)) {
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
    if (!jtiReplayCache) {
      throw new Error(
        "jtiReplayCache is required when enforceUniqueJti is enabled",
      );
    }

    const tokenJti =
      typeof decodedJWT.payload.jti === "string"
        ? decodedJWT.payload.jti.trim()
        : undefined;

    if (!tokenJti) {
      result.jtiValid = false;
      result.valid = false;
      result.errors.push("Token is missing required jti claim");
    } else if (!jtiReplayCache.consume(tokenJti)) {
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

  if (
    decodedJWT.payload.iat !== undefined &&
    typeof decodedJWT.payload.iat !== "number"
  ) {
    result.valid = false;
    result.errors.push("Token iat claim must be a number");
  } else if (
    typeof decodedJWT.payload.iat === "number" &&
    decodedJWT.payload.iat > now + clockSkewTolerance
  ) {
    result.valid = false;
    result.errors.push("Token issued-at time is in the future.");
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
        const normalizedAmrValuesLower = normalizedAmrValues.map((value) =>
          value.toLowerCase(),
        );
        const hasPhishingResistantAmr = normalizedAmrValuesLower.some((value) =>
          PHISHING_RESISTANT_AMR_VALUES.has(value),
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
    } else if (actualJkt.length !== expectedJkt.length) {
      result.cnfValid = false;
      result.valid = false;
      result.errors.push("Token cnf.jkt does not match expected binding");
    } else if (!timingSafeEqual(actualJkt, expectedJkt)) {
      result.cnfValid = false;
      result.valid = false;
      result.errors.push("Token cnf.jkt does not match expected binding");
    }
  }

  if (
    decodedJWT.payload.exp !== undefined &&
    typeof decodedJWT.payload.exp !== "number"
  ) {
    result.valid = false;
    result.errors.push("Token exp claim must be a number");
  } else if (typeof decodedJWT.payload.exp === "number") {
    if (decodedJWT.payload.exp <= now - clockSkewTolerance) {
      result.expired = true;
      result.valid = false;
      result.errors.push("Token has expired");
    }
  }

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

  if (issuer) {
    const tokenIssuer =
      typeof decodedJWT.payload.iss === "string"
        ? decodedJWT.payload.iss.trim()
        : "";

    if (!tokenIssuer) {
      result.issuerValid = false;
      result.valid = false;
      result.errors.push("Token is missing required issuer (iss) claim");
      logger.warn("Issuer claim is missing");
    } else if (tokenIssuer !== issuer) {
      result.issuerValid = false;
      result.valid = false;
      result.errors.push(
        `Token issuer "${tokenIssuer}" does not match expected "${issuer}"`,
      );
      logger.warn(`Issuer mismatch: expected ${issuer}, got ${tokenIssuer}`);
    }
  }

  const expectedAudience =
    typeof audience === "string" ? audience.trim() : undefined;
  const tokenAudienceArray = normalizeAudienceClaim(decodedJWT.payload.aud);
  const normalizedAudienceList = tokenAudienceArray ?? [];

  if (tokenAudienceArray === null) {
    result.audienceValid = false;
    result.valid = false;
    result.errors.push(
      "Token aud claim must be a string or an array of non-empty strings",
    );
    logger.warn("Audience claim format is invalid");
  }

  if (expectedAudience) {
    if (normalizedAudienceList.length === 0) {
      result.audienceValid = false;
      result.valid = false;
      result.errors.push("Token is missing required audience (aud) claim");
      logger.warn("Audience claim is missing");
    } else if (!normalizedAudienceList.includes(expectedAudience)) {
      result.audienceValid = false;
      result.valid = false;
      result.errors.push(
        `Token audience does not contain expected "${expectedAudience}"`,
      );
      logger.warn(
        `Audience mismatch: expected ${expectedAudience}, got ${normalizedAudienceList.join(", ")}`,
      );
    }
  }

  const normalizedClientId =
    typeof clientId === "string" && clientId.trim() !== ""
      ? clientId.trim()
      : undefined;
  const tokenAzp =
    typeof decodedJWT.payload.azp === "string"
      ? decodedJWT.payload.azp.trim()
      : undefined;

  if (normalizedAudienceList.length > 1 && !tokenAzp) {
    result.azpValid = false;
    result.valid = false;
    result.errors.push(
      "azp claim is REQUIRED when multiple audiences are present (OIDC Core 3.1.3.7).",
    );
  }

  if (tokenAzp && normalizedClientId) {
    if (tokenAzp !== normalizedClientId) {
      result.azpValid = false;
      result.valid = false;
      result.errors.push(
        `Token azp "${tokenAzp}" does not match expected client identifier`,
      );
    }
  }

  if (nonce) {
    const tokenNonce =
      typeof decodedJWT.payload.nonce === "string"
        ? decodedJWT.payload.nonce
        : "";

    if (!tokenNonce) {
      result.nonceValid = false;
      result.valid = false;
      result.errors.push("Token is missing required nonce claim");
      logger.warn("Nonce claim is missing");
    } else if (tokenNonce.length !== nonce.length) {
      result.nonceValid = false;
      result.valid = false;
      result.errors.push(
        `Token nonce "${tokenNonce}" does not match expected "${nonce}"`,
      );
      logger.warn(`Nonce mismatch: expected ${nonce}, got ${tokenNonce}`);
    } else if (!timingSafeEqual(tokenNonce, nonce)) {
      result.nonceValid = false;
      result.valid = false;
      result.errors.push(
        `Token nonce "${tokenNonce}" does not match expected "${nonce}"`,
      );
      logger.warn(`Nonce mismatch: expected ${nonce}, got ${tokenNonce}`);
    }
  }

  const nestedClaimPaths: string[] = [];
  const nestedClaimTraversalState: NestedClaimTraversalState = {
    keyCount: 0,
    maxTotalKeys: MAX_TOTAL_NESTED_CLAIM_KEYS,
  };
  let nestedClaimTraversalFailed = false;

  try {
    if (
      decodedJWT.payload.profile &&
      typeof decodedJWT.payload.profile === "object" &&
      !Array.isArray(decodedJWT.payload.profile)
    ) {
      nestedClaimPaths.push(
        ...collectNestedClaimPaths(
          decodedJWT.payload.profile as Record<string, unknown>,
          "profile",
          0,
          nestedClaimTraversalState,
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
          0,
          nestedClaimTraversalState,
        ),
      );
    }
  } catch (error) {
    nestedClaimTraversalFailed = true;
    result.nestedClaimsTrusted = false;
    result.valid = false;
    result.errors.push(
      error instanceof Error ? error.message : "Nested claim traversal failed",
    );
  }

  if (!nestedClaimTraversalFailed && nestedClaimPaths.length > 0) {
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
        if (!normalizedTrustedPaths.includes(claimPath)) {
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
 * Check if token is expired.
 */
export function isTokenExpired(
  decodedJWT: DecodedJWT,
  clockSkewTolerance: number = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
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

  // OIDC time claims are Unix seconds; Date.now() is milliseconds.
  const now = Math.floor(Date.now() / 1000);
  const expired = decodedJWT.payload.exp <= now - clockSkewTolerance;

  logger.debug("Token expiration checked", {
    expired,
    exp: decodedJWT.payload.exp,
    now,
    clockSkewTolerance,
  });

  return expired;
}

/**
 * Get remaining time until token expiration.
 */
export function getTokenExpiresIn(
  decodedJWT: DecodedJWT,
  clockSkewTolerance: number = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
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
