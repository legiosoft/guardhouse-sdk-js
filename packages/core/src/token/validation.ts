import { createGuardhouseLogger } from "../debug";
import { timingSafeEqual } from "../security";

import { ALLOWED_ALGORITHMS, PHISHING_RESISTANT_AMR_VALUES } from "./constants";
import { consumeJti } from "./replay-cache";
import {
  isAlgorithmCompatibleWithKeyType,
  validateJwkMetadataForToken,
} from "./jwk";
import type {
  DecodedJWT,
  TokenValidationOptions,
  TokenValidationResult,
} from "./types";

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
    clockSkewTolerance = 30,
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
 * Check if token is expired.
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
 * Get remaining time until token expiration.
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
