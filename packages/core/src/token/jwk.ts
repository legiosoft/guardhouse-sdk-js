import { timingSafeEqual } from "../security";

import type {
  ExpectedJwkKeyType,
  JwkMetadata,
  JwkMetadataValidationOptions,
  JwkMetadataValidationResult,
} from "./types";

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

export function isAlgorithmCompatibleWithKeyType(
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
