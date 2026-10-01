import { createGuardhouseLogger } from "../debug";
import { isUnsafeObjectKey } from "../security";

import { base64UrlDecode } from "./base64";
import {
  BASE64_URL_SEGMENT_PATTERN,
  MAX_JWT_DEPTH,
  MAX_JWT_LENGTH,
  MAX_JWT_SEGMENT_LENGTH,
} from "./constants";
import type { UntrustedDecodedJWT } from "./types";

class SafeJwtDecodeError extends Error {}

function createSafeJsonReviver(
  target: "header" | "payload",
): (key: string, value: unknown) => unknown {
  const malformedMessage = `Malformed JWT ${target}`;

  return (key, value) => {
    if (key && isUnsafeObjectKey(key)) {
      throw new SafeJwtDecodeError(malformedMessage);
    }

    if (
      key === "" &&
      (!value || typeof value !== "object" || Array.isArray(value))
    ) {
      throw new SafeJwtDecodeError(malformedMessage);
    }

    return value;
  };
}

function isPlainJsonObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function rethrowAsTraversalError(error: unknown): never {
  if (error instanceof SafeJwtDecodeError) {
    throw error;
  }

  throw new SafeJwtDecodeError("JWT JSON structure is not safely traversable");
}

function assertJsonDepthWithinLimit(
  value: unknown,
  maxDepth: number,
  currentDepth = 0,
  seen = new WeakSet<object>(),
): void {
  if (currentDepth > maxDepth) {
    throw new SafeJwtDecodeError(
      "JWT JSON structure exceeds maximum nesting depth",
    );
  }

  if (value === null || typeof value !== "object") {
    return;
  }

  if (seen.has(value)) {
    throw new SafeJwtDecodeError(
      "JWT JSON structure contains circular references",
    );
  }

  seen.add(value);

  if (Array.isArray(value)) {
    try {
      for (const item of value) {
        assertJsonDepthWithinLimit(item, maxDepth, currentDepth + 1, seen);
      }
    } catch (error) {
      rethrowAsTraversalError(error);
    } finally {
      seen.delete(value);
    }

    return;
  }

  try {
    const entries = Object.values(value);
    for (const item of entries) {
      assertJsonDepthWithinLimit(item, maxDepth, currentDepth + 1, seen);
    }
  } catch (error) {
    rethrowAsTraversalError(error);
  } finally {
    seen.delete(value);
  }
}

/**
 * Decode JWT token (header + payload)
 *
 * SECURITY: Does NOT verify signature.
 */
/**
 * Parses a compact JWS without verifying its signature or claims.
 *
 * SECURITY: The returned header and payload are attacker-controlled. Use
 * OidcIdTokenVerifier before trusting any token value.
 */
export function decodeJWT(
  token: string,
  options: { debug?: boolean } = {},
): UntrustedDecodedJWT {
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
    const header = JSON.parse(
      base64UrlDecode(headerPart),
      createSafeJsonReviver("header"),
    );
    const payload = JSON.parse(
      base64UrlDecode(payloadPart),
      createSafeJsonReviver("payload"),
    );

    if (!isPlainJsonObject(header)) {
      throw new SafeJwtDecodeError("Malformed JWT header");
    }

    if (!isPlainJsonObject(payload)) {
      throw new SafeJwtDecodeError("Malformed JWT payload");
    }

    const algorithm =
      typeof header.alg === "string" ? header.alg.trim() : undefined;
    if (!algorithm || algorithm.toLowerCase() === "none") {
      throw new SafeJwtDecodeError(
        'JWT algorithm "none" is not supported for security reasons',
      );
    }

    assertJsonDepthWithinLimit(header, MAX_JWT_DEPTH);
    assertJsonDepthWithinLimit(payload, MAX_JWT_DEPTH);

    logger.debug("JWT decoded", {
      algorithm,
      hasSubject: typeof payload.sub === "string" && payload.sub.trim() !== "",
    });

    return {
      header: header as UntrustedDecodedJWT["header"],
      payload: payload as UntrustedDecodedJWT["payload"],
    };
  } catch (error) {
    const safeReason =
      error instanceof SafeJwtDecodeError
        ? error.message
        : "JWT JSON is malformed";
    logger.error("Token decode failed", {
      reason: safeReason,
    });
    throw new Error(`Failed to decode JWT: ${safeReason}`);
  }
}
