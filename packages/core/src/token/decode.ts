import { createGuardhouseLogger } from "../debug";
import { isUnsafeObjectKey } from "../security";

import { base64UrlDecode } from "./base64";
import {
  BASE64_URL_SEGMENT_PATTERN,
  MAX_JWT_DEPTH,
  MAX_JWT_LENGTH,
  MAX_JWT_SEGMENT_LENGTH,
} from "./constants";
import type { DecodedJWT } from "./types";

function createSafeJsonReviver(
  target: "header" | "payload",
): (key: string, value: unknown) => unknown {
  const malformedMessage = `Malformed JWT ${target}`;

  return (key, value) => {
    if (key && isUnsafeObjectKey(key)) {
      throw new Error(malformedMessage);
    }

    if (
      key === "" &&
      (!value || typeof value !== "object" || Array.isArray(value))
    ) {
      throw new Error(malformedMessage);
    }

    return value;
  };
}

function isPlainJsonObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function rethrowAsTraversalError(error: unknown): never {
  if (
    error instanceof Error &&
    (error.message.includes("maximum nesting depth") ||
      error.message.includes("circular references"))
  ) {
    throw error;
  }

  throw new Error("JWT JSON structure is not safely traversable");
}

function assertJsonDepthWithinLimit(
  value: unknown,
  maxDepth: number,
  currentDepth = 0,
  seen = new WeakSet<object>(),
): void {
  if (currentDepth > maxDepth) {
    throw new Error("JWT JSON structure exceeds maximum nesting depth");
  }

  if (value === null || typeof value !== "object") {
    return;
  }

  if (seen.has(value)) {
    throw new Error("JWT JSON structure contains circular references");
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
    const header = JSON.parse(
      base64UrlDecode(headerPart),
      createSafeJsonReviver("header"),
    );
    const payload = JSON.parse(
      base64UrlDecode(payloadPart),
      createSafeJsonReviver("payload"),
    );

    if (!isPlainJsonObject(header)) {
      throw new Error("Malformed JWT header");
    }

    if (!isPlainJsonObject(payload)) {
      throw new Error("Malformed JWT payload");
    }

    const algorithm =
      typeof header.alg === "string" ? header.alg.trim() : undefined;
    if (!algorithm || algorithm.toLowerCase() === "none") {
      throw new Error(
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
      header: header as DecodedJWT["header"],
      payload: payload as DecodedJWT["payload"],
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
