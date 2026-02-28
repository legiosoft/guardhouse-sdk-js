import { createGuardhouseLogger } from "../debug";
import { timingSafeEqual, toUtf8Bytes } from "../security";
import { getCryptoAdapter } from "../crypto";

import { base64UrlDecodeToBytes } from "./base64";
import { tryLoadNodeCrypto } from "./node-crypto";
import type {
  DecodedJWT,
  OidcHashValidationOptions,
  OidcHashValidationResult,
} from "./types";

function resolveHashBitLength(algorithm: string): 256 | 384 | 512 | null {
  const normalizedAlgorithm = algorithm.trim().toUpperCase();

  // RFC 8037: EdDSA maps to SHA-512 for Ed25519/EdDSA hash claim derivation.
  if (normalizedAlgorithm === "EDDSA") {
    return 512;
  }

  if (normalizedAlgorithm.endsWith("256")) {
    return 256;
  }

  if (normalizedAlgorithm.endsWith("384")) {
    return 384;
  }

  if (normalizedAlgorithm.endsWith("512")) {
    return 512;
  }

  return null;
}

async function digestBytes(
  input: string,
  hashBitLength: 256 | 384 | 512,
): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  const data = toUtf8Bytes(input);

  if (subtle) {
    const bufferToHash =
      data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
        ? data.buffer
        : data.slice().buffer;
    const digestInput = bufferToHash as unknown as Parameters<
      typeof subtle.digest
    >[1];

    const digest = await subtle.digest(`SHA-${hashBitLength}`, digestInput);
    return new Uint8Array(digest);
  }

  const nodeCrypto = tryLoadNodeCrypto();
  if (nodeCrypto) {
    const hash = nodeCrypto.createHash(`sha${hashBitLength}`);
    hash.update(data);
    return new Uint8Array(hash.digest());
  }

  if (hashBitLength === 256) {
    try {
      const adapter = await getCryptoAdapter();
      return await adapter.sha256(data);
    } catch {
      // Keep the public error message stable below.
    }
  }

  throw new Error("Cryptographic hash function is unavailable");
}

/**
 * Computes OIDC at_hash/c_hash bytes from the raw token/code input.
 *
 * OIDC defines these values over the ASCII representation of the access token
 * or authorization code; toUtf8Bytes is safe here because these values should
 * be URL-safe ASCII by specification.
 */
async function computeOidcHashClaim(
  value: string,
  algorithm: string,
): Promise<Uint8Array> {
  const hashBitLength = resolveHashBitLength(algorithm);

  if (!hashBitLength) {
    throw new Error(
      `Unsupported signing algorithm for hash validation: ${algorithm}`,
    );
  }

  const digest = await digestBytes(value, hashBitLength);
  return digest.slice(0, Math.floor(digest.length / 2));
}

export async function validateOidcHashClaims(
  decodedJWT: DecodedJWT,
  options: OidcHashValidationOptions,
): Promise<OidcHashValidationResult> {
  const {
    idTokenAlg,
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

  const algorithm = idTokenAlg.trim();

  if (!algorithm) {
    throw new Error("idTokenAlg is required for OIDC hash claim validation");
  }

  if (typeof decodedJWT.payload.at_hash === "string") {
    if (!accessToken) {
      result.valid = false;
      result.atHashValid = false;
      result.errors.push("at_hash is present but access token is missing");
    } else {
      const expectedAtHash = await computeOidcHashClaim(accessToken, algorithm);

      let tokenAtHashBytes: Uint8Array;
      try {
        tokenAtHashBytes = base64UrlDecodeToBytes(decodedJWT.payload.at_hash);
      } catch {
        result.valid = false;
        result.atHashValid = false;
        result.errors.push("id_token at_hash claim must be valid Base64URL");
        tokenAtHashBytes = new Uint8Array(0);
      }

      if (
        result.atHashValid &&
        tokenAtHashBytes.length !== expectedAtHash.length
      ) {
        result.valid = false;
        result.atHashValid = false;
        result.errors.push("at_hash length mismatch");
      }

      if (
        result.atHashValid &&
        !timingSafeEqual(expectedAtHash, tokenAtHashBytes)
      ) {
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

      let tokenCHashBytes: Uint8Array;
      try {
        tokenCHashBytes = base64UrlDecodeToBytes(decodedJWT.payload.c_hash);
      } catch {
        result.valid = false;
        result.cHashValid = false;
        result.errors.push("id_token c_hash claim must be valid Base64URL");
        tokenCHashBytes = new Uint8Array(0);
      }

      if (
        result.cHashValid &&
        tokenCHashBytes.length !== expectedCHash.length
      ) {
        result.valid = false;
        result.cHashValid = false;
        result.errors.push("c_hash length mismatch");
      }

      if (
        result.cHashValid &&
        !timingSafeEqual(expectedCHash, tokenCHashBytes)
      ) {
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
