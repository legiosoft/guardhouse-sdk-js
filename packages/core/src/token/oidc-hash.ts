import { createGuardhouseLogger } from "../debug";
import { timingSafeEqual } from "../security";

import { base64UrlEncodeBytes } from "./base64";
import { tryLoadNodeCrypto } from "./node-crypto";
import type {
  DecodedJWT,
  OidcHashValidationOptions,
  OidcHashValidationResult,
} from "./types";

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
