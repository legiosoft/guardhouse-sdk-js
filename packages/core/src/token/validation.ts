import { createGuardhouseLogger } from "../debug";

import type { UntrustedDecodedJWT } from "./types";

const DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS = 60;

function validateClockSkew(clockSkewTolerance: number): void {
  if (!Number.isFinite(clockSkewTolerance) || clockSkewTolerance < 0) {
    throw new Error("clockSkewTolerance must be a non-negative number");
  }
}

/**
 * Checks an untrusted decoded token's expiration claim.
 *
 * Missing, malformed, and non-finite expiration claims fail closed.
 */
export function isTokenExpired(
  decodedJWT: UntrustedDecodedJWT,
  clockSkewTolerance: number = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
  debug?: boolean,
): boolean {
  validateClockSkew(clockSkewTolerance);

  const logger = createGuardhouseLogger("Token", debug);
  const expiresAt = decodedJWT.payload.exp;
  if (typeof expiresAt !== "number" || !Number.isFinite(expiresAt)) {
    logger.debug("Token has no valid exp claim; treating token as expired");
    return true;
  }

  const now = Math.floor(Date.now() / 1000);
  const expired = expiresAt <= now - clockSkewTolerance;
  logger.debug("Token expiration checked", {
    expired,
    exp: expiresAt,
    now,
    clockSkewTolerance,
  });
  return expired;
}

/**
 * Gets the remaining lifetime of an untrusted decoded token.
 *
 * Missing, malformed, non-finite, and expired claims return zero.
 */
export function getTokenExpiresIn(
  decodedJWT: UntrustedDecodedJWT,
  clockSkewTolerance: number = DEFAULT_CLOCK_SKEW_TOLERANCE_SECONDS,
  debug?: boolean,
): number {
  validateClockSkew(clockSkewTolerance);

  const logger = createGuardhouseLogger("Token", debug);
  const expiresAt = decodedJWT.payload.exp;
  if (typeof expiresAt !== "number" || !Number.isFinite(expiresAt)) {
    logger.debug("Token has no valid exp claim; remaining lifetime is zero");
    return 0;
  }

  const now = Math.floor(Date.now() / 1000);
  const expiresIn = expiresAt - now - clockSkewTolerance;
  logger.debug("Computed token expiration window", {
    expiresIn,
    exp: expiresAt,
    now,
    clockSkewTolerance,
  });
  return expiresIn > 0 ? expiresIn : 0;
}
