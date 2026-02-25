/**
 * Allowed JWT signing algorithms
 *
 * SECURITY: Only allow cryptographically secure algorithms
 */
export const ALLOWED_ALGORITHMS: string[] = [
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

export const BASE64_URL_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
export const MAX_JWT_LENGTH = 8192;
export const MAX_JWT_SEGMENT_LENGTH = 4096;
export const MAX_JWT_DEPTH = 16;
export const MAX_TRACKED_JTI = 4096;

export const PHISHING_RESISTANT_AMR_VALUES = new Set([
  "hwk",
  "fido",
  "fido2",
  "webauthn",
]);
