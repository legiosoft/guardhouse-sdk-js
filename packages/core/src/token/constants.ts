/**
 * Allowed OIDC ID token signing algorithms
 *
 * SECURITY: OIDC ID tokens must be validated with asymmetric algorithms.
 */
export const ALLOWED_OIDC_ALGORITHMS: string[] = [
  "RS256",
  "RS384",
  "RS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
];

// Explicitly disallow base64url padding characters such as '='.
export const BASE64_URL_SEGMENT_PATTERN = /^[A-Za-z0-9_-]+$/;
export const MAX_JWT_LENGTH = 8192;
export const MAX_JWT_SEGMENT_LENGTH = 4096;
export const MAX_JWT_DEPTH = 3;
export const MAX_TRACKED_NONCE_AND_JTI = 4096;

export const PHISHING_RESISTANT_AMR_VALUES = new Set([
  "hwk",
  "fido",
  "fido2",
  "webauthn",
  "pki",
  "mfa",
]);
