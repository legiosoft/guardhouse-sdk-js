export interface JWTPayload {
  sub?: string;
  name?: string;
  email?: string;
  picture?: string;
  iss?: string;
  aud?: string | string[];
  azp?: string;
  acr?: string;
  amr?: string[];
  auth_time?: number;
  at_hash?: string;
  c_hash?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
  nonce?: string;
  sid?: string;
  cnf?: {
    jkt?: string;
    [key: string]: unknown;
  };
  profile?: Record<string, unknown>;
  address?: Record<string, unknown>;
  roles?: string[];
  scopes?: string[];
  [key: string]: unknown;
}

export interface JWTHeader {
  alg: string;
  typ?: string;
  kid?: string;
  jku?: string;
  crit?: string[];
  [key: string]: unknown;
}

export interface DecodedJWT {
  header: JWTHeader;
  payload: JWTPayload;
}

export interface TokenValidationResult {
  valid: boolean;
  signatureVerified: boolean;
  expired: boolean;
  notBeforeValid: boolean;
  issuerValid: boolean;
  audienceValid: boolean;
  azpValid: boolean;
  kidValid: boolean;
  jwkMetadataValid: boolean;
  nonceValid: boolean;
  acrValid: boolean;
  authTimeValid: boolean;
  amrValid: boolean;
  jtiValid: boolean;
  cnfValid: boolean;
  nestedClaimsTrusted: boolean;
  errors: string[];
}

export type ExpectedJwkKeyType = "RSA" | "EC" | "oct" | "OKP";

export interface JwkMetadata {
  kid?: string;
  kty?: string;
  use?: string;
  alg?: string;
  key_ops?: string[];
  [key: string]: unknown;
}

export interface JwkMetadataValidationOptions {
  tokenAlgorithm: string;
  expectedKid?: string;
  expectedKeyType?: ExpectedJwkKeyType;
  requireUseSig?: boolean;
  requireAlgMatch?: boolean;
}

export interface JwkMetadataValidationResult {
  valid: boolean;
  kidValid: boolean;
  keyTypeValid: boolean;
  useValid: boolean;
  algValid: boolean;
  keyOpsValid: boolean;
  errors: string[];
}

export interface TokenValidationOptions {
  issuer?: string;
  audience?: string;
  clientId?: string;
  nonce?: string;
  verifiedSignature?: VerifiedSignatureProof;
  /** @deprecated Prefer verifiedSignature for type-safe verification context. */
  signatureVerified?: boolean;
  trustedJkuOrigins?: string[];
  supportedCriticalHeaders?: string[];
  allowedAlgorithms?: string[];
  expectedKid?: string;
  allowedKids?: string[];
  resolvedJwk?: JwkMetadata;
  expectedKeyType?: ExpectedJwkKeyType;
  requiredAcrValues?: string[];
  maxAgeSeconds?: number;
  requiredAmrValues?: string[];
  requirePhishingResistantMfa?: boolean;
  requiredCnfJkt?: string;
  enforceUniqueJti?: boolean;
  jtiReplayCache?: {
    consume(jti: string): boolean;
  };
  trustedNestedClaimPaths?: string[];
  allowUntrustedNestedClaims?: boolean;
  /** Clock skew tolerance in seconds. */
  clockSkewTolerance?: number;
  debug?: boolean;
}

export interface VerifiedSignatureProof {
  verified: true;
  algorithm: string;
  kid?: string;
  keyType?: ExpectedJwkKeyType;
}

export interface OidcHashValidationOptions {
  idTokenAlg: string;
  accessToken?: string;
  authorizationCode?: string;
  requireAtHash?: boolean;
  requireCHash?: boolean;
  debug?: boolean;
}

export interface OidcHashValidationResult {
  valid: boolean;
  atHashValid: boolean;
  cHashValid: boolean;
  errors: string[];
}
