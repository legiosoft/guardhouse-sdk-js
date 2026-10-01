export interface JWTPayload {
  readonly sub?: string;
  readonly name?: string;
  readonly email?: string;
  readonly picture?: string;
  readonly iss?: string;
  readonly aud?: string | readonly string[];
  readonly azp?: string;
  readonly acr?: string;
  readonly amr?: readonly string[];
  readonly auth_time?: number;
  readonly at_hash?: string;
  readonly c_hash?: string;
  readonly exp?: number;
  readonly nbf?: number;
  readonly iat?: number;
  readonly jti?: string;
  readonly nonce?: string;
  readonly sid?: string;
  readonly cnf?: {
    readonly jkt?: string;
    readonly [key: string]: unknown;
  };
  readonly profile?: string;
  readonly address?: Readonly<Record<string, unknown>>;
  readonly roles?: readonly string[];
  readonly scopes?: readonly string[];
  readonly [key: string]: unknown;
}

export interface JWTHeader {
  readonly alg: string;
  readonly typ?: string;
  readonly kid?: string;
  readonly jku?: string;
  readonly crit?: readonly string[];
  readonly [key: string]: unknown;
}

/**
 * A parsed JWT whose signature and claims have not been verified.
 *
 * Never use values from this object for authentication or authorization.
 */
export interface UntrustedDecodedJWT {
  readonly header: JWTHeader;
  readonly payload: JWTPayload;
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
