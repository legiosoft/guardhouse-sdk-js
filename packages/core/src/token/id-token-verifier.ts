import {
  compactVerify,
  createRemoteJWKSet,
  customFetch,
  jwtVerify,
  type FetchImplementation,
} from "jose";

import { GuardhouseError } from "../config";
import {
  enforceNonSpoofableHostname,
  enforceSecureHttpUrl,
  timingSafeEqual,
} from "../security";
import {
  ALLOWED_OIDC_ALGORITHMS,
  MAX_CLOCK_SKEW_TOLERANCE_SECONDS,
} from "./constants";
import { decodeJWT } from "./decode";
import type { IdTokenReplayCache } from "./replay-cache";
import type { JWTHeader, JWTPayload } from "./types";

const DEFAULT_CLOCK_SKEW_SECONDS = 60;
const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1000;
const MAX_METADATA_RESPONSE_BYTES = 1024 * 1024;
const METADATA_REQUEST_TIMEOUT_MS = 10_000;
const FORCED_REFRESH_COOLDOWN_MS = 30_000;

export type IdTokenSigningAlgorithm =
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "EdDSA";

const SUPPORTED_SIGNING_ALGORITHMS = new Set<IdTokenSigningAlgorithm>([
  "RS256",
  "RS384",
  "RS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
]);

interface AuthenticationRequirements {
  readonly allowedAdditionalIdTokenAudiences?: readonly string[];
  readonly requiredAcrValues?: readonly string[];
  readonly requiredAmrValues?: readonly string[];
}

/** Serializable identity fields of this verified ID token, without inherited claims. */
export interface OidcIdentityMetadata {
  readonly issuer: string;
  readonly clientId: string;
  readonly subject: string;
  readonly audiences: readonly string[];
  readonly authorizedParty: string | null;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly nonce: string | null;
  readonly authTime: number | null;
  readonly acr: string | null;
  readonly amr: readonly string[];
  readonly sessionId: string | null;
}

const VERIFIED_OIDC_IDENTITY: unique symbol = Symbol("VerifiedOidcIdentity");
interface VerifiedIdentityContext {
  readonly status: "current" | "historical";
  readonly nonce: string | null;
  readonly authTime: number | null;
}

// Original refresh constraints are private evidence, not claims of every token
// in the chain. Keeping them outside the serializable snapshot lets a token be
// restored from its signature without inventing claims that it did not contain.
const verifiedOidcIdentityEvidence = new WeakMap<
  object,
  VerifiedIdentityContext
>();

/** Current, signature- and claim-verified OIDC identity evidence. */
export interface OidcIdentity extends OidcIdentityMetadata {
  readonly [VERIFIED_OIDC_IDENTITY]: "current";
}

/**
 * Signature-verified identity metadata from an expired token.
 *
 * This evidence can bind refresh and UserInfo responses, but must never be
 * treated as a current authentication credential.
 */
export interface HistoricalOidcIdentity extends OidcIdentityMetadata {
  readonly [VERIFIED_OIDC_IDENTITY]: "historical";
}

export type OidcIdentityEvidence = OidcIdentity | HistoricalOidcIdentity;

export interface AuthorizationCodeIdTokenContext extends AuthenticationRequirements {
  readonly purpose: "authorization_code";
  readonly nonce: string;
  readonly maxAgeSeconds?: number;
  readonly replayCache?: IdTokenReplayCache;
}

export interface RefreshIdTokenContext extends AuthenticationRequirements {
  readonly purpose: "refresh";
  readonly previousIdentity: OidcIdentityEvidence;
}

export interface SessionIdTokenContext extends AuthenticationRequirements {
  readonly purpose: "session";
}

export type IdTokenValidationContext =
  | AuthorizationCodeIdTokenContext
  | RefreshIdTokenContext
  | SessionIdTokenContext;

export interface OidcIdTokenVerifierOptions {
  authority: string;
  clientId: string;
  allowedAlgorithms?: readonly IdTokenSigningAlgorithm[];
  clockSkewToleranceSeconds?: number;
  cacheTtlMs?: number;
  metadataRequestTimeoutMs?: number;
  jwksUri?: string;
  fetcher?: typeof fetch;
}

export type VerifyIdTokenOptions = OidcIdTokenVerifierOptions &
  IdTokenValidationContext;

export interface VerifiedIdTokenPayload extends JWTPayload {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string | readonly string[];
  readonly exp: number;
  readonly iat: number;
}

const VERIFIED_ID_TOKEN: unique symbol = Symbol("VerifiedIdToken");
const VERIFY_HISTORICAL_IDENTITY: unique symbol = Symbol(
  "verifyHistoricalIdTokenIdentity",
);

/** A signature- and purpose-verified ID token. Instances are verifier-created. */
export interface VerifiedIdToken {
  readonly [VERIFIED_ID_TOKEN]: true;
  readonly header: Readonly<JWTHeader>;
  readonly payload: VerifiedIdTokenPayload;
  readonly identity: OidcIdentity;
}

interface CachedValue<T> {
  expiresAt: number;
  value: T;
}

interface DiscoveryMetadata {
  issuer: string;
  jwksUri: string;
  signingAlgorithms: readonly string[];
}

function failValidation(reason: string, cause?: unknown): never {
  throw new GuardhouseError(
    `ID token validation failed: ${reason}`,
    "ID_TOKEN_VALIDATION_FAILED",
    cause === undefined ? undefined : { cause },
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

export function isOidcIdentityEvidence(
  value: unknown,
): value is OidcIdentityEvidence {
  if (!isRecord(value)) return false;
  const evidence = verifiedOidcIdentityEvidence.get(value);
  return evidence?.status === "current" || evidence?.status === "historical";
}

function getVerifiedIdentityContext(
  identity: OidcIdentityEvidence,
): VerifiedIdentityContext {
  const context = verifiedOidcIdentityEvidence.get(identity);
  if (!context) {
    throw new GuardhouseError(
      "previousIdentity must be genuine verified OIDC identity evidence",
      "OIDC_CONFIGURATION_ERROR",
    );
  }
  return context;
}

function createOidcIdentityEvidence<TStatus extends "current" | "historical">(
  metadata: OidcIdentityMetadata,
  status: TStatus,
  continuity: Pick<OidcIdentityMetadata, "nonce" | "authTime"> = metadata,
): TStatus extends "current" ? OidcIdentity : HistoricalOidcIdentity {
  const identity = {
    ...metadata,
    audiences: Object.freeze([...metadata.audiences]),
    amr: Object.freeze([...metadata.amr]),
  } as OidcIdentityMetadata & {
    [VERIFIED_OIDC_IDENTITY]?: "current" | "historical";
  };
  Object.defineProperty(identity, VERIFIED_OIDC_IDENTITY, {
    value: status,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  verifiedOidcIdentityEvidence.set(
    identity,
    Object.freeze({
      status,
      nonce: continuity.nonce,
      authTime: continuity.authTime,
    }),
  );

  return Object.freeze(identity) as TStatus extends "current"
    ? OidcIdentity
    : HistoricalOidcIdentity;
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new GuardhouseError(
      `${name} must be a non-empty string`,
      "OIDC_CONFIGURATION_ERROR",
    );
  }

  return value.trim();
}

function requireExactContextString(value: unknown, name: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value !== value.trim()
  ) {
    throw new GuardhouseError(
      `${name} must be a non-empty exact string`,
      "OIDC_CONFIGURATION_ERROR",
    );
  }

  return value;
}

function snapshotAuthenticationRequirements(
  context: Record<string, unknown>,
): AuthenticationRequirements {
  const snapshot: {
    allowedAdditionalIdTokenAudiences?: readonly string[];
    requiredAcrValues?: readonly string[];
    requiredAmrValues?: readonly string[];
  } = {};

  for (const name of [
    "allowedAdditionalIdTokenAudiences",
    "requiredAcrValues",
    "requiredAmrValues",
  ] as const) {
    const values = context[name];
    if (
      values !== undefined &&
      (!Array.isArray(values) ||
        values.some(
          (value) =>
            typeof value !== "string" ||
            value.length === 0 ||
            value !== value.trim(),
        ))
    ) {
      throw new GuardhouseError(
        `${name} must contain non-empty exact strings`,
        "OIDC_CONFIGURATION_ERROR",
      );
    }

    if (values !== undefined) {
      snapshot[name] = Object.freeze([...(values as string[])]);
    }
  }

  return Object.freeze(snapshot);
}

function snapshotValidationContext(context: unknown): IdTokenValidationContext {
  if (!isRecord(context)) {
    throw new GuardhouseError(
      "ID token validation context is required",
      "OIDC_CONFIGURATION_ERROR",
    );
  }

  const purpose = context["purpose"];
  if (
    purpose !== "authorization_code" &&
    purpose !== "refresh" &&
    purpose !== "session"
  ) {
    throw new GuardhouseError(
      "ID token validation purpose is invalid",
      "OIDC_CONFIGURATION_ERROR",
    );
  }

  const requirements = snapshotAuthenticationRequirements(context);

  if (purpose === "authorization_code") {
    const nonce = requireExactContextString(context["nonce"], "nonce");
    const maxAgeSeconds = context["maxAgeSeconds"];
    if (
      maxAgeSeconds !== undefined &&
      (typeof maxAgeSeconds !== "number" ||
        !Number.isFinite(maxAgeSeconds) ||
        maxAgeSeconds < 0)
    ) {
      throw new GuardhouseError(
        "maxAgeSeconds must be a non-negative number",
        "OIDC_CONFIGURATION_ERROR",
      );
    }
    const replayCache = context["replayCache"];
    if (
      replayCache !== undefined &&
      (!isRecord(replayCache) || typeof replayCache["consume"] !== "function")
    ) {
      throw new GuardhouseError(
        "replayCache must implement consume",
        "OIDC_CONFIGURATION_ERROR",
      );
    }

    return Object.freeze({
      ...requirements,
      purpose,
      nonce,
      ...(maxAgeSeconds === undefined ? {} : { maxAgeSeconds }),
      ...(replayCache === undefined
        ? {}
        : { replayCache: replayCache as unknown as IdTokenReplayCache }),
    });
  } else if (purpose === "refresh") {
    const previousIdentity = context["previousIdentity"];
    if (!isOidcIdentityEvidence(previousIdentity)) {
      throw new GuardhouseError(
        "previousIdentity must be genuine verified OIDC identity evidence",
        "OIDC_CONFIGURATION_ERROR",
      );
    }

    return Object.freeze({
      ...requirements,
      purpose,
      previousIdentity,
    });
  }

  return Object.freeze({ ...requirements, purpose });
}

function validateAuthority(authority: string): string {
  const issuer = requireString(authority, "authority");
  let url: URL;

  try {
    url = new URL(issuer);
    enforceSecureHttpUrl(url, "OIDC authority");
    enforceNonSpoofableHostname(url, "OIDC authority");
  } catch (error) {
    throw new GuardhouseError(
      "authority must be a trusted HTTP(S) URL",
      "OIDC_CONFIGURATION_ERROR",
      { cause: error },
    );
  }

  if (url.username || url.password || url.search || url.hash) {
    throw new GuardhouseError(
      "authority must not contain credentials, a query, or a fragment",
      "OIDC_CONFIGURATION_ERROR",
    );
  }

  // Issuer identifiers are compared exactly. URL parsing is validation only.
  return issuer;
}

function buildDiscoveryUrl(issuer: string): string {
  return `${issuer.endsWith("/") ? issuer : `${issuer}/`}.well-known/openid-configuration`;
}

function validateJwksUri(value: unknown): string {
  let url: URL;

  try {
    url = new URL(requireString(value, "jwks_uri"));
    enforceSecureHttpUrl(url, "JWKS URI");
    enforceNonSpoofableHostname(url, "JWKS URI");
  } catch (error) {
    throw new GuardhouseError(
      "jwks_uri is invalid",
      "OIDC_CONFIGURATION_ERROR",
      { cause: error },
    );
  }

  if (url.username || url.password || url.hash) {
    throw new GuardhouseError(
      "jwks_uri must not contain credentials or a fragment",
      "OIDC_CONFIGURATION_ERROR",
    );
  }

  return url.toString();
}

function numericDate(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    failValidation(`${name} must be a NumericDate`);
  }

  return value;
}

function validateOptionalStringClaim(
  payload: JWTPayload,
  name: keyof JWTPayload,
  exact: boolean,
): void {
  const value = payload[name];
  if (value === undefined) return;

  if (typeof value !== "string") {
    failValidation(`${String(name)} must be a string`);
  }
  if (exact && (value.length === 0 || value !== value.trim())) {
    failValidation(`${String(name)} must be a non-empty exact string`);
  }
}

function validateStringArrayClaim(value: unknown, name: string): void {
  if (
    !Array.isArray(value) ||
    value.some(
      (entry) =>
        typeof entry !== "string" ||
        entry.length === 0 ||
        entry !== entry.trim(),
    )
  ) {
    failValidation(`${name} must be an array of non-empty exact strings`);
  }
}

function validateTypedPayloadClaims(payload: JWTPayload): void {
  for (const name of [
    "iss",
    "sub",
    "azp",
    "acr",
    "at_hash",
    "c_hash",
    "jti",
    "nonce",
    "sid",
  ] as const) {
    validateOptionalStringClaim(payload, name, true);
  }
  for (const name of ["name", "email", "picture", "profile"] as const) {
    validateOptionalStringClaim(payload, name, false);
  }

  if (payload.aud !== undefined) normalizeAudience(payload.aud);
  for (const name of ["exp", "nbf", "iat", "auth_time"] as const) {
    if (payload[name] !== undefined) numericDate(payload[name], name);
  }
  for (const name of ["amr", "roles", "scopes"] as const) {
    if (payload[name] !== undefined) {
      validateStringArrayClaim(payload[name], name);
    }
  }

  for (const name of ["cnf", "address"] as const) {
    if (payload[name] !== undefined && !isRecord(payload[name])) {
      failValidation(`${name} must be an object`);
    }
  }
  if (payload.cnf?.jkt !== undefined) {
    claimString(payload.cnf.jkt, "cnf.jkt");
  }
}

function validateTypedHeaderClaims(header: JWTHeader): void {
  claimString(header.alg, "alg");
  if (header.typ !== undefined) claimString(header.typ, "typ");
  if (header.kid !== undefined) claimString(header.kid, "kid");
  if (header.jku !== undefined) claimString(header.jku, "jku");
  if (header.crit !== undefined) {
    validateStringArrayClaim(header.crit, "crit");
    if (new Set(header.crit).size !== header.crit.length) {
      failValidation("crit must not contain duplicate values");
    }
  }
}

function cloneAndFreezeJson(value: unknown, name: string): unknown {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean"
  ) {
    return value;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      failValidation(`${name} contains a non-finite number`);
    }
    return value;
  }
  if (Array.isArray(value)) {
    return Object.freeze(
      value.map((entry, index) =>
        cloneAndFreezeJson(entry, `${name}[${index}]`),
      ),
    );
  }
  if (isRecord(value)) {
    const clone: Record<string, unknown> = {};
    for (const [key, entry] of Object.entries(value)) {
      Object.defineProperty(clone, key, {
        value: cloneAndFreezeJson(entry, `${name}.${key}`),
        enumerable: true,
        configurable: false,
        writable: false,
      });
    }
    return Object.freeze(clone);
  }

  failValidation(`${name} contains a non-JSON value`);
}

function cloneAndFreezeRecord<T extends Record<string, unknown>>(
  value: T,
  name: string,
): Readonly<T> {
  return cloneAndFreezeJson(value, name) as Readonly<T>;
}

function claimString(value: unknown, name: string): string {
  if (typeof value !== "string" || !value || value !== value.trim()) {
    failValidation(`${name} must be a non-empty exact string`);
  }

  return value;
}

function normalizeAudience(value: unknown): readonly string[] {
  if (typeof value === "string" && value && value === value.trim()) {
    return [value];
  }

  if (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every(
      (entry) => typeof entry === "string" && entry && entry === entry.trim(),
    )
  ) {
    return value as readonly string[];
  }

  failValidation("aud must be a non-empty string or string array");
}

function validateExplicitType(header: JWTHeader): void {
  if (
    header.typ !== undefined &&
    header.typ !== "JWT" &&
    header.typ !== "application/JWT"
  ) {
    failValidation("typ must be absent, JWT, or application/JWT");
  }
}

function validateTemporalClaimsAt(
  issuedAt: number,
  expiresAt: number,
  notBefore: number | null,
  authTime: number | null,
  context: IdTokenValidationContext,
  clockSkew: number,
  allowExpired: boolean,
  now: number,
): void {
  if (issuedAt > now + clockSkew) failValidation("iat is in the future");
  if (expiresAt <= issuedAt) failValidation("exp must be later than iat");
  if (!allowExpired && expiresAt <= now - clockSkew) {
    failValidation("exp indicates an expired token");
  }

  if (notBefore !== null) {
    if (notBefore >= expiresAt) {
      failValidation("nbf must be earlier than exp");
    }
    if (notBefore > now + clockSkew) {
      failValidation("nbf is in the future");
    }
  }

  if (authTime !== null) {
    if (authTime > now + clockSkew) {
      failValidation("auth_time is in the future");
    }
    if (authTime > issuedAt + clockSkew) {
      failValidation("auth_time must not be later than iat");
    }
  }

  if (
    context.purpose === "authorization_code" &&
    context.maxAgeSeconds !== undefined
  ) {
    if (authTime === null) {
      failValidation("auth_time is required when maxAgeSeconds is supplied");
    }
    if (now - authTime > context.maxAgeSeconds + clockSkew) {
      failValidation("auth_time exceeds maxAgeSeconds");
    }
  }
}

async function validateGuardhouseIdTokenClaims(
  payload: JWTPayload,
  issuer: string,
  clientId: string,
  context: IdTokenValidationContext,
  clockSkew: number,
  allowExpired = false,
): Promise<OidcIdentityMetadata> {
  validateTypedPayloadClaims(payload);

  const tokenIssuer = claimString(payload.iss, "iss");
  if (tokenIssuer !== issuer)
    failValidation("iss does not exactly match issuer");

  const subject = claimString(payload.sub, "sub");

  const issuedAt = numericDate(payload.iat, "iat");
  const expiresAt = numericDate(payload.exp, "exp");
  const notBefore =
    payload.nbf === undefined ? null : numericDate(payload.nbf, "nbf");
  const now = Math.floor(Date.now() / 1000);

  const audiences = normalizeAudience(payload.aud);
  if (!audiences.includes(clientId)) {
    failValidation("aud must include clientId");
  }
  const allowedAudiences = new Set([
    clientId,
    ...(context.allowedAdditionalIdTokenAudiences ?? []),
  ]);
  if (audiences.some((audience) => !allowedAudiences.has(audience))) {
    failValidation("aud contains an additional audience that is not allowed");
  }
  if (new Set(audiences).size !== audiences.length) {
    failValidation("aud must not contain duplicate audiences");
  }
  if (audiences.length > 1 && payload.azp !== clientId) {
    failValidation("azp must exactly match clientId for multiple audiences");
  }
  if (payload.azp !== undefined && payload.azp !== clientId) {
    failValidation("azp must exactly match clientId");
  }

  const tokenNonce =
    payload.nonce === undefined ? null : claimString(payload.nonce, "nonce");
  const acr =
    payload.acr === undefined ? null : claimString(payload.acr, "acr");
  const sessionId =
    payload.sid === undefined ? null : claimString(payload.sid, "sid");

  if (context.purpose === "authorization_code") {
    const nonce = requireExactContextString(context.nonce, "nonce");
    if (
      tokenNonce === null ||
      tokenNonce.length !== nonce.length ||
      !timingSafeEqual(tokenNonce, nonce)
    ) {
      failValidation("nonce does not match");
    }

    if (
      context.maxAgeSeconds !== undefined &&
      (!Number.isFinite(context.maxAgeSeconds) || context.maxAgeSeconds < 0)
    ) {
      throw new GuardhouseError(
        "maxAgeSeconds must be a non-negative number",
        "OIDC_CONFIGURATION_ERROR",
      );
    }
  }

  const requiredAcrValues = new Set(
    (context.requiredAcrValues ?? []).map((value) =>
      requireString(value, "requiredAcrValues entry"),
    ),
  );
  if (
    requiredAcrValues.size > 0 &&
    (acr === null || !requiredAcrValues.has(acr))
  ) {
    failValidation("acr does not satisfy the required authentication context");
  }

  const amr = payload.amr ?? [];
  const tokenAmr = new Set(amr);
  for (const requiredAmr of context.requiredAmrValues ?? []) {
    if (!tokenAmr.has(requireString(requiredAmr, "requiredAmrValues entry"))) {
      failValidation(
        "amr does not contain every required authentication method",
      );
    }
  }

  let authTime: number | null = null;
  if (payload.auth_time !== undefined) {
    authTime = numericDate(payload.auth_time, "auth_time");
  }

  validateTemporalClaimsAt(
    issuedAt,
    expiresAt,
    notBefore,
    authTime,
    context,
    clockSkew,
    allowExpired,
    now,
  );

  const identity: OidcIdentityMetadata = Object.freeze({
    issuer: tokenIssuer,
    clientId,
    subject,
    audiences: Object.freeze([...audiences].sort()),
    authorizedParty: payload.azp ?? null,
    issuedAt,
    expiresAt,
    nonce: tokenNonce,
    authTime,
    acr,
    amr: Object.freeze([...amr]),
    sessionId,
  });

  if (context.purpose === "authorization_code") {
    if (context.replayCache) {
      const jti = claimString(payload.jti, "jti");
      let consumed = false;
      try {
        consumed =
          (await context.replayCache.consume(
            Object.freeze({
              issuer: tokenIssuer,
              jti,
              expiresAt,
            }),
          )) === true;
      } catch (error) {
        failValidation("replay protection failed", error);
      }
      if (!consumed) {
        failValidation("ID token replay was detected or cache is full");
      }

      // A custom replay cache may perform network or durable-storage I/O. The
      // token must still satisfy every time-based condition when verified
      // evidence is actually issued, not only before that await.
      validateTemporalClaimsAt(
        issuedAt,
        expiresAt,
        notBefore,
        authTime,
        context,
        clockSkew,
        allowExpired,
        Math.floor(Date.now() / 1000),
      );
    }
  } else if (context.purpose === "refresh") {
    const previous = context.previousIdentity;
    const previousContext = getVerifiedIdentityContext(previous);
    const previousAudiences = [...previous.audiences].sort();
    const currentAudiences = [...identity.audiences].sort();
    if (
      previous.issuer !== identity.issuer ||
      previous.clientId !== identity.clientId ||
      previous.subject !== identity.subject ||
      previousAudiences.length !== currentAudiences.length ||
      previousAudiences.some(
        (audience, index) => audience !== currentAudiences[index],
      ) ||
      previous.authorizedParty !== identity.authorizedParty ||
      (identity.nonce !== null && identity.nonce !== previousContext.nonce) ||
      (identity.authTime !== null &&
        identity.authTime !== previousContext.authTime)
    ) {
      failValidation("refresh identity continuity check failed");
    }
  }

  return identity;
}

function isRetryableKeyVerificationError(error: unknown): boolean {
  if (!isRecord(error)) return false;

  return (
    error["code"] === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED" ||
    error["code"] === "ERR_JWKS_NO_MATCHING_KEY"
  );
}

export class OidcIdTokenVerifier {
  private readonly authority: string;
  private readonly clientId: string;
  private readonly allowedAlgorithms: readonly IdTokenSigningAlgorithm[];
  private readonly allowedAlgorithmSet: ReadonlySet<IdTokenSigningAlgorithm>;
  private readonly clockSkew: number;
  private readonly cacheTtlMs: number;
  private readonly metadataRequestTimeoutMs: number;
  private readonly configuredJwksUri?: string;
  private readonly fetcher: typeof fetch;

  private discoveryCache: CachedValue<DiscoveryMetadata> | null = null;
  private discoveryRequest: Promise<DiscoveryMetadata> | null = null;
  private remoteJwks: ReturnType<typeof createRemoteJWKSet> | null = null;
  private remoteJwksUri: string | null = null;
  private jwksRefreshRequest: Promise<void> | null = null;
  private lastForcedRefreshAt = 0;

  constructor(options: OidcIdTokenVerifierOptions) {
    this.authority = validateAuthority(options.authority);
    this.clientId = requireString(options.clientId, "clientId");

    const configuredAlgorithms =
      options.allowedAlgorithms ??
      (ALLOWED_OIDC_ALGORITHMS as IdTokenSigningAlgorithm[]);
    if (
      configuredAlgorithms.length === 0 ||
      configuredAlgorithms.some(
        (algorithm) => !SUPPORTED_SIGNING_ALGORITHMS.has(algorithm),
      )
    ) {
      throw new GuardhouseError(
        "allowedAlgorithms must contain only supported asymmetric algorithms",
        "OIDC_CONFIGURATION_ERROR",
      );
    }

    this.allowedAlgorithms = Array.from(new Set(configuredAlgorithms));
    this.allowedAlgorithmSet = new Set(this.allowedAlgorithms);
    this.clockSkew =
      options.clockSkewToleranceSeconds ?? DEFAULT_CLOCK_SKEW_SECONDS;
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
    this.metadataRequestTimeoutMs =
      options.metadataRequestTimeoutMs ?? METADATA_REQUEST_TIMEOUT_MS;
    this.configuredJwksUri =
      options.jwksUri === undefined
        ? undefined
        : validateJwksUri(options.jwksUri);

    if (
      !Number.isFinite(this.clockSkew) ||
      this.clockSkew < 0 ||
      this.clockSkew > MAX_CLOCK_SKEW_TOLERANCE_SECONDS
    ) {
      throw new GuardhouseError(
        `clockSkewToleranceSeconds must be between 0 and ${MAX_CLOCK_SKEW_TOLERANCE_SECONDS}`,
        "OIDC_CONFIGURATION_ERROR",
      );
    }
    if (!Number.isFinite(this.cacheTtlMs) || this.cacheTtlMs < 0) {
      throw new GuardhouseError(
        "cacheTtlMs must be non-negative",
        "OIDC_CONFIGURATION_ERROR",
      );
    }
    if (
      !Number.isFinite(this.metadataRequestTimeoutMs) ||
      this.metadataRequestTimeoutMs <= 0 ||
      this.metadataRequestTimeoutMs > 30_000
    ) {
      throw new GuardhouseError(
        "metadataRequestTimeoutMs must be between 1 and 30000",
        "OIDC_CONFIGURATION_ERROR",
      );
    }

    const fetcher = options.fetcher ?? globalThis.fetch;
    if (typeof fetcher !== "function") {
      throw new GuardhouseError(
        "fetch is unavailable for OIDC discovery",
        "OIDC_CONFIGURATION_ERROR",
      );
    }
    this.fetcher = fetcher.bind(globalThis);
  }

  async verify(
    idToken: string,
    context: IdTokenValidationContext,
  ): Promise<VerifiedIdToken> {
    // Copy all caller-controlled policy synchronously. Verification performs
    // network I/O, so retaining the caller's mutable object would allow its
    // purpose or assurance requirements to change after verification starts.
    const contextSnapshot = snapshotValidationContext(context);
    const { payload, header } = await this.verifyCryptographically(
      idToken,
      false,
    );
    const identity = await validateGuardhouseIdTokenClaims(
      payload,
      this.authority,
      this.clientId,
      contextSnapshot,
      this.clockSkew,
    );

    const frozenHeader = cloneAndFreezeRecord(
      header as Record<string, unknown>,
      "header",
    ) as Readonly<JWTHeader>;
    const frozenPayload = cloneAndFreezeRecord(
      payload as Record<string, unknown>,
      "payload",
    ) as VerifiedIdTokenPayload;

    return Object.freeze({
      [VERIFIED_ID_TOKEN]: true as const,
      header: frozenHeader,
      payload: frozenPayload,
      identity: createOidcIdentityEvidence(
        identity,
        "current",
        contextSnapshot.purpose === "refresh"
          ? getVerifiedIdentityContext(contextSnapshot.previousIdentity)
          : identity,
      ),
    });
  }

  async [VERIFY_HISTORICAL_IDENTITY](
    idToken: string,
    requirements: AuthenticationRequirements = {},
  ): Promise<HistoricalOidcIdentity> {
    const requirementsSnapshot = snapshotAuthenticationRequirements(
      requirements as Record<string, unknown>,
    );
    const { payload } = await this.verifyCryptographically(idToken, true);
    return createOidcIdentityEvidence(
      await validateGuardhouseIdTokenClaims(
        payload,
        this.authority,
        this.clientId,
        {
          purpose: "session",
          ...requirementsSnapshot,
        },
        this.clockSkew,
        true,
      ),
      "historical",
    );
  }

  private async verifyCryptographically(
    idToken: string,
    historical: boolean,
  ): Promise<{ payload: JWTPayload; header: JWTHeader }> {
    const decodedJWT = decodeJWT(idToken);
    const algorithm = decodedJWT.header.alg as IdTokenSigningAlgorithm;

    validateTypedHeaderClaims(decodedJWT.header);
    validateExplicitType(decodedJWT.header);
    if (!this.allowedAlgorithmSet.has(algorithm)) {
      failValidation(`alg ${decodedJWT.header.alg} is not allowed`);
    }
    if (
      decodedJWT.header.jku !== undefined ||
      decodedJWT.header["x5u"] !== undefined ||
      decodedJWT.header["jwk"] !== undefined
    ) {
      failValidation("token-supplied key locations are not trusted");
    }

    const discovery = await this.getDiscovery();
    if (!discovery.signingAlgorithms.includes(algorithm)) {
      failValidation("alg is not advertised by OIDC discovery metadata");
    }

    const remoteJwks = this.getRemoteJwks(discovery.jwksUri);
    const hadFreshJwks = remoteJwks.fresh;
    const observedRefreshAt = this.lastForcedRefreshAt;
    const attemptVerification = async (): Promise<{
      payload: JWTPayload;
      header: JWTHeader;
    }> => {
      if (historical) {
        const verified = await compactVerify(idToken, remoteJwks, {
          algorithms: [...this.allowedAlgorithms],
        });
        return {
          payload: decodedJWT.payload,
          header: verified.protectedHeader as JWTHeader,
        };
      }

      const verified = await this.verifyWithJose(idToken, remoteJwks);
      return {
        payload: verified.payload as JWTPayload,
        header: verified.protectedHeader as JWTHeader,
      };
    };

    let verified: { payload: JWTPayload; header: JWTHeader };

    try {
      verified = await attemptVerification();
    } catch (error) {
      if (
        !hadFreshJwks ||
        !isRetryableKeyVerificationError(error) ||
        !(await this.reloadJwks(remoteJwks, observedRefreshAt))
      ) {
        failValidation("signature or standard claims are invalid", error);
      }

      try {
        verified = await attemptVerification();
      } catch (retryError) {
        failValidation("signature or standard claims are invalid", retryError);
      }
    }

    return verified;
  }

  private verifyWithJose(
    idToken: string,
    remoteJwks: ReturnType<typeof createRemoteJWKSet>,
  ) {
    return jwtVerify(idToken, remoteJwks, {
      algorithms: [...this.allowedAlgorithms],
      issuer: this.authority,
      audience: this.clientId,
      clockTolerance: this.clockSkew,
      requiredClaims: ["iss", "sub", "aud", "exp", "iat"],
    });
  }

  private getRemoteJwks(
    jwksUri: string,
  ): ReturnType<typeof createRemoteJWKSet> {
    if (this.remoteJwks && this.remoteJwksUri === jwksUri) {
      return this.remoteJwks;
    }

    const boundedFetch: FetchImplementation = (url, options) =>
      this.fetcher(url, {
        ...options,
        cache: "no-store",
        credentials: "omit",
      });

    this.remoteJwks = createRemoteJWKSet(new URL(jwksUri), {
      timeoutDuration: this.metadataRequestTimeoutMs,
      cooldownDuration: FORCED_REFRESH_COOLDOWN_MS,
      cacheMaxAge: this.cacheTtlMs,
      [customFetch]: boundedFetch,
    });
    this.remoteJwksUri = jwksUri;
    this.jwksRefreshRequest = null;
    this.lastForcedRefreshAt = 0;
    return this.remoteJwks;
  }

  private async reloadJwks(
    remoteJwks: ReturnType<typeof createRemoteJWKSet>,
    observedRefreshAt: number,
  ): Promise<boolean> {
    if (this.jwksRefreshRequest) {
      await this.jwksRefreshRequest;
      return true;
    }

    if (this.lastForcedRefreshAt > observedRefreshAt) {
      return true;
    }

    const now = Date.now();
    if (now - this.lastForcedRefreshAt < FORCED_REFRESH_COOLDOWN_MS) {
      return false;
    }

    this.lastForcedRefreshAt = now;
    const refresh = remoteJwks.reload();
    this.jwksRefreshRequest = refresh;

    try {
      await refresh;
      return true;
    } catch (error) {
      failValidation("JWKS refresh failed", error);
    } finally {
      if (this.jwksRefreshRequest === refresh) {
        this.jwksRefreshRequest = null;
      }
    }

    return false;
  }

  private async getDiscovery(): Promise<DiscoveryMetadata> {
    if (this.configuredJwksUri) {
      return {
        issuer: this.authority,
        jwksUri: this.configuredJwksUri,
        signingAlgorithms: this.allowedAlgorithms,
      };
    }

    if (this.discoveryCache && this.discoveryCache.expiresAt > Date.now()) {
      return this.discoveryCache.value;
    }
    if (this.discoveryRequest) return this.discoveryRequest;

    const request = this.fetchDiscovery();
    this.discoveryRequest = request;

    try {
      return await request;
    } finally {
      if (this.discoveryRequest === request) this.discoveryRequest = null;
    }
  }

  private async fetchDiscovery(): Promise<DiscoveryMetadata> {
    const raw = await this.fetchJson(
      buildDiscoveryUrl(this.authority),
      "OIDC discovery",
    );
    if (!isRecord(raw)) {
      throw new GuardhouseError(
        "OIDC discovery response must be an object",
        "OIDC_DISCOVERY_FAILED",
      );
    }
    if (raw["issuer"] !== this.authority) {
      throw new GuardhouseError(
        "OIDC discovery issuer does not exactly match authority",
        "OIDC_DISCOVERY_FAILED",
      );
    }

    const advertisedAlgorithms = raw["id_token_signing_alg_values_supported"];
    if (
      !Array.isArray(advertisedAlgorithms) ||
      advertisedAlgorithms.length === 0 ||
      advertisedAlgorithms.some(
        (value) => typeof value !== "string" || value.trim() === "",
      )
    ) {
      throw new GuardhouseError(
        "OIDC discovery must advertise ID token signing algorithms",
        "OIDC_DISCOVERY_FAILED",
      );
    }
    if (!advertisedAlgorithms.includes("RS256")) {
      throw new GuardhouseError(
        "OIDC discovery ID token signing algorithms must include RS256",
        "OIDC_DISCOVERY_FAILED",
      );
    }

    let jwksUri: string;
    try {
      jwksUri = validateJwksUri(raw["jwks_uri"]);
    } catch (error) {
      throw new GuardhouseError(
        "OIDC discovery jwks_uri is invalid",
        "OIDC_DISCOVERY_FAILED",
        { cause: error },
      );
    }
    const value: DiscoveryMetadata = {
      issuer: this.authority,
      jwksUri,
      signingAlgorithms: Object.freeze([...advertisedAlgorithms] as string[]),
    };
    this.discoveryCache = {
      value,
      expiresAt: Date.now() + this.cacheTtlMs,
    };
    return value;
  }

  private async fetchJson(url: string, name: string): Promise<unknown> {
    const controller = new AbortController();
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_resolve, reject) => {
      timeoutHandle = setTimeout(() => {
        controller.abort();
        reject(new Error(`${name} request timed out`));
      }, this.metadataRequestTimeoutMs);
    });

    try {
      const response = await Promise.race([
        this.fetcher(url, {
          method: "GET",
          cache: "no-store",
          credentials: "omit",
          redirect: "error",
          signal: controller.signal,
          headers: { Accept: "application/json" },
        }),
        timeout,
      ]);

      if (!response.ok) {
        throw new GuardhouseError(
          `${name} request failed with status ${response.status}`,
          "OIDC_METADATA_REQUEST_FAILED",
          response.status,
        );
      }

      const body = await Promise.race([
        this.readBoundedResponseBody(response, controller, name),
        timeout,
      ]);
      if (!body) {
        throw new GuardhouseError(
          `${name} response is empty`,
          "OIDC_METADATA_REQUEST_FAILED",
        );
      }

      try {
        return JSON.parse(body) as unknown;
      } catch (error) {
        throw new GuardhouseError(
          `${name} response is not valid JSON`,
          "OIDC_METADATA_REQUEST_FAILED",
          { cause: error },
        );
      }
    } catch (error) {
      if (error instanceof GuardhouseError) throw error;
      throw new GuardhouseError(
        `${name} request failed`,
        "OIDC_METADATA_REQUEST_FAILED",
        { cause: error },
      );
    } finally {
      if (timeoutHandle) clearTimeout(timeoutHandle);
    }
  }

  private async readBoundedResponseBody(
    response: Response,
    controller: AbortController,
    name: string,
  ): Promise<string> {
    const advertisedLength = response.headers.get("Content-Length");
    if (
      advertisedLength &&
      /^\d+$/.test(advertisedLength.trim()) &&
      Number(advertisedLength) > MAX_METADATA_RESPONSE_BYTES
    ) {
      controller.abort();
      throw new GuardhouseError(
        `${name} response is too large`,
        "OIDC_METADATA_REQUEST_FAILED",
      );
    }

    if (!response.body) return response.text();

    const reader = response.body.getReader();
    const cancelOnAbort = () => {
      void reader.cancel().catch(() => undefined);
    };
    controller.signal.addEventListener("abort", cancelOnAbort, { once: true });
    const decoder = new TextDecoder();
    let body = "";
    let receivedBytes = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) return body + decoder.decode();

        receivedBytes += value.byteLength;
        if (receivedBytes > MAX_METADATA_RESPONSE_BYTES) {
          controller.abort();
          await reader.cancel().catch(() => undefined);
          throw new GuardhouseError(
            `${name} response is too large`,
            "OIDC_METADATA_REQUEST_FAILED",
          );
        }

        body += decoder.decode(value, { stream: true });
      }
    } finally {
      controller.signal.removeEventListener("abort", cancelOnAbort);
      reader.releaseLock();
    }
  }
}

/**
 * Re-verifies a stored ID token solely to recover its signed identity tuple.
 * Expiration is still required and finite, but a past expiration is permitted
 * because the result is not a current-token capability.
 *
 * @internal Import from this module only; intentionally not barrel-exported.
 */
export async function verifyHistoricalIdTokenIdentity(
  idToken: string,
  options: OidcIdTokenVerifierOptions & AuthenticationRequirements,
): Promise<HistoricalOidcIdentity> {
  const verifier = new OidcIdTokenVerifier(options);
  return verifier[VERIFY_HISTORICAL_IDENTITY](idToken, {
    allowedAdditionalIdTokenAudiences:
      options.allowedAdditionalIdTokenAudiences,
    requiredAcrValues: options.requiredAcrValues,
    requiredAmrValues: options.requiredAmrValues,
  });
}

export async function verifyIdToken(
  idToken: string,
  options: VerifyIdTokenOptions,
): Promise<VerifiedIdToken> {
  return new OidcIdTokenVerifier(options).verify(idToken, options);
}
