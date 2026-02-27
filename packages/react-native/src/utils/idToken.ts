import { decodeJWT, validateToken } from "@guardhouse/core";
import type {
  DecodedJWT,
  ExpectedJwkKeyType,
  JwkMetadata,
  VerifiedSignatureProof,
} from "@guardhouse/core";
import { createReactNativeLogger } from "../debug";

const OPENID_DISCOVERY_PATH = "/.well-known/openid-configuration";
const DISCOVERY_CACHE_TTL_MS = 5 * 60 * 1000;
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;

interface DiscoveryCacheEntry {
  jwksUri: string;
  expiresAt: number;
}

interface JwksCacheEntry {
  jwksUri: string;
  keys: JwkMetadata[];
  expiresAt: number;
}

interface VerificationAlgorithmConfig {
  importAlgorithm:
    | AlgorithmIdentifier
    | RsaHashedImportParams
    | EcKeyImportParams;
  verifyAlgorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
  joseEcdsaSignature: boolean;
}

export interface RedirectUriDescriptor {
  protocol: string;
  hostname: string;
  port: string;
  pathname: string;
}

export interface IdTokenValidatorOptions {
  authority: string;
  clientId: string;
  jwksUri?: string;
  requiredAcrValues?: string[];
  requiredAmrValues?: string[];
  requireWebAuthn?: boolean;
  requirePhishingResistantMfa?: boolean;
  allowInsecureIdTokenValidation?: boolean;
  debug?: boolean;
}

function normalizePathname(pathname: string): string {
  if (!pathname || pathname === "/") {
    return "/";
  }

  return pathname.replace(/\/+$/, "");
}

function normalizeIssuer(value: string): string {
  return value.trim().replace(/\/+$/, "");
}

function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1"
  );
}

function assertSecureUrl(url: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`${label} is not a valid URL`);
  }

  const isHttps = parsed.protocol === "https:";
  const isHttpLoopback =
    parsed.protocol === "http:" && isLoopbackHost(parsed.hostname);

  if (!isHttps && !isHttpLoopback) {
    throw new Error(
      `${label} must use HTTPS (or HTTP for loopback hosts in development)`,
    );
  }

  return parsed.toString();
}

function normalizeStringValues(values: string[] | undefined): string[] {
  if (!values || values.length === 0) {
    return [];
  }

  const deduplicated = new Set<string>();
  for (const value of values) {
    const normalized = value.trim();
    if (normalized) {
      deduplicated.add(normalized);
    }
  }

  return Array.from(deduplicated);
}

function normalizeExpectedJwkKeyType(
  value: unknown,
): ExpectedJwkKeyType | undefined {
  return value === "RSA" || value === "EC" || value === "OKP" || value === "oct"
    ? value
    : undefined;
}

function expectedKeyTypeForAlgorithm(
  algorithm: string,
): ExpectedJwkKeyType | undefined {
  if (algorithm.startsWith("RS") || algorithm.startsWith("PS")) {
    return "RSA";
  }

  if (algorithm.startsWith("ES")) {
    return "EC";
  }

  if (algorithm === "EdDSA") {
    return "OKP";
  }

  return undefined;
}

function base64UrlToBytes(segment: string): Uint8Array<ArrayBuffer> {
  const base64 = segment.replace(/-/g, "+").replace(/_/g, "/");
  const padding = (4 - (base64.length % 4)) % 4;
  const padded = `${base64}${"=".repeat(padding)}`;
  const decoded = atob(padded);
  const bytes = new Uint8Array(new ArrayBuffer(decoded.length));

  for (let i = 0; i < decoded.length; i += 1) {
    bytes[i] = decoded.charCodeAt(i);
  }

  return bytes;
}

function asciiToBytes(value: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(value.length));
  for (let i = 0; i < value.length; i += 1) {
    bytes[i] = value.charCodeAt(i);
  }
  return bytes;
}

function concatBytes(
  chunks: ReadonlyArray<Uint8Array<ArrayBufferLike>>,
): Uint8Array<ArrayBuffer> {
  const length = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const output = new Uint8Array(new ArrayBuffer(length));
  let offset = 0;

  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.length;
  }

  return output;
}

function encodeDerLength(length: number): Uint8Array<ArrayBuffer> {
  if (length < 0) {
    throw new Error("DER length cannot be negative");
  }

  if (length < 0x80) {
    return Uint8Array.from([length]);
  }

  const bytes: number[] = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }

  return Uint8Array.from([0x80 | bytes.length, ...bytes]);
}

function joseIntToDerInteger(
  value: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBuffer> {
  let offset = 0;
  while (offset < value.length - 1 && value[offset] === 0) {
    offset += 1;
  }

  let normalized = Uint8Array.from(value.slice(offset));

  if ((normalized[0] & 0x80) !== 0) {
    normalized = concatBytes([Uint8Array.from([0x00]), normalized]);
  }

  return concatBytes([
    Uint8Array.from([0x02]),
    encodeDerLength(normalized.length),
    normalized,
  ]);
}

function convertJoseEcdsaSignatureToDer(
  signature: Uint8Array<ArrayBufferLike>,
): Uint8Array<ArrayBuffer> {
  if (signature.length % 2 !== 0) {
    throw new Error("Invalid ECDSA JWT signature length");
  }

  const componentLength = signature.length / 2;
  const r = Uint8Array.from(signature.slice(0, componentLength));
  const s = Uint8Array.from(signature.slice(componentLength));
  const derR = joseIntToDerInteger(r);
  const derS = joseIntToDerInteger(s);
  const sequenceBody = concatBytes([derR, derS]);

  return concatBytes([
    Uint8Array.from([0x30]),
    encodeDerLength(sequenceBody.length),
    sequenceBody,
  ]);
}

function getVerificationAlgorithmConfig(
  algorithm: string,
): VerificationAlgorithmConfig {
  switch (algorithm) {
    case "RS256":
      return {
        importAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
        verifyAlgorithm: { name: "RSASSA-PKCS1-v1_5" },
        joseEcdsaSignature: false,
      };
    case "RS384":
      return {
        importAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-384" },
        verifyAlgorithm: { name: "RSASSA-PKCS1-v1_5" },
        joseEcdsaSignature: false,
      };
    case "RS512":
      return {
        importAlgorithm: { name: "RSASSA-PKCS1-v1_5", hash: "SHA-512" },
        verifyAlgorithm: { name: "RSASSA-PKCS1-v1_5" },
        joseEcdsaSignature: false,
      };
    case "PS256":
      return {
        importAlgorithm: { name: "RSA-PSS", hash: "SHA-256" },
        verifyAlgorithm: { name: "RSA-PSS", saltLength: 32 },
        joseEcdsaSignature: false,
      };
    case "PS384":
      return {
        importAlgorithm: { name: "RSA-PSS", hash: "SHA-384" },
        verifyAlgorithm: { name: "RSA-PSS", saltLength: 48 },
        joseEcdsaSignature: false,
      };
    case "PS512":
      return {
        importAlgorithm: { name: "RSA-PSS", hash: "SHA-512" },
        verifyAlgorithm: { name: "RSA-PSS", saltLength: 64 },
        joseEcdsaSignature: false,
      };
    case "ES256":
      return {
        importAlgorithm: { name: "ECDSA", namedCurve: "P-256" },
        verifyAlgorithm: { name: "ECDSA", hash: "SHA-256" },
        joseEcdsaSignature: true,
      };
    case "ES384":
      return {
        importAlgorithm: { name: "ECDSA", namedCurve: "P-384" },
        verifyAlgorithm: { name: "ECDSA", hash: "SHA-384" },
        joseEcdsaSignature: true,
      };
    case "ES512":
      return {
        importAlgorithm: { name: "ECDSA", namedCurve: "P-521" },
        verifyAlgorithm: { name: "ECDSA", hash: "SHA-512" },
        joseEcdsaSignature: true,
      };
    case "EdDSA":
      return {
        importAlgorithm: { name: "Ed25519" },
        verifyAlgorithm: { name: "Ed25519" },
        joseEcdsaSignature: false,
      };
    default:
      throw new Error(`Unsupported ID token signing algorithm: ${algorithm}`);
  }
}

function extractJwtSignatureInput(idToken: string): {
  signingInput: string;
  signature: Uint8Array<ArrayBuffer>;
} {
  const parts = idToken.split(".");

  if (parts.length !== 3 || parts.some((part) => part.length === 0)) {
    throw new Error("Invalid JWT structure");
  }

  return {
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: base64UrlToBytes(parts[2]),
  };
}

function buildDiscoveryUrl(authority: string): string {
  const authorityUrl = new URL(authority);
  const basePath = authorityUrl.pathname.replace(/\/+$/, "");

  authorityUrl.pathname = `${basePath}${OPENID_DISCOVERY_PATH}`;
  authorityUrl.search = "";
  authorityUrl.hash = "";

  return authorityUrl.toString();
}

function isSignatureVerificationKey(jwk: JwkMetadata): boolean {
  const use = typeof jwk.use === "string" ? jwk.use.trim().toLowerCase() : "";
  if (use && use !== "sig") {
    return false;
  }

  if (jwk.key_ops !== undefined) {
    if (!Array.isArray(jwk.key_ops)) {
      return false;
    }

    const operations = jwk.key_ops
      .filter((operation) => typeof operation === "string")
      .map((operation) => operation.trim().toLowerCase());

    if (operations.length > 0 && !operations.includes("verify")) {
      return false;
    }
  }

  return true;
}

function selectSigningJwk(
  keys: JwkMetadata[],
  algorithm: string,
  kid: string | undefined,
): JwkMetadata {
  const normalizedKid = typeof kid === "string" ? kid.trim() : "";
  const expectedKeyType = expectedKeyTypeForAlgorithm(algorithm);

  const candidates = keys.filter((jwk) => {
    if (!isSignatureVerificationKey(jwk)) {
      return false;
    }

    if (expectedKeyType) {
      const keyType = normalizeExpectedJwkKeyType(jwk.kty);
      if (keyType && keyType !== expectedKeyType) {
        return false;
      }
    }

    if (
      typeof jwk.alg === "string" &&
      jwk.alg.trim() !== "" &&
      jwk.alg !== algorithm
    ) {
      return false;
    }

    if (!normalizedKid) {
      return true;
    }

    return typeof jwk.kid === "string" && jwk.kid.trim() === normalizedKid;
  });

  if (candidates.length === 0) {
    if (normalizedKid) {
      throw new Error(`No JWKS key matches token kid "${normalizedKid}"`);
    }

    throw new Error("No JWKS key matches the token algorithm");
  }

  if (!normalizedKid && candidates.length > 1) {
    throw new Error(
      "Multiple signing keys are available; token header must include kid",
    );
  }

  return candidates[0];
}

export function createRedirectUriDescriptor(
  redirectUri: string,
): RedirectUriDescriptor {
  const parsed = new URL(redirectUri);

  return {
    protocol: parsed.protocol,
    hostname: parsed.hostname.toLowerCase(),
    port: parsed.port,
    pathname: normalizePathname(parsed.pathname),
  };
}

export function matchesRedirectUri(
  callbackUrl: string,
  expected: RedirectUriDescriptor,
): boolean {
  try {
    const callback = new URL(callbackUrl);

    return (
      callback.protocol === expected.protocol &&
      callback.hostname.toLowerCase() === expected.hostname &&
      callback.port === expected.port &&
      normalizePathname(callback.pathname) === expected.pathname
    );
  } catch {
    return false;
  }
}

export class IdTokenValidator {
  private readonly authority: string;
  private readonly clientId: string;
  private readonly jwksUri?: string;
  private readonly requiredAcrValues: string[];
  private readonly requiredAmrValues: string[];
  private readonly requirePhishingResistantMfa: boolean;
  private readonly allowInsecureIdTokenValidation: boolean;
  private readonly debug: boolean;
  private readonly logger: ReturnType<typeof createReactNativeLogger>;

  private discoveryCache: DiscoveryCacheEntry | null = null;
  private jwksCache: JwksCacheEntry | null = null;

  constructor(options: IdTokenValidatorOptions) {
    this.authority = options.authority;
    this.clientId = options.clientId;
    this.jwksUri = options.jwksUri;
    this.requiredAcrValues = normalizeStringValues(options.requiredAcrValues);

    const normalizedAmrValues = normalizeStringValues(
      options.requiredAmrValues,
    );
    if (options.requireWebAuthn) {
      normalizedAmrValues.push("webauthn");
    }
    this.requiredAmrValues = normalizeStringValues(normalizedAmrValues);

    this.requirePhishingResistantMfa =
      options.requirePhishingResistantMfa ?? false;
    this.allowInsecureIdTokenValidation =
      options.allowInsecureIdTokenValidation ?? false;
    this.debug = options.debug ?? false;
    this.logger = createReactNativeLogger("IdToken", this.debug);
  }

  async validate(idToken: string, nonce?: string): Promise<DecodedJWT> {
    if (!idToken || typeof idToken !== "string") {
      throw new Error("ID token is required for validation");
    }

    const normalizedNonce = typeof nonce === "string" ? nonce.trim() : "";

    const decoded = decodeJWT(idToken, {
      debug: this.debug,
    });

    const algorithm = decoded.header.alg;
    if (typeof algorithm !== "string" || algorithm.trim() === "") {
      throw new Error("ID token header is missing alg");
    }

    try {
      let keys = await this.fetchJwks(false);
      let signingJwk = selectSigningJwk(keys, algorithm, decoded.header.kid);

      let signatureVerified = await this.verifyJwtSignature(
        idToken,
        algorithm,
        signingJwk,
      );
      if (!signatureVerified) {
        keys = await this.fetchJwks(true);
        signingJwk = selectSigningJwk(keys, algorithm, decoded.header.kid);
        signatureVerified = await this.verifyJwtSignature(
          idToken,
          algorithm,
          signingJwk,
        );
      }

      if (!signatureVerified) {
        throw new Error("ID token signature verification failed");
      }

      const verifiedSignature: VerifiedSignatureProof = {
        verified: true,
        algorithm,
        kid: typeof signingJwk.kid === "string" ? signingJwk.kid : undefined,
        keyType: normalizeExpectedJwkKeyType(signingJwk.kty),
      };

      const validation = validateToken(decoded, {
        issuer: this.authority,
        audience: this.clientId,
        clientId: this.clientId,
        nonce: normalizedNonce || undefined,
        verifiedSignature,
        resolvedJwk: signingJwk,
        requiredAcrValues:
          this.requiredAcrValues.length > 0
            ? this.requiredAcrValues
            : undefined,
        requiredAmrValues:
          this.requiredAmrValues.length > 0
            ? this.requiredAmrValues
            : undefined,
        requirePhishingResistantMfa: this.requirePhishingResistantMfa,
        debug: this.debug,
      });

      if (!validation.valid) {
        throw new Error(
          `ID token validation failed: ${validation.errors.join(", ")}`,
        );
      }

      this.logger.debug("ID token signature and claims validated", {
        kid: verifiedSignature.kid,
        algorithm,
        requiredAmrCount: this.requiredAmrValues.length,
        requiredAcrCount: this.requiredAcrValues.length,
        phishingResistantMfaRequired: this.requirePhishingResistantMfa,
      });

      return decoded;
    } catch (error) {
      if (
        this.allowInsecureIdTokenValidation &&
        this.isWebCryptoUnavailableError(error)
      ) {
        this.logger.warn(
          "WebCrypto signature verification is unavailable. Falling back to insecure claims-only ID token validation.",
        );

        const fallbackValidation = validateToken(decoded, {
          issuer: this.authority,
          audience: this.clientId,
          clientId: this.clientId,
          nonce: normalizedNonce || undefined,
          signatureVerified: true,
          requiredAcrValues:
            this.requiredAcrValues.length > 0
              ? this.requiredAcrValues
              : undefined,
          requiredAmrValues:
            this.requiredAmrValues.length > 0
              ? this.requiredAmrValues
              : undefined,
          requirePhishingResistantMfa: this.requirePhishingResistantMfa,
          debug: this.debug,
        });

        if (!fallbackValidation.valid) {
          throw new Error(
            `ID token validation failed: ${fallbackValidation.errors.join(", ")}`,
          );
        }

        return decoded;
      }

      throw error;
    }
  }

  private isWebCryptoUnavailableError(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error);

    return (
      message.includes("subtle.verify is unavailable") ||
      message.includes("crypto.subtle")
    );
  }

  private async resolveJwksUri(): Promise<string> {
    if (typeof this.jwksUri === "string" && this.jwksUri.trim() !== "") {
      return assertSecureUrl(this.jwksUri.trim(), "jwksUri");
    }

    const now = Date.now();
    if (this.discoveryCache && this.discoveryCache.expiresAt > now) {
      return this.discoveryCache.jwksUri;
    }

    const discoveryUrl = assertSecureUrl(
      buildDiscoveryUrl(this.authority),
      "OIDC discovery URL",
    );

    this.logger.debug("Fetching OIDC discovery metadata", {
      discoveryUrl,
    });

    const response = await fetch(discoveryUrl, {
      method: "GET",
      headers: {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `OIDC discovery request failed (${response.status}): ${errorText}`,
      );
    }

    const discovery = (await response.json()) as Record<string, unknown>;

    const issuer =
      typeof discovery["issuer"] === "string" ? discovery["issuer"].trim() : "";

    if (issuer && normalizeIssuer(issuer) !== normalizeIssuer(this.authority)) {
      throw new Error(
        `OIDC discovery issuer mismatch. Expected ${normalizeIssuer(this.authority)} but received ${normalizeIssuer(issuer)}`,
      );
    }

    const discoveredJwksUri =
      typeof discovery["jwks_uri"] === "string"
        ? discovery["jwks_uri"].trim()
        : "";

    if (!discoveredJwksUri) {
      throw new Error("OIDC discovery response is missing jwks_uri");
    }

    const secureJwksUri = assertSecureUrl(discoveredJwksUri, "jwks_uri");

    this.discoveryCache = {
      jwksUri: secureJwksUri,
      expiresAt: Date.now() + DISCOVERY_CACHE_TTL_MS,
    };

    return secureJwksUri;
  }

  private async fetchJwks(forceRefresh: boolean): Promise<JwkMetadata[]> {
    const jwksUri = await this.resolveJwksUri();
    const now = Date.now();

    if (
      !forceRefresh &&
      this.jwksCache &&
      this.jwksCache.jwksUri === jwksUri &&
      this.jwksCache.expiresAt > now
    ) {
      return this.jwksCache.keys;
    }

    this.logger.debug("Fetching JWKS", {
      jwksUri,
      forceRefresh,
    });

    const response = await fetch(jwksUri, {
      method: "GET",
      headers: {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`JWKS request failed (${response.status}): ${errorText}`);
    }

    const jwksResponse = (await response.json()) as Record<string, unknown>;
    const rawKeys = jwksResponse["keys"];

    if (!Array.isArray(rawKeys)) {
      throw new Error("JWKS response is missing keys array");
    }

    const keys = rawKeys.filter(
      (entry): entry is JwkMetadata =>
        Boolean(entry) && typeof entry === "object" && !Array.isArray(entry),
    );

    if (keys.length === 0) {
      throw new Error("JWKS response does not include any signing keys");
    }

    this.jwksCache = {
      jwksUri,
      keys,
      expiresAt: Date.now() + JWKS_CACHE_TTL_MS,
    };

    return keys;
  }

  private async verifyJwtSignature(
    idToken: string,
    algorithm: string,
    jwk: JwkMetadata,
  ): Promise<boolean> {
    if (
      typeof globalThis.crypto?.subtle?.importKey !== "function" ||
      typeof globalThis.crypto.subtle.verify !== "function"
    ) {
      throw new Error(
        "WebCrypto subtle.verify is unavailable. Install and configure a WebCrypto-capable runtime before using ID token signature validation.",
      );
    }

    const verificationAlgorithm = getVerificationAlgorithmConfig(algorithm);

    const key = await globalThis.crypto.subtle.importKey(
      "jwk",
      jwk as JsonWebKey,
      verificationAlgorithm.importAlgorithm,
      false,
      ["verify"],
    );

    const tokenSignatureInput = extractJwtSignatureInput(idToken);

    const signature = verificationAlgorithm.joseEcdsaSignature
      ? convertJoseEcdsaSignatureToDer(tokenSignatureInput.signature)
      : tokenSignatureInput.signature;

    return globalThis.crypto.subtle.verify(
      verificationAlgorithm.verifyAlgorithm,
      key,
      signature,
      asciiToBytes(tokenSignatureInput.signingInput),
    );
  }
}
