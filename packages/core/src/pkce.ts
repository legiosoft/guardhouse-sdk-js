/**
 * PKCE Service
 *
 * SECURITY ARCHITECTURE:
 *
 * 1. Why PKCE (Proof Key for Code Exchange)?
 *    - Prevents authorization code interception attacks (RFC 7636)
 *    - Essential for public clients (mobile apps, SPAs)
 *    - Binds authorization code to cryptographically secure verifier
 *
 * 2. Why code_verifier length (43-128)?
 *    - RFC 7636: RECOMMENDED minimum 128 bits (43 base64url chars)
 *    - 128 bits: 43 chars (balanced security vs URL length)
 *    - 256 bits: 86 chars (more secure, longer URLs)
 *
 * 3. Why S256 (SHA-256) vs plain?
 *    - RFC 7636: RECOMMENDED using S256
 *    - Plain text is vulnerable to interception
 *    - S256 proves verifier possession without revealing it
 *
 * 4. Why random state and nonce?
 *    - State: CSRF protection, 128 bits minimum
 *    - Nonce: JWT replay protection, 128 bits minimum
 *    - Both use CSPRNG (Math.random() is NOT secure)
 *
 * 5. Why base64url encoding?
 *    - URL-safe: Uses '-' and '_' instead of '+' and '/'
 *    - No padding: Removes '=' to prevent encoding issues
 *    - Standard for OAuth 2.0 and JWT
 */

import { getCryptoAdapter } from "./crypto";
import type { CryptoAdapter } from "./crypto";
import { createGuardhouseLogger } from "./debug";

export interface PKCECodePair {
  codeVerifier: string;
  codeChallenge: string;
}

export interface PKCEOptions {
  length?: number;
  method?: "S256";
  debug?: boolean;
}

const MIN_CODE_VERIFIER_BYTES = 32;
const MAX_CODE_VERIFIER_BYTES = 96;
const MIN_STATE_OR_NONCE_BYTES = 16;
const PKCE_CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;
const MAX_STORED_CODE_VERIFIERS = 512;
const codeVerifierVault = new Map<string, Uint8Array>();
const codeVerifierVaultOrder: string[] = [];

function utf8Encode(value: string): Uint8Array {
  if (typeof TextEncoder === "function") {
    return new TextEncoder().encode(value);
  }

  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(value, "utf8"));
  }

  const bytes = new Uint8Array(value.length);
  for (let index = 0; index < value.length; index += 1) {
    bytes[index] = value.charCodeAt(index) & 0xff;
  }
  return bytes;
}

function utf8Decode(value: Uint8Array): string {
  if (typeof TextDecoder === "function") {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  }

  if (typeof Buffer !== "undefined") {
    return Buffer.from(value).toString("utf8");
  }

  let output = "";
  for (const byte of value) {
    output += String.fromCharCode(byte);
  }
  return output;
}

function wipeBytes(value: Uint8Array): void {
  value.fill(0);
}

function isCryptoAdapter(value: unknown): value is CryptoAdapter {
  return (
    typeof value === "object" &&
    value !== null &&
    "randomBytes" in value &&
    "sha256" in value
  );
}

/**
 * Generate PKCE code pair (verifier + challenge)
 *
 * SECURITY: Uses CSPRNG for cryptographically secure random values
 *
 * @param cryptoAdapter - Crypto adapter for the environment
 * @param options - PKCE generation options
 * @returns Promise with code verifier and challenge
 *
 * @throws {Error} If crypto is not available
 */
export async function generatePKCE(
  options?: PKCEOptions,
): Promise<PKCECodePair>;
export async function generatePKCE(
  cryptoAdapter: CryptoAdapter,
  options?: PKCEOptions,
): Promise<PKCECodePair>;
export async function generatePKCE(
  adapterOrOptions: CryptoAdapter | PKCEOptions = {},
  maybeOptions: PKCEOptions = {},
): Promise<PKCECodePair> {
  const cryptoAdapter = isCryptoAdapter(adapterOrOptions)
    ? adapterOrOptions
    : await getCryptoAdapter();

  const options = isCryptoAdapter(adapterOrOptions)
    ? maybeOptions
    : adapterOrOptions;

  const {
    length = 43, // 128 bits (RFC 7636 recommended minimum)
    method = "S256",
    debug,
  } = options;

  if (!Number.isInteger(length)) {
    throw new Error("PKCE length must be an integer");
  }

  if (length < MIN_CODE_VERIFIER_BYTES || length > MAX_CODE_VERIFIER_BYTES) {
    throw new Error(
      `PKCE length must be between ${MIN_CODE_VERIFIER_BYTES} and ${MAX_CODE_VERIFIER_BYTES} bytes`,
    );
  }

  if (method !== "S256") {
    throw new Error("Only S256 PKCE method is supported");
  }

  const logger = createGuardhouseLogger("PKCE", debug);

  logger.debug("Generating PKCE pair", {
    length,
    method,
    adapter: cryptoAdapter.name,
  });

  // SECURITY: Use CSPRNG for code verifier (Math.random() is NOT secure)
  const randomBytes = await cryptoAdapter.randomBytes(length);

  // Convert to base64url
  const codeVerifier = bufferToBase64Url(randomBytes);

  logger.debug("Code verifier generated", {
    length: codeVerifier.length,
  });

  // SECURITY: S256 method (RFC 7636 RECOMMENDED)
  // Challenge = BASE64URL(SHA256(ASCII(code_verifier)))
  const data = new TextEncoder().encode(codeVerifier);
  const hash = await cryptoAdapter.sha256(data);
  const codeChallenge = bufferToBase64Url(hash);

  logger.debug("Code challenge generated with S256");

  return {
    codeVerifier,
    codeChallenge,
  };
}

/**
 * Generate cryptographically secure random state
 *
 * SECURITY: Used for CSRF protection
 * - Must be unique per authorization request
 * - Must be validated in callback
 * - Minimum 128 bits (recommended)
 *
 * @param cryptoAdapter - Crypto adapter for the environment
 * @param length - Length of state in bytes (default: 16 = 128 bits)
 * @returns URL-safe base64 encoded random state
 *
 * @throws {Error} If crypto is not available
 */
export async function generateState(
  length?: number,
  debug?: boolean,
): Promise<string>;
export async function generateState(
  cryptoAdapter: CryptoAdapter,
  length?: number,
  debug?: boolean,
): Promise<string>;
export async function generateState(
  adapterOrLength: CryptoAdapter | number = 16,
  maybeLengthOrDebug: number | boolean = 16,
  maybeDebug = false,
): Promise<string> {
  const usesExplicitAdapter = isCryptoAdapter(adapterOrLength);

  const cryptoAdapter = usesExplicitAdapter
    ? adapterOrLength
    : await getCryptoAdapter();

  const length = usesExplicitAdapter
    ? typeof maybeLengthOrDebug === "number"
      ? maybeLengthOrDebug
      : 16
    : adapterOrLength;

  const debug = usesExplicitAdapter
    ? typeof maybeLengthOrDebug === "boolean"
      ? maybeLengthOrDebug
      : maybeDebug
    : typeof maybeLengthOrDebug === "boolean"
      ? maybeLengthOrDebug
      : maybeDebug;

  if (!Number.isInteger(length) || length < MIN_STATE_OR_NONCE_BYTES) {
    throw new Error(
      `State length must be an integer of at least ${MIN_STATE_OR_NONCE_BYTES} bytes`,
    );
  }

  const logger = createGuardhouseLogger("PKCE", debug);

  logger.debug("Generating state", {
    length,
    adapter: cryptoAdapter.name,
  });

  // SECURITY: Use CSPRNG (Math.random() is NOT secure)
  const randomBytes = await cryptoAdapter.randomBytes(length);

  const state = bufferToBase64Url(randomBytes);

  logger.debug("State generated", {
    length: state.length,
  });

  return state;
}

/**
 * Generate cryptographically secure nonce
 *
 * SECURITY: Used for JWT replay protection
 * - Must be unique per authentication
 * - Must be validated in ID token
 * - Minimum 128 bits (recommended)
 *
 * @param cryptoAdapter - Crypto adapter for the environment
 * @param length - Length of nonce in bytes (default: 16 = 128 bits)
 * @returns URL-safe base64 encoded random nonce
 *
 * @throws {Error} If crypto is not available
 */
export async function generateNonce(
  length?: number,
  debug?: boolean,
): Promise<string>;
export async function generateNonce(
  cryptoAdapter: CryptoAdapter,
  length?: number,
  debug?: boolean,
): Promise<string>;
export async function generateNonce(
  adapterOrLength: CryptoAdapter | number = 16,
  maybeLengthOrDebug: number | boolean = 16,
  maybeDebug = false,
): Promise<string> {
  const usesExplicitAdapter = isCryptoAdapter(adapterOrLength);

  const cryptoAdapter = usesExplicitAdapter
    ? adapterOrLength
    : await getCryptoAdapter();

  const length = usesExplicitAdapter
    ? typeof maybeLengthOrDebug === "number"
      ? maybeLengthOrDebug
      : 16
    : adapterOrLength;

  const debug = usesExplicitAdapter
    ? typeof maybeLengthOrDebug === "boolean"
      ? maybeLengthOrDebug
      : maybeDebug
    : typeof maybeLengthOrDebug === "boolean"
      ? maybeLengthOrDebug
      : maybeDebug;

  if (!Number.isInteger(length) || length < MIN_STATE_OR_NONCE_BYTES) {
    throw new Error(
      `Nonce length must be an integer of at least ${MIN_STATE_OR_NONCE_BYTES} bytes`,
    );
  }

  const logger = createGuardhouseLogger("PKCE", debug);

  logger.debug("Generating nonce", {
    length,
    adapter: cryptoAdapter.name,
  });

  // SECURITY: Use CSPRNG (Math.random() is NOT secure)
  const randomBytes = await cryptoAdapter.randomBytes(length);

  const nonce = bufferToBase64Url(randomBytes);

  logger.debug("Nonce generated", {
    length: nonce.length,
  });

  return nonce;
}

export async function stashCodeVerifier(codeVerifier: string): Promise<string> {
  const normalizedVerifier = codeVerifier.trim();

  if (!PKCE_CODE_VERIFIER_PATTERN.test(normalizedVerifier)) {
    throw new Error(
      "codeVerifier must be 43-128 RFC7636 unreserved characters",
    );
  }

  const cryptoAdapter = await getCryptoAdapter();
  const handle = bufferToBase64Url(await cryptoAdapter.randomBytes(24));
  const verifierBytes = utf8Encode(normalizedVerifier);

  codeVerifierVault.set(handle, verifierBytes);
  codeVerifierVaultOrder.push(handle);

  if (codeVerifierVaultOrder.length > MAX_STORED_CODE_VERIFIERS) {
    const evictedHandle = codeVerifierVaultOrder.shift();
    if (evictedHandle) {
      codeVerifierVault.delete(evictedHandle);
    }
  }

  return handle;
}

export function consumeCodeVerifier(handle: string): string {
  const normalizedHandle = handle.trim();
  const codeVerifierBytes = codeVerifierVault.get(normalizedHandle);

  if (!codeVerifierBytes) {
    throw new Error("PKCE verifier handle is invalid or already consumed");
  }

  const codeVerifier = utf8Decode(codeVerifierBytes);
  wipeBytes(codeVerifierBytes);

  codeVerifierVault.delete(normalizedHandle);

  const index = codeVerifierVaultOrder.indexOf(normalizedHandle);
  if (index >= 0) {
    codeVerifierVaultOrder.splice(index, 1);
  }

  return codeVerifier;
}

export function dropCodeVerifier(handle: string): void {
  const normalizedHandle = handle.trim();
  const codeVerifierBytes = codeVerifierVault.get(normalizedHandle);

  if (!codeVerifierBytes) {
    return;
  }

  wipeBytes(codeVerifierBytes);
  codeVerifierVault.delete(normalizedHandle);

  const index = codeVerifierVaultOrder.indexOf(normalizedHandle);
  if (index >= 0) {
    codeVerifierVaultOrder.splice(index, 1);
  }
}

/**
 * Convert buffer to base64url encoding
 *
 * RFC 4648: Base64URL encoding
 * - No padding ('=' characters)
 * - Replace '+' with '-'
 * - Replace '/' with '_'
 * - Standard for OAuth 2.0 and JWT
 *
 * @param buffer - Uint8Array to encode
 * @returns Base64URL encoded string
 */
function bufferToBase64Url(buffer: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(buffer)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  if (typeof btoa !== "function") {
    throw new Error("Base64 encoding is unavailable in this environment");
  }

  let binary = "";
  const len = buffer.byteLength;

  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(buffer[i]);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
