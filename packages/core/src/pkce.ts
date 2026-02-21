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

export interface PKCECodePair {
  codeVerifier: string;
  codeChallenge: string;
}

export interface PKCEOptions {
  length?: number;
  method?: "S256" | "plain";
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
    method = "S256", // Force S256 (plain is insecure)
  } = options;

  console.log(
    `[PKCE] Generating PKCE pair (length: ${length}, method: ${method})`,
  );

  // SECURITY: Use CSPRNG for code verifier (Math.random() is NOT secure)
  const randomBytes = await cryptoAdapter.randomBytes(length);

  // Convert to base64url
  const codeVerifier = bufferToBase64Url(randomBytes);

  console.log(
    `[PKCE] Code verifier generated (length: ${codeVerifier.length})`,
  );

  let codeChallenge: string;

  if (method === "plain") {
    console.warn("[PKCE] WARNING: Plain text PKCE is NOT secure (RFC 7636)");
    codeChallenge = codeVerifier;
  } else {
    // SECURITY: S256 method (RFC 7636 RECOMMENDED)
    // Challenge = BASE64URL(SHA256(ASCII(code_verifier)))
    const data = new TextEncoder().encode(codeVerifier);
    const hash = await cryptoAdapter.sha256(data);
    codeChallenge = bufferToBase64Url(hash);

    console.log(`[PKCE] Code challenge generated (S256)`);
  }

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
export async function generateState(length?: number): Promise<string>;
export async function generateState(
  cryptoAdapter: CryptoAdapter,
  length?: number,
): Promise<string>;
export async function generateState(
  adapterOrLength: CryptoAdapter | number = 16,
  maybeLength: number = 16,
): Promise<string> {
  const cryptoAdapter = isCryptoAdapter(adapterOrLength)
    ? adapterOrLength
    : await getCryptoAdapter();

  const length = isCryptoAdapter(adapterOrLength)
    ? maybeLength
    : adapterOrLength;

  console.log(`[PKCE] Generating state (length: ${length})`);

  // SECURITY: Use CSPRNG (Math.random() is NOT secure)
  const randomBytes = await cryptoAdapter.randomBytes(length);

  const state = bufferToBase64Url(randomBytes);

  console.log(`[PKCE] State generated (length: ${state.length})`);

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
export async function generateNonce(length?: number): Promise<string>;
export async function generateNonce(
  cryptoAdapter: CryptoAdapter,
  length?: number,
): Promise<string>;
export async function generateNonce(
  adapterOrLength: CryptoAdapter | number = 16,
  maybeLength: number = 16,
): Promise<string> {
  const cryptoAdapter = isCryptoAdapter(adapterOrLength)
    ? adapterOrLength
    : await getCryptoAdapter();

  const length = isCryptoAdapter(adapterOrLength)
    ? maybeLength
    : adapterOrLength;

  console.log(`[PKCE] Generating nonce (length: ${length})`);

  // SECURITY: Use CSPRNG (Math.random() is NOT secure)
  const randomBytes = await cryptoAdapter.randomBytes(length);

  const nonce = bufferToBase64Url(randomBytes);

  console.log(`[PKCE] Nonce generated (length: ${nonce.length})`);

  return nonce;
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
  let binary = "";
  const len = buffer.byteLength;

  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(buffer[i]);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
