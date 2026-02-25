import { bytesToBase64Url, getCryptoAdapter } from "./crypto";
import type { CryptoAdapter } from "./crypto";
import { createGuardhouseLogger } from "./debug";
import { toUtf8Bytes } from "./security";

export interface PKCECodePair {
  codeVerifier: string;
  codeChallenge: string;
}

export interface PKCEOptions {
  /**
   * Raw entropy bytes used to generate code_verifier.
   * This is NOT the final code_verifier string length.
   * 32-96 bytes maps to roughly 43-128 Base64URL characters.
   */
  length?: number;
  method?: "S256";
  debug?: boolean;
}

export interface OAuthPKCEManagerOptions {
  codeVerifierTtlMs?: number;
  maxStoredCodeVerifiers?: number;
  cryptoAdapter?: CryptoAdapter;
}

const MIN_CODE_VERIFIER_BYTES = 32;
const MAX_CODE_VERIFIER_BYTES = 96;
const MIN_STATE_OR_NONCE_BYTES = 16;
const PKCE_CODE_VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/;
const HANDLE_RANDOM_BYTES = 24;
const DEFAULT_MAX_STORED_CODE_VERIFIERS = 512;
export const DEFAULT_CODE_VERIFIER_TTL_MS = 900_000;

async function resolveCryptoAdapter(
  explicitAdapter?: CryptoAdapter,
): Promise<CryptoAdapter> {
  return explicitAdapter ?? getCryptoAdapter();
}

export class OAuthPKCEManager {
  private readonly codeVerifierVault = new Map<
    string,
    { codeVerifier: string; expiresAt: number }
  >();
  private readonly codeVerifierTtlMs: number;
  private readonly maxStoredCodeVerifiers: number;
  private readonly explicitCryptoAdapter?: CryptoAdapter;

  constructor(options: OAuthPKCEManagerOptions = {}) {
    const ttl = options.codeVerifierTtlMs ?? DEFAULT_CODE_VERIFIER_TTL_MS;
    if (!Number.isInteger(ttl) || ttl <= 0) {
      throw new Error("codeVerifierTtlMs must be a positive integer");
    }

    const maxStored =
      options.maxStoredCodeVerifiers ?? DEFAULT_MAX_STORED_CODE_VERIFIERS;
    if (!Number.isInteger(maxStored) || maxStored <= 0) {
      throw new Error("maxStoredCodeVerifiers must be a positive integer");
    }

    this.codeVerifierTtlMs = ttl;
    this.maxStoredCodeVerifiers = maxStored;
    this.explicitCryptoAdapter = options.cryptoAdapter;
  }

  async stashCodeVerifier(codeVerifier: string): Promise<string> {
    const normalizedVerifier = codeVerifier.trim();

    if (!PKCE_CODE_VERIFIER_PATTERN.test(normalizedVerifier)) {
      throw new Error(
        "codeVerifier must be 43-128 RFC7636 unreserved characters",
      );
    }

    const now = Date.now();
    this.purgeExpiredCodeVerifiers(now);

    const cryptoAdapter = await this.getCryptoAdapter();
    const handle = bytesToBase64Url(
      await cryptoAdapter.randomBytes(HANDLE_RANDOM_BYTES),
    );

    this.codeVerifierVault.set(handle, {
      codeVerifier: normalizedVerifier,
      expiresAt: now + this.codeVerifierTtlMs,
    });

    this.evictOverflowCodeVerifiers();

    return handle;
  }

  consumeCodeVerifier(handle: string): string {
    const normalizedHandle = handle.trim();
    const now = Date.now();
    this.purgeExpiredCodeVerifiers(now);

    const entry = this.codeVerifierVault.get(normalizedHandle);
    if (!entry) {
      throw new Error("PKCE verifier handle is invalid or already consumed");
    }

    this.codeVerifierVault.delete(normalizedHandle);
    return entry.codeVerifier;
  }

  dropCodeVerifier(handle: string): void {
    const normalizedHandle = handle.trim();
    if (!normalizedHandle) {
      return;
    }

    this.codeVerifierVault.delete(normalizedHandle);
  }

  private purgeExpiredCodeVerifiers(now: number): void {
    for (const [handle, entry] of this.codeVerifierVault.entries()) {
      if (now > entry.expiresAt) {
        this.codeVerifierVault.delete(handle);
      } else {
        break;
      }
    }
  }

  private evictOverflowCodeVerifiers(): void {
    while (this.codeVerifierVault.size > this.maxStoredCodeVerifiers) {
      const oldestHandle = this.codeVerifierVault.keys().next().value;
      if (!oldestHandle) {
        break;
      }

      this.codeVerifierVault.delete(oldestHandle);
    }
  }

  private async getCryptoAdapter(): Promise<CryptoAdapter> {
    return this.explicitCryptoAdapter ?? getCryptoAdapter();
  }
}

export async function generatePKCE(
  options: PKCEOptions = {},
  cryptoAdapter?: CryptoAdapter,
): Promise<PKCECodePair> {
  const { length = 43, method = "S256", debug } = options;

  if (!Number.isInteger(length)) {
    throw new Error("PKCE length must be an integer");
  }

  if (length < MIN_CODE_VERIFIER_BYTES || length > MAX_CODE_VERIFIER_BYTES) {
    throw new Error(
      `PKCE length must be between ${MIN_CODE_VERIFIER_BYTES} and ${MAX_CODE_VERIFIER_BYTES} entropy bytes`,
    );
  }

  if (method !== "S256") {
    throw new Error("Only S256 PKCE method is supported");
  }

  const adapter = await resolveCryptoAdapter(cryptoAdapter);
  const logger = createGuardhouseLogger("PKCE", debug);

  logger.debug("Generating PKCE pair", {
    length,
    method,
    adapter: adapter.name,
  });

  const randomBytes = await adapter.randomBytes(length);
  const codeVerifier = bytesToBase64Url(randomBytes);

  const verifierBytes = toUtf8Bytes(codeVerifier);
  const hash = await adapter.sha256(verifierBytes);
  const codeChallenge = bytesToBase64Url(hash);

  logger.debug("Code challenge generated with S256");

  return {
    codeVerifier,
    codeChallenge,
  };
}

export async function generateState(
  length = MIN_STATE_OR_NONCE_BYTES,
  debug = false,
  cryptoAdapter?: CryptoAdapter,
): Promise<string> {
  if (!Number.isInteger(length) || length < MIN_STATE_OR_NONCE_BYTES) {
    throw new Error(
      `State length must be an integer of at least ${MIN_STATE_OR_NONCE_BYTES} bytes`,
    );
  }

  const adapter = await resolveCryptoAdapter(cryptoAdapter);
  const logger = createGuardhouseLogger("PKCE", debug);

  logger.debug("Generating state", {
    length,
    adapter: adapter.name,
  });

  return bytesToBase64Url(await adapter.randomBytes(length));
}

export async function generateNonce(
  length = MIN_STATE_OR_NONCE_BYTES,
  debug = false,
  cryptoAdapter?: CryptoAdapter,
): Promise<string> {
  if (!Number.isInteger(length) || length < MIN_STATE_OR_NONCE_BYTES) {
    throw new Error(
      `Nonce length must be an integer of at least ${MIN_STATE_OR_NONCE_BYTES} bytes`,
    );
  }

  const adapter = await resolveCryptoAdapter(cryptoAdapter);
  const logger = createGuardhouseLogger("PKCE", debug);

  logger.debug("Generating nonce", {
    length,
    adapter: adapter.name,
  });

  return bytesToBase64Url(await adapter.randomBytes(length));
}
