/**
 * Cryptographic Adapter Interface
 *
 * SECURITY ARCHITECTURE DECISIONS:
 *
 * 1. Why use adapter pattern?
 *    - Abstracts environment-specific crypto implementations
 *    - Allows runtime detection and graceful fallbacks
 *    - Prevents "crypto is undefined" errors
 *    - Makes testing easier (mockable)
 *
 * 2. Why SubtleCrypto API first?
 *    - Standardized in modern browsers (globalThis.crypto)
 *    - Available in modern Node.js (globalThis.crypto.subtle)
 *    - Non-blocking (async), better for performance
 *    - Hardware-accelerated on most platforms
 *
 * 3. Why fallback to Node.js crypto?
 *    - Legacy Node.js (before v15) doesn't have Web Crypto
 *    - Still widely used in enterprise environments
 *    - Provides synchronous fallback when async API unavailable
 *
 * 4. Why allow crypto provider injection for React Native?
 *    - React Native doesn't have standard crypto in all versions
 *    - User can inject their own implementation (react-native-crypto-js, etc.)
 *    - Avoids forcing heavy polyfills on all users
 *    - Follows "Dependency Injection" principle (IoC)
 *
 * 5. CSPRNG Requirements:
 *    - Use cryptographic quality random (Math.random() is NOT secure)
 *    - Node: crypto.randomBytes() or globalThis.crypto.getRandomValues()
 *    - Browser: globalThis.crypto.getRandomValues()
 *
 * 6. SHA-256 Requirements:
 *    - PKCE REQUIRES SHA-256 (RFC 7636)
 *    - Node: crypto.createHash('sha256')
 *    - Browser: globalThis.crypto.subtle.digest({ name: 'SHA-256' }, data)
 *
 * 7. BASE64URL Encoding:
 *    - PKCE requires base64url (RFC 4648)
 *    - Replace '+' → '-', '/' → '_', remove padding '='
 *    - Standard for OAuth 2.0 and JWT
 */

import { createGuardhouseLogger } from "./debug";

interface NodeCryptoHashLike {
  update(data: Uint8Array): NodeCryptoHashLike;
  digest(): Uint8Array;
}

interface NodeCryptoLike {
  randomBytes(length: number): Uint8Array;
  randomBytes(
    length: number,
    callback: (error: Error | null, buffer: Uint8Array) => void,
  ): void;
  createHash(algorithm: "sha256"): NodeCryptoHashLike;
}

type NodeRequireFunction = (moduleId: string) => unknown;

function tryLoadNodeCrypto(): NodeCryptoLike | null {
  try {
    const dynamicRequire = Function(
      "return typeof require !== 'undefined' ? require : null;",
    )() as NodeRequireFunction | null;

    if (typeof dynamicRequire !== "function") {
      return null;
    }

    const loadedCrypto = dynamicRequire(
      "crypto",
    ) as Partial<NodeCryptoLike> | null;

    const randomBytes = loadedCrypto?.randomBytes;
    const createHash = loadedCrypto?.createHash;

    if (
      !loadedCrypto ||
      typeof randomBytes !== "function" ||
      typeof createHash !== "function"
    ) {
      return null;
    }

    try {
      const syncRandomBytes = randomBytes as (length: number) => unknown;
      const probeRandom = syncRandomBytes.call(loadedCrypto, 1);

      if (probeRandom instanceof Uint8Array) {
        // Expected Node.js Buffer/Uint8Array output.
      } else if (
        typeof ArrayBuffer !== "undefined" &&
        probeRandom instanceof ArrayBuffer
      ) {
        void new Uint8Array(probeRandom);
      } else if (
        typeof probeRandom === "object" &&
        probeRandom !== null &&
        "length" in probeRandom &&
        typeof (probeRandom as { length: unknown }).length === "number"
      ) {
        void new Uint8Array(probeRandom as ArrayLike<number>);
      } else {
        return null;
      }

      const probeHash = createHash.call(loadedCrypto, "sha256");
      if (
        !probeHash ||
        typeof probeHash.update !== "function" ||
        typeof probeHash.digest !== "function"
      ) {
        return null;
      }
    } catch {
      return null;
    }

    return loadedCrypto as NodeCryptoLike;
  } catch {
    return null;
  }
}

export function bytesToBase64Url(buffer: Uint8Array): string {
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
  for (const byte of buffer) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export interface CryptoAdapter {
  name?: string;
  randomBytes(length: number): Promise<Uint8Array>;
  sha256(data: Uint8Array): Promise<Uint8Array>;
}

/**
 * SubtleCrypto Implementation (Browsers & Modern Node.js)
 *
 * Uses Web Crypto API (globalThis.crypto / globalThis.crypto.subtle)
 *
 * Available in:
 * - All modern browsers (Chrome, Firefox, Safari, Edge)
 * - Node.js 15+ (globalThis.crypto)
 *
 * SECURE: Non-blocking, hardware-accelerated
 */
class SubtleCryptoAdapter implements CryptoAdapter {
  name = "SubtleCrypto";

  async randomBytes(length: number): Promise<Uint8Array> {
    if (typeof globalThis.crypto?.getRandomValues === "function") {
      return globalThis.crypto.getRandomValues(new Uint8Array(length));
    }
    throw new Error("crypto.getRandomValues not available");
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    if (typeof globalThis.crypto?.subtle === "object") {
      const subtle = globalThis.crypto.subtle;
      const bufferToHash =
        data.byteOffset === 0 && data.byteLength === data.buffer.byteLength
          ? data.buffer
          : data.slice().buffer;
      const digestInput = bufferToHash as unknown as Parameters<
        typeof subtle.digest
      >[1];

      const buffer = await subtle.digest({ name: "SHA-256" }, digestInput);
      return new Uint8Array(buffer);
    }
    throw new Error("crypto.subtle not available");
  }
}

/**
 * Node.js Crypto Implementation (Legacy & Modern)
 *
 * Uses Node.js built-in crypto module
 *
 * Available in:
 * - All Node.js versions (require('crypto'))
 * - Works in both old and new Node.js
 *
 * SECURE: Uses OpenSSL-backed crypto, battle-tested
 */
class NodeCryptoAdapter implements CryptoAdapter {
  name = "NodeCrypto";
  private nodeCrypto: NodeCryptoLike;

  constructor(nodeCrypto?: NodeCryptoLike) {
    const resolvedNodeCrypto = nodeCrypto ?? tryLoadNodeCrypto();

    if (!resolvedNodeCrypto) {
      throw new Error("Node.js crypto module not available");
    }

    this.nodeCrypto = resolvedNodeCrypto;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      this.nodeCrypto.randomBytes(length, (error, buffer) => {
        if (error) {
          reject(error);
          return;
        }

        resolve(new Uint8Array(buffer));
      });
    });
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      try {
        const hash = this.nodeCrypto.createHash("sha256");
        hash.update(Buffer.from(data.buffer, data.byteOffset, data.byteLength));
        resolve(new Uint8Array(hash.digest()));
      } catch (error) {
        reject(error);
      }
    });
  }
}

/**
 * Fallback Crypto Adapter (Pure JS)
 *
 * WARNING: This should be used ONLY when no native crypto is available
 *
 * Not suitable for production because:
 * - Pure JS implementation is slow
 * - Not hardware-accelerated
 * - May not be cryptographically secure on all platforms
 *
 * Use cases:
 * - Very old environments (extremely old browsers/Node.js)
 * - Testing environments (unit tests)
 * - Development only
 *
 * For React Native: Users should inject react-native-crypto-js or similar
 */
class FallbackCryptoAdapter implements CryptoAdapter {
  name = "FallbackCrypto";

  async randomBytes(length: number): Promise<Uint8Array> {
    if (typeof globalThis.crypto?.getRandomValues === "function") {
      return globalThis.crypto.getRandomValues(new Uint8Array(length));
    }

    throw new Error(
      "Secure random generation is unavailable. Inject a cryptographically secure adapter.",
    );
  }

  async sha256(_data: Uint8Array): Promise<Uint8Array> {
    throw new Error(
      "SHA-256 not available in fallback adapter. Please provide a crypto provider.",
    );
  }
}

/**
 * Detect and return appropriate crypto adapter
 *
 * Priority order:
 * 1. SubtleCrypto (globalThis.crypto) - Modern browsers & Node 15+
 * 2. NodeCrypto (require('crypto')) - Legacy Node.js
 * 3. Provided crypto adapter (injected) - For React Native, etc.
 * 4. FallbackCrypto (pure JS) - Last resort (not for production)
 *
 * SECURITY: Runtime detection ensures we use best available crypto
 */
export function detectCryptoAdapter(): CryptoAdapter {
  logger.debug("Detecting crypto adapter");

  const webCrypto = globalThis.crypto;

  if (
    webCrypto &&
    typeof webCrypto.getRandomValues === "function" &&
    webCrypto.subtle &&
    typeof webCrypto.subtle.digest === "function"
  ) {
    logger.info("Using SubtleCrypto adapter");
    return new SubtleCryptoAdapter();
  }

  const nodeCrypto = tryLoadNodeCrypto();
  if (nodeCrypto) {
    logger.info("Using Node.js crypto adapter");
    return new NodeCryptoAdapter(nodeCrypto);
  }

  logger.debug("Node.js crypto not available");

  logger.warn("No native crypto available. Using fallback adapter.", {
    warning: "Fallback adapter is not suitable for production",
    recommendation:
      "Inject a custom crypto provider (for example react-native-quick-crypto)",
  });

  return new FallbackCryptoAdapter();
}

/**
 * Create crypto adapter with provider injection
 *
 * Allows users to inject their own crypto implementation
 * Useful for React Native or custom environments
 *
 * @param provider - Custom crypto adapter
 * @returns The provided adapter
 */
export function createCryptoAdapter(provider: CryptoAdapter): CryptoAdapter {
  logger.info("Using custom crypto provider", {
    provider: provider.name,
  });
  return provider;
}

/**
 * Global crypto adapter instance
 *
 * Can be replaced at runtime by calling setCryptoAdapter()
 * Useful for React Native apps to inject react-native-crypto-js
 */
let globalCryptoAdapter: CryptoAdapter | null = null;
const logger = createGuardhouseLogger("Crypto");

/**
 * Set global crypto adapter (dependency injection)
 *
 * @example
 * import { setCryptoAdapter } from '@guardhouse/core';
 * import { NativeModules } from 'react-native';
 *
 * const RNAdapater = {
 *   async randomBytes(length) {
 *     return NativeModules.GuardhouseCrypto.randomBytes(length);
 *   },
 *   async sha256(data) {
 *     return NativeModules.GuardhouseCrypto.sha256(data);
 *   },
 *   name: 'ReactNativeCrypto',
 * };
 *
 * setCryptoAdapter(new CryptoAdapter(RNAdapater));
 */
export function setCryptoAdapter(adapter: CryptoAdapter): void {
  globalCryptoAdapter = adapter;
  logger.info("Crypto adapter set", {
    adapter: adapter.name,
  });
}

/**
 * Get or create crypto adapter
 *
 * Returns the set global adapter or detects one automatically
 */
export async function getCryptoAdapter(): Promise<CryptoAdapter> {
  if (globalCryptoAdapter) {
    logger.debug("Using cached crypto adapter", {
      adapter: globalCryptoAdapter.name,
    });
    return globalCryptoAdapter;
  }

  const adapter = detectCryptoAdapter();
  globalCryptoAdapter = adapter;

  logger.info("Detected crypto adapter", {
    adapter: adapter.name,
  });

  return adapter;
}

/**
 * Initialize crypto adapter
 *
 * Call this early in your app to ensure crypto is ready
 * Returns the adapter for immediate use
 */
export async function initializeCrypto(): Promise<CryptoAdapter> {
  logger.debug("Initializing crypto adapter");
  const adapter = await getCryptoAdapter();

  logger.debug("Crypto adapter initialized", {
    adapter: adapter.name,
  });

  return adapter;
}
