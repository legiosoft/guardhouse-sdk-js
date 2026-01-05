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
      const buffer = await globalThis.crypto.subtle.digest(
        { name: "SHA-256" },
        data as any,
      );
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
  private nodeCrypto: any;

  constructor() {
    try {
      this.nodeCrypto = require("crypto");
    } catch (error) {
      throw new Error("Node.js crypto module not available");
    }
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      try {
        const buffer = this.nodeCrypto.randomBytes(length);
        resolve(new Uint8Array(buffer));
      } catch (error) {
        reject(error);
      }
    });
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    return new Promise((resolve, reject) => {
      try {
        const hash = this.nodeCrypto.createHash("sha256");
        hash.update(Buffer.from(data));
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
    if (typeof Math.random !== "function") {
      throw new Error("Math.random not available");
    }

    const array = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      array[i] = Math.floor(Math.random() * 256);
    }

    return new Promise((resolve) => {
      setTimeout(() => resolve(array), 0);
    });
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
  if (
    typeof globalThis.crypto?.subtle === "object" &&
    typeof globalThis.crypto?.getRandomValues === "function"
  ) {
    console.log("[Guardhouse Crypto] Using SubtleCrypto adapter");
    return new SubtleCryptoAdapter();
  }

  try {
    require("crypto");
    console.log("[Guardhouse Crypto] Using Node.js crypto adapter");
    return new NodeCryptoAdapter();
  } catch (error) {
    console.log("[Guardhouse Crypto] Node.js crypto not available");
  }

  console.warn(
    "[Guardhouse Crypto] No native crypto available. Using fallback adapter.",
    "\nWARNING: Fallback adapter is NOT suitable for production.",
    "For React Native: Inject a crypto provider like react-native-crypto-js",
  );

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
  console.log(
    `[Guardhouse Crypto] Using custom crypto provider: ${provider.name}`,
  );
  return provider;
}

/**
 * Global crypto adapter instance
 *
 * Can be replaced at runtime by calling setCryptoAdapter()
 * Useful for React Native apps to inject react-native-crypto-js
 */
let globalCryptoAdapter: CryptoAdapter | null = null;

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
  console.log(`[Guardhouse Crypto] Crypto adapter set to: ${adapter.name}`);
}

/**
 * Get or create crypto adapter
 *
 * Returns the set global adapter or detects one automatically
 */
export async function getCryptoAdapter(): Promise<CryptoAdapter> {
  if (globalCryptoAdapter) {
    return globalCryptoAdapter;
  }

  const adapter = detectCryptoAdapter();
  globalCryptoAdapter = adapter;
  return adapter;
}

/**
 * Initialize crypto adapter
 *
 * Call this early in your app to ensure crypto is ready
 * Returns the adapter for immediate use
 */
export async function initializeCrypto(): Promise<CryptoAdapter> {
  console.log("[Guardhouse Crypto] Initializing crypto adapter...");
  return await getCryptoAdapter();
}
