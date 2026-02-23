import type { CryptoAdapter } from "@guardhouse/core";
import { createReactNativeLogger } from "./debug";

type DynamicRequire = (moduleName: string) => unknown;

interface QuickCryptoModule {
  randomBytes(size: number): unknown;
  createHash(algorithm: string): {
    update(data: unknown): {
      digest(): unknown;
    };
    digest(): unknown;
  };
}

function toUint8Array(value: unknown): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }

  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  if (
    typeof value === "object" &&
    value !== null &&
    "buffer" in value &&
    "byteOffset" in value &&
    "byteLength" in value
  ) {
    const typedArrayLike = value as {
      buffer: ArrayBuffer;
      byteOffset: number;
      byteLength: number;
    };

    return new Uint8Array(
      typedArrayLike.buffer,
      typedArrayLike.byteOffset,
      typedArrayLike.byteLength,
    );
  }

  throw new Error("Unsupported byte buffer returned by crypto provider");
}

function tryRequire(moduleName: string): unknown {
  const dynamicRequire = (globalThis as { require?: DynamicRequire }).require;

  if (typeof dynamicRequire !== "function") {
    return null;
  }

  try {
    return dynamicRequire(moduleName);
  } catch {
    return null;
  }
}

class ReactNativeWebCryptoAdapter implements CryptoAdapter {
  name = "ReactNativeWebCrypto";

  async randomBytes(length: number): Promise<Uint8Array> {
    if (typeof globalThis.crypto?.getRandomValues !== "function") {
      throw new Error("crypto.getRandomValues is not available");
    }

    return globalThis.crypto.getRandomValues(new Uint8Array(length));
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    if (typeof globalThis.crypto?.subtle !== "object") {
      throw new Error("crypto.subtle is not available");
    }

    const input = Uint8Array.from(data);

    const hash = await globalThis.crypto.subtle.digest(
      { name: "SHA-256" },
      input.buffer,
    );

    return new Uint8Array(hash);
  }
}

class ReactNativeQuickCryptoAdapter implements CryptoAdapter {
  name = "ReactNativeQuickCrypto";

  constructor(private quickCrypto: QuickCryptoModule) {}

  async randomBytes(length: number): Promise<Uint8Array> {
    return toUint8Array(this.quickCrypto.randomBytes(length));
  }

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    const digest = this.quickCrypto.createHash("sha256").update(data).digest();
    return toUint8Array(digest);
  }
}

function resolveQuickCryptoModule(): QuickCryptoModule | null {
  const moduleCandidate = tryRequire("react-native-quick-crypto") as
    | { default?: QuickCryptoModule }
    | QuickCryptoModule
    | null;

  if (!moduleCandidate) {
    return null;
  }

  const resolvedModule =
    typeof (moduleCandidate as { randomBytes?: unknown }).randomBytes ===
    "function"
      ? (moduleCandidate as QuickCryptoModule)
      : (moduleCandidate as { default?: QuickCryptoModule }).default;

  if (
    resolvedModule &&
    typeof resolvedModule.randomBytes === "function" &&
    typeof resolvedModule.createHash === "function"
  ) {
    return resolvedModule;
  }

  return null;
}

export function resolveReactNativeCryptoAdapter(
  adapter: CryptoAdapter | undefined,
  debug = false,
): CryptoAdapter {
  const logger = createReactNativeLogger("Crypto", debug);

  if (adapter) {
    logger.debug("Using custom crypto adapter", { adapter: adapter.name });
    return adapter;
  }

  if (
    typeof globalThis.crypto?.getRandomValues === "function" &&
    typeof globalThis.crypto?.subtle === "object"
  ) {
    logger.debug("Using React Native Web Crypto adapter");
    return new ReactNativeWebCryptoAdapter();
  }

  const quickCryptoModule = resolveQuickCryptoModule();
  if (quickCryptoModule) {
    logger.debug("Using react-native-quick-crypto adapter");
    return new ReactNativeQuickCryptoAdapter(quickCryptoModule);
  }

  throw new Error(
    "No native SHA-256 provider available. Install react-native-quick-crypto or pass a custom cryptoAdapter to GuardhouseProvider.",
  );
}
