interface NodeCryptoHashLike {
  update(data: Uint8Array): NodeCryptoHashLike;
  // Node returns Buffer, which is a Uint8Array subclass.
  digest(): Uint8Array;
}

export interface NodeCryptoLike {
  randomBytes(size: number): Uint8Array;
  createHash(algorithm: `sha${256 | 384 | 512}`): NodeCryptoHashLike;
}

type NodeRequireFunction = (moduleId: string) => unknown;

function isByteArrayView(value: unknown): value is { byteLength: number } {
  return (
    ArrayBuffer.isView(value) &&
    typeof (value as { byteLength?: unknown }).byteLength === "number"
  );
}

function hasUsableWebCryptoDigest(): boolean {
  return Boolean(
    globalThis.crypto?.subtle &&
    typeof globalThis.crypto.subtle.digest === "function",
  );
}

function getRuntimeRequire(): NodeRequireFunction | null {
  const runtime = globalThis as typeof globalThis & {
    require?: unknown;
    process?: {
      versions?: {
        node?: unknown;
      };
    };
  };

  const isNodeLike =
    typeof runtime.process !== "undefined" &&
    typeof runtime.process?.versions?.node === "string" &&
    runtime.process.versions.node.trim() !== "";

  if (!isNodeLike) {
    return null;
  }

  return typeof runtime.require === "function"
    ? (runtime.require as NodeRequireFunction)
    : null;
}

export function tryLoadNodeCrypto(): NodeCryptoLike | null {
  if (hasUsableWebCryptoDigest()) {
    return null;
  }

  const dynamicRequire = getRuntimeRequire();
  if (typeof dynamicRequire !== "function") {
    return null;
  }

  try {
    const loadedCrypto = dynamicRequire(
      "crypto",
    ) as Partial<NodeCryptoLike> | null;

    if (
      !loadedCrypto ||
      typeof loadedCrypto.createHash !== "function" ||
      typeof loadedCrypto.randomBytes !== "function"
    ) {
      return null;
    }

    const probeRandom = loadedCrypto.randomBytes(1) as unknown;
    if (!isByteArrayView(probeRandom) || probeRandom.byteLength !== 1) {
      return null;
    }

    const probeHash = loadedCrypto.createHash("sha256");
    if (
      !probeHash ||
      typeof probeHash.update !== "function" ||
      typeof probeHash.digest !== "function"
    ) {
      return null;
    }

    return loadedCrypto as NodeCryptoLike;
  } catch {
    return null;
  }
}
