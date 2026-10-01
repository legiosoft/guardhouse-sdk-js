import type { CryptoAdapter } from "@guardhouse/core";
import {
  CryptoDigestAlgorithm,
  digest,
  getRandomBytesAsync,
} from "expo-crypto";

// Optional PKCE adapter only. installCrypto.ts supplies Web Crypto for OIDC.
export const expoCryptoAdapter: CryptoAdapter = {
  name: "ExpoCrypto",

  async randomBytes(length: number): Promise<Uint8Array> {
    return getRandomBytesAsync(length);
  },

  async sha256(data: Uint8Array): Promise<Uint8Array> {
    const hash = await digest(CryptoDigestAlgorithm.SHA256, data);
    return new Uint8Array(hash);
  },
};
