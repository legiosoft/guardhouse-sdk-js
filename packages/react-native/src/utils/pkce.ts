import {
  generateNonce,
  generatePKCE,
  generateState,
  type CryptoAdapter,
} from "@guardhouse/core";

export interface PkceArtifacts {
  codeVerifier: string;
  codeChallenge: string;
  state: string;
  nonce: string;
}

/**
 * Generates PKCE + OAuth anti-forgery artifacts.
 */
export async function createPkceArtifacts(
  cryptoAdapter: CryptoAdapter,
  debug: boolean,
): Promise<PkceArtifacts> {
  const { codeVerifier, codeChallenge } = await generatePKCE(
    { debug },
    cryptoAdapter,
  );
  const state = await generateState(32, debug, cryptoAdapter);
  const nonce = await generateNonce(32, debug, cryptoAdapter);

  return {
    codeVerifier,
    codeChallenge,
    state,
    nonce,
  };
}
