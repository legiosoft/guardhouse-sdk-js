import { createGuardhouseLogger } from "../debug";
import { timingSafeEqual } from "../security";

import {
  MAX_STATE_BINDINGS,
  MAX_TRACKED_STATE_TOKENS,
  SILENT_AUTH_ERROR_CODES,
  STATE_TOKEN_PATTERN,
} from "./constants";

export const DEFAULT_STATE_TTL_MS = 900_000;

export class StateExpiredError extends Error {
  constructor(message = "State handle has expired and cannot be consumed") {
    super(message);
    this.name = "StateExpiredError";
  }
}

export interface OAuthStateManagerOptions {
  stateTtlMs?: number;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  if (typeof btoa !== "function") {
    throw new Error("Base64 encoding is unavailable in this environment");
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function createStateBindingHandle(): string {
  let webCrypto: Crypto | undefined = globalThis.crypto;

  if (!webCrypto && typeof require === "function") {
    try {
      webCrypto = require("crypto").webcrypto as Crypto | undefined;
    } catch {
      // Ignore and fall through to explicit availability error below.
    }
  }

  if (!webCrypto || typeof webCrypto.getRandomValues !== "function") {
    throw new Error("Secure random generator is unavailable for state binding");
  }

  const randomBytes = new Uint8Array(18);
  webCrypto.getRandomValues(randomBytes);

  return bytesToBase64Url(randomBytes);
}

export class OAuthStateManager {
  private readonly stateTtlMs: number;
  private readonly consumedStateSet = new Map<string, number>();
  private readonly stateBindingVault = new Map<
    string,
    { state: string; expiresAt: number }
  >();

  constructor(options: OAuthStateManagerOptions = {}) {
    const configuredTtl = options.stateTtlMs ?? DEFAULT_STATE_TTL_MS;
    if (!Number.isInteger(configuredTtl) || configuredTtl <= 0) {
      throw new Error("stateTtlMs must be a positive integer");
    }

    this.stateTtlMs = configuredTtl;
  }

  validateAndConsumeState(expectedState: string, returnedState: string): void {
    const logger = createGuardhouseLogger("Auth");
    const normalizedExpectedState = expectedState.trim();
    const normalizedReturnedState = returnedState.trim();

    if (!normalizedExpectedState || !normalizedReturnedState) {
      logger.error("OAuth state validation failed", {
        reason: "missing_expected_or_returned_state",
        hasExpectedState: Boolean(normalizedExpectedState),
        hasReturnedState: Boolean(normalizedReturnedState),
      });
      throw new Error("Expected and returned OAuth state are both required");
    }

    const now = Date.now();
    this.purgeExpiredConsumedStates(now);

    if (this.consumedStateSet.has(normalizedExpectedState)) {
      logger.error("OAuth state validation failed", {
        reason: "replayed_state_detected",
      });
      throw new Error("OAuth state was already used and cannot be reused");
    }

    if (!timingSafeEqual(normalizedExpectedState, normalizedReturnedState)) {
      logger.error("OAuth state validation failed", {
        reason: "state_mismatch",
        expectedLength: normalizedExpectedState.length,
        returnedLength: normalizedReturnedState.length,
      });
      throw new Error("OAuth state mismatch");
    }

    this.consumedStateSet.set(normalizedExpectedState, now + this.stateTtlMs);

    while (this.consumedStateSet.size > MAX_TRACKED_STATE_TOKENS) {
      const oldestState = this.consumedStateSet.keys().next().value;
      if (oldestState === undefined) {
        break;
      }
      this.consumedStateSet.delete(oldestState);
    }
  }

  stashExpectedState(expectedState: string): string {
    const normalizedState = expectedState.trim();

    if (!STATE_TOKEN_PATTERN.test(normalizedState)) {
      throw new Error("expectedState must be a valid high-entropy state token");
    }

    const now = Date.now();
    this.purgeExpiredStateBindings(now);

    const handle = createStateBindingHandle();
    this.stateBindingVault.set(handle, {
      state: normalizedState,
      expiresAt: now + this.stateTtlMs,
    });

    while (this.stateBindingVault.size > MAX_STATE_BINDINGS) {
      const oldestHandle = this.stateBindingVault.keys().next().value;
      if (oldestHandle === undefined) {
        break;
      }
      this.stateBindingVault.delete(oldestHandle);
    }

    return handle;
  }

  consumeStateBinding(stateHandle: string, returnedState: string): void {
    const normalizedHandle = stateHandle.trim();
    const now = Date.now();

    const expectedState = this.stateBindingVault.get(normalizedHandle);

    if (!expectedState) {
      throw new Error("State handle is invalid or has already been consumed");
    }

    if (now > expectedState.expiresAt) {
      this.stateBindingVault.delete(normalizedHandle);
      throw new StateExpiredError();
    }

    this.purgeExpiredStateBindings(now);

    this.stateBindingVault.delete(normalizedHandle);

    this.validateAndConsumeState(expectedState.state, returnedState);
  }

  private purgeExpiredConsumedStates(now: number): void {
    for (const [state, expiresAt] of this.consumedStateSet.entries()) {
      if (now > expiresAt) {
        this.consumedStateSet.delete(state);
      } else {
        break;
      }
    }
  }

  private purgeExpiredStateBindings(now: number): void {
    for (const [handle, expectedState] of this.stateBindingVault.entries()) {
      if (now > expectedState.expiresAt) {
        this.stateBindingVault.delete(handle);
      } else {
        break;
      }
    }
  }
}

export function validateFormPostCsrfToken(
  expectedToken: string,
  actualToken: string,
): void {
  const normalizedExpected = expectedToken.trim();
  const normalizedActual = actualToken.trim();

  if (!normalizedExpected || !normalizedActual) {
    throw new Error("Both expected and actual CSRF tokens are required");
  }

  if (!timingSafeEqual(normalizedExpected, normalizedActual)) {
    throw new Error("form_post CSRF token validation failed");
  }
}

export function isSilentAuthenticationError(errorCode: string): boolean {
  return SILENT_AUTH_ERROR_CODES.has(errorCode.trim());
}
