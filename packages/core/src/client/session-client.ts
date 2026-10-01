import {
  canonicalizeIssuer,
  OAuthStateManager,
  parseOAuthCallbackUrl,
  restoreAuthorizationTransaction as restoreTransaction,
  sanitizeOAuthCallbackUrl,
} from "../auth";
import type {
  AuthorizationCallbackInput,
  AuthorizationTransaction,
  ValidatedAuthorizationCallback,
} from "../auth";
import { GuardhouseError, isTransientAuthError } from "../config";
import { OidcIdTokenVerifier } from "../token";
import type { IdTokenValidationContext, VerifiedIdToken } from "../token";
import type { OidcIdentity } from "../token/id-token-verifier";

import {
  LEGACY_DEFAULT_SESSION_STORAGE_KEY,
  SILENT_AUTH_ERROR_CODES,
} from "./constants";
import { GuardhouseClientBase } from "./base-client";
import type { SessionState, TokenResponse } from "./types";

const sharedStorageOperationTails = new WeakMap<object, Promise<void>>();
type AuthorizationCodeCallback = Extract<
  ValidatedAuthorizationCallback,
  { type: "authorization_code" }
>;
const validatedAuthorizationCodeEvidence = new WeakMap<
  object,
  { readonly owner: object; readonly transaction: AuthorizationTransaction }
>();

function orderedQueryTuplesMatch(left: URL, right: URL): boolean {
  const leftEntries = Array.from(left.searchParams.entries());
  const rightEntries = Array.from(right.searchParams.entries());
  if (leftEntries.length !== rightEntries.length) return false;

  return leftEntries.every(
    ([leftKey, leftValue], index) =>
      leftKey === rightEntries[index]?.[0] &&
      leftValue === rightEntries[index]?.[1],
  );
}

function hasUrlAuthority(url: URL): boolean {
  return url.href.slice(url.protocol.length).startsWith("//");
}

function callbackRedirectMatches(callbackUrl: URL, redirectUrl: URL): boolean {
  return (
    !callbackUrl.username &&
    !callbackUrl.password &&
    callbackUrl.protocol === redirectUrl.protocol &&
    hasUrlAuthority(callbackUrl) === hasUrlAuthority(redirectUrl) &&
    callbackUrl.host === redirectUrl.host &&
    callbackUrl.pathname === redirectUrl.pathname &&
    orderedQueryTuplesMatch(callbackUrl, redirectUrl) &&
    callbackUrl.hash === redirectUrl.hash
  );
}

export class GuardhouseClientSession extends GuardhouseClientBase {
  private readonly stateManager = new OAuthStateManager();
  private idTokenVerifier: OidcIdTokenVerifier | null = null;
  private sessionOperationGeneration = 0;
  private storageClearPending = false;

  protected beginSessionOperation(): number {
    this.sessionOperationGeneration += 1;
    return this.sessionOperationGeneration;
  }

  protected captureSessionOperation(): number {
    return this.sessionOperationGeneration;
  }

  protected assertSessionOperationCurrent(generation: number): void {
    if (generation !== this.sessionOperationGeneration) {
      throw new GuardhouseError(
        "Session operation was invalidated by a newer session action",
        "SESSION_OPERATION_INVALIDATED",
      );
    }
  }

  protected consumeValidatedAuthorizationCallback(
    callback: AuthorizationCodeCallback,
  ): AuthorizationTransaction {
    if (!callback || typeof callback !== "object") {
      throw new GuardhouseError(
        "Authorization callback was not validated by this client",
        "INVALID_CALLBACK_EVIDENCE",
      );
    }

    const evidence = validatedAuthorizationCodeEvidence.get(callback);
    if (!evidence || evidence.owner !== this) {
      throw new GuardhouseError(
        "Authorization callback was not validated by this client or was already consumed",
        "INVALID_CALLBACK_EVIDENCE",
      );
    }

    // Consume before any transaction restoration or network operation. A
    // failed exchange must start from a fresh authorization transaction.
    validatedAuthorizationCodeEvidence.delete(callback);
    return this.restoreAuthorizationTransaction(evidence.transaction);
  }

  private runStorageOperation<T>(operation: () => Promise<T>): Promise<T> {
    const storage = this.config.storage;
    if (!storage) {
      return operation();
    }

    const previous =
      sharedStorageOperationTails.get(storage) ?? Promise.resolve();
    const result = previous.then(operation, operation);
    const settled = result.then(
      () => undefined,
      () => undefined,
    );
    sharedStorageOperationTails.set(storage, settled);
    void settled.finally(() => {
      if (sharedStorageOperationTails.get(storage) === settled) {
        sharedStorageOperationTails.delete(storage);
      }
    });
    return result;
  }

  private async removePersistedSessionIfUnchanged(
    serializedSessionState: string,
  ): Promise<void> {
    const storage = this.config.storage;
    if (!storage) {
      return;
    }

    if (storage.compareAndRemoveItem) {
      const removed = await storage.compareAndRemoveItem(
        this.sessionStorageKey,
        serializedSessionState,
      );
      if (typeof removed !== "boolean") {
        throw new GuardhouseError(
          "Storage adapter returned an invalid compare-and-remove result",
          "SESSION_STORAGE_CLEAR_FAILED",
        );
      }
      if (
        (await storage.getItem(this.sessionStorageKey)) ===
        serializedSessionState
      ) {
        throw new GuardhouseError(
          "Storage adapter retained the matched session record after atomic removal",
          "SESSION_STORAGE_CLEAR_FAILED",
        );
      }
      return;
    }

    const currentSessionState = await storage.getItem(this.sessionStorageKey);

    if (currentSessionState === serializedSessionState) {
      await storage.removeItem(this.sessionStorageKey);
      const valueAfterRemoval = await storage.getItem(this.sessionStorageKey);
      if (valueAfterRemoval === serializedSessionState) {
        throw new GuardhouseError(
          "Storage adapter retained the stale session record after removal",
          "SESSION_STORAGE_CLEAR_FAILED",
        );
      }
    }
  }

  private async rejectInvalidatedSessionWrite(
    generation: number,
    serializedSessionState: string,
  ): Promise<never> {
    try {
      await this.removePersistedSessionIfUnchanged(serializedSessionState);
    } catch (error) {
      throw error instanceof GuardhouseError
        ? error
        : new GuardhouseError(
            "Failed to remove an invalidated persisted session",
            "SESSION_STORAGE_CLEAR_FAILED",
            { cause: error },
          );
    }

    this.assertSessionOperationCurrent(generation);
    throw new GuardhouseError(
      "Session operation was invalidated by a newer session action",
      "SESSION_OPERATION_INVALIDATED",
    );
  }

  private async removeLegacyDefaultSessionState(): Promise<void> {
    if (!this.usesDefaultSessionStorageKey || !this.config.storage) {
      return;
    }
    const keys = [
      LEGACY_DEFAULT_SESSION_STORAGE_KEY,
      this.legacyV2SessionStorageKey,
    ].filter((key): key is string => Boolean(key));
    for (const key of keys) {
      try {
        await this.config.storage.removeItem(key);
      } catch (error) {
        this.logger.warn("Failed to remove legacy session state", {
          reason: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }

  async verifyIdToken(
    idToken: string,
    context: IdTokenValidationContext,
  ): Promise<VerifiedIdToken> {
    if (!this.idTokenVerifier) {
      this.idTokenVerifier = new OidcIdTokenVerifier({
        authority: this.protocolIssuer,
        clientId: this.config.clientId,
        cacheTtlMs: this.discoveryCacheTtlMs,
      });
    }
    return this.idTokenVerifier.verify(idToken, context);
  }

  private async removePersistedSessionKeysDurably(): Promise<void> {
    if (!this.config.storage) return;
    const keys = [
      this.sessionStorageKey,
      this.usesDefaultSessionStorageKey
        ? LEGACY_DEFAULT_SESSION_STORAGE_KEY
        : null,
      this.legacyV2SessionStorageKey,
    ].filter((key): key is string => Boolean(key));
    for (const key of keys) {
      await this.config.storage.removeItem(key);
    }
    for (const key of keys) {
      if ((await this.config.storage.getItem(key)) !== null) {
        throw new Error(`Storage adapter retained cleared session key ${key}`);
      }
    }
  }

  restoreAuthorizationTransaction(value: unknown): AuthorizationTransaction {
    try {
      return restoreTransaction(value, {
        issuer: this.protocolIssuer,
        clientId: this.config.clientId,
      });
    } catch (error) {
      throw new GuardhouseError(
        error instanceof Error
          ? error.message
          : "Authorization transaction is invalid",
        "INVALID_AUTHORIZATION_TRANSACTION",
        { cause: error },
      );
    }
  }

  protected async cacheSessionState(
    tokenResponse: TokenResponse,
    generation: number,
    options: {
      previousSessionState?: SessionState | null;
      preserveRefreshToken?: boolean;
      verifiedIdentity?: OidcIdentity;
    } = {},
  ): Promise<void> {
    const sessionState = this.buildSessionStateFromTokenResponse(
      tokenResponse,
      options.previousSessionState,
      options.preserveRefreshToken,
      options.verifiedIdentity,
    );
    const serializedSessionState = JSON.stringify(sessionState);

    this.assertSessionOperationCurrent(generation);

    if (!this.config.storage) {
      this.sessionState = sessionState;
      return;
    }

    try {
      await this.runStorageOperation(async () => {
        this.assertSessionOperationCurrent(generation);

        try {
          await this.config.storage!.setItem(
            this.sessionStorageKey,
            serializedSessionState,
          );
        } catch (error) {
          if (generation !== this.sessionOperationGeneration) {
            return this.rejectInvalidatedSessionWrite(
              generation,
              serializedSessionState,
            );
          }
          throw error;
        }

        if (generation !== this.sessionOperationGeneration) {
          return this.rejectInvalidatedSessionWrite(
            generation,
            serializedSessionState,
          );
        }

        await this.removeLegacyDefaultSessionState();

        if (generation !== this.sessionOperationGeneration) {
          return this.rejectInvalidatedSessionWrite(
            generation,
            serializedSessionState,
          );
        }
      });
    } catch (error) {
      if (
        error instanceof GuardhouseError &&
        error.code === "SESSION_OPERATION_INVALIDATED"
      ) {
        throw error;
      }

      this.assertSessionOperationCurrent(generation);
      this.sessionState = null;
      try {
        await this.runStorageOperation(() =>
          this.removePersistedSessionIfUnchanged(serializedSessionState),
        );
      } catch (cleanupError) {
        throw new GuardhouseError(
          "Failed to persist session state and conditionally remove its durable record",
          "SESSION_STORAGE_WRITE_FAILED",
          { cause: cleanupError },
        );
      }
      throw new GuardhouseError(
        "Failed to persist session state",
        "SESSION_STORAGE_WRITE_FAILED",
        { cause: error },
      );
    }

    this.assertSessionOperationCurrent(generation);
    this.sessionState = sessionState;
    this.storageClearPending = false;
  }

  protected async capturePersistedSessionState(): Promise<
    string | null | undefined
  > {
    if (!this.config.storage) {
      return undefined;
    }

    try {
      return await this.runStorageOperation(() =>
        this.config.storage!.getItem(this.sessionStorageKey),
      );
    } catch (error) {
      throw new GuardhouseError(
        "Failed to read persisted session state before a security-sensitive operation",
        "SESSION_STORAGE_READ_FAILED",
        { cause: error },
      );
    }
  }

  protected async clearSessionStateIfUnchanged(
    expectedPersistedSession: string | null | undefined,
    resetSilentAuthCounter = true,
  ): Promise<void> {
    this.sessionOperationGeneration += 1;
    this.sessionState = null;

    if (resetSilentAuthCounter) {
      this.silentAuthAttemptCount = 0;
    }

    if (!this.config.storage || expectedPersistedSession === undefined) {
      return;
    }

    try {
      if (expectedPersistedSession !== null) {
        await this.runStorageOperation(() =>
          this.removePersistedSessionIfUnchanged(expectedPersistedSession),
        );
      }
    } catch (error) {
      throw error instanceof GuardhouseError
        ? error
        : new GuardhouseError(
            "Failed to conditionally clear persisted session",
            "SESSION_STORAGE_CLEAR_FAILED",
            { cause: error },
          );
    }
  }

  async getSessionState() {
    if (this.sessionState) {
      const currentSession = this.sessionState;
      const generation = this.captureSessionOperation();
      const persistedSnapshot = this.config.storage
        ? JSON.stringify(currentSession)
        : undefined;
      if (currentSession.expiresAt <= Date.now()) {
        await this.clearSessionStateIfUnchanged(persistedSnapshot);
        return null;
      }
      if (currentSession.kind === "oidc") {
        let verifiedIdentity: OidcIdentity;
        try {
          verifiedIdentity = (
            await this.verifyIdToken(currentSession.idToken, {
              purpose: "session",
            })
          ).identity;
        } catch (error) {
          if (generation !== this.sessionOperationGeneration) return null;
          if (isTransientAuthError(error)) throw error;
          await this.clearSessionStateIfUnchanged(persistedSnapshot);
          return null;
        }
        if (generation !== this.sessionOperationGeneration) return null;
        if (
          JSON.stringify(verifiedIdentity) !==
          JSON.stringify(currentSession.identity)
        ) {
          await this.clearSessionStateIfUnchanged(persistedSnapshot);
          return null;
        }
        if (generation !== this.sessionOperationGeneration) return null;
        this.sessionState = { ...currentSession, identity: verifiedIdentity };
      }
      return { ...this.sessionState };
    }

    if (!this.config.storage) {
      return null;
    }

    if (this.storageClearPending) {
      try {
        await this.runStorageOperation(() =>
          this.removePersistedSessionKeysDurably(),
        );
        this.storageClearPending = false;
      } catch (error) {
        throw new GuardhouseError(
          "Failed to durably clear persisted session state",
          "SESSION_STORAGE_CLEAR_FAILED",
          { cause: error },
        );
      }
      return null;
    }

    const generation = this.captureSessionOperation();
    let persistedSnapshot: string | null | undefined;
    let snapshotRead = false;

    try {
      persistedSnapshot = await this.runStorageOperation(() =>
        this.config.storage!.getItem(this.sessionStorageKey),
      );
      snapshotRead = true;
      const serialized = persistedSnapshot;

      if (generation !== this.sessionOperationGeneration) {
        return null;
      }

      if (!serialized) {
        await this.runStorageOperation(() =>
          this.removeLegacyDefaultSessionState(),
        );

        if (generation !== this.sessionOperationGeneration) {
          return null;
        }

        return null;
      }

      let parsed: unknown;
      try {
        parsed = JSON.parse(serialized);
      } catch (error) {
        this.logger.warn(
          "Corrupt persisted session state detected; clearing local session state",
          {
            reason: error instanceof Error ? error.message : String(error),
          },
        );
        await this.clearSessionStateIfUnchanged(serialized);
        return null;
      }

      if (typeof parsed !== "object" || parsed === null) {
        await this.clearSessionStateIfUnchanged(serialized);
        return null;
      }

      const parsedRecord = parsed as Record<string, unknown>;

      if (
        parsedRecord["version"] !== 3 ||
        (parsedRecord["kind"] !== "oauth" && parsedRecord["kind"] !== "oidc") ||
        parsedRecord["issuer"] !== this.issuer ||
        parsedRecord["clientId"] !== this.config.clientId.trim() ||
        typeof parsedRecord["accessToken"] !== "string" ||
        typeof parsedRecord["tokenType"] !== "string" ||
        typeof parsedRecord["expiresAt"] !== "number" ||
        !Number.isFinite(parsedRecord["expiresAt"]) ||
        parsedRecord["expiresAt"] <= Date.now() ||
        typeof parsedRecord["hasRefreshToken"] !== "boolean"
      ) {
        await this.clearSessionStateIfUnchanged(serialized);
        return null;
      }

      const baseSessionState = {
        version: 3 as const,
        issuer: this.issuer,
        clientId: this.config.clientId.trim(),
        accessToken: parsedRecord["accessToken"],
        tokenType: parsedRecord["tokenType"],
        expiresAt: parsedRecord["expiresAt"],
        hasRefreshToken: Boolean(parsedRecord["hasRefreshToken"]),
        scope:
          typeof parsedRecord["scope"] === "string"
            ? parsedRecord["scope"]
            : undefined,
      };
      let sessionState: SessionState;
      if (parsedRecord["kind"] === "oidc") {
        const idToken = parsedRecord["idToken"];
        const identity = parsedRecord["identity"];
        if (
          typeof idToken !== "string" ||
          idToken.trim() === "" ||
          typeof identity !== "object" ||
          identity === null ||
          Array.isArray(identity)
        ) {
          await this.clearSessionStateIfUnchanged(serialized);
          return null;
        }
        const identityRecord = identity as Record<string, unknown>;
        if (
          identityRecord["issuer"] !== this.protocolIssuer ||
          identityRecord["clientId"] !== this.config.clientId.trim() ||
          typeof identityRecord["subject"] !== "string" ||
          !Array.isArray(identityRecord["audiences"]) ||
          identityRecord["audiences"].some(
            (entry) => typeof entry !== "string",
          ) ||
          typeof identityRecord["issuedAt"] !== "number" ||
          !Number.isFinite(identityRecord["issuedAt"]) ||
          typeof identityRecord["expiresAt"] !== "number" ||
          !Number.isFinite(identityRecord["expiresAt"]) ||
          (identityRecord["authorizedParty"] !== null &&
            typeof identityRecord["authorizedParty"] !== "string") ||
          (identityRecord["nonce"] !== null &&
            typeof identityRecord["nonce"] !== "string") ||
          (identityRecord["authTime"] !== null &&
            (typeof identityRecord["authTime"] !== "number" ||
              !Number.isFinite(identityRecord["authTime"]))) ||
          (identityRecord["acr"] !== null &&
            typeof identityRecord["acr"] !== "string") ||
          !Array.isArray(identityRecord["amr"]) ||
          identityRecord["amr"].some((entry) => typeof entry !== "string") ||
          (identityRecord["sessionId"] !== null &&
            typeof identityRecord["sessionId"] !== "string")
        ) {
          await this.clearSessionStateIfUnchanged(serialized);
          return null;
        }
        let verifiedIdentity: OidcIdentity;
        try {
          verifiedIdentity = (
            await this.verifyIdToken(idToken, { purpose: "session" })
          ).identity;
        } catch (error) {
          if (generation !== this.sessionOperationGeneration) return null;
          if (isTransientAuthError(error)) throw error;
          await this.clearSessionStateIfUnchanged(serialized);
          return null;
        }
        if (
          JSON.stringify(verifiedIdentity) !== JSON.stringify(identityRecord)
        ) {
          await this.clearSessionStateIfUnchanged(serialized);
          return null;
        }
        sessionState = {
          ...baseSessionState,
          kind: "oidc",
          idToken,
          identity: verifiedIdentity,
        };
      } else {
        sessionState = { ...baseSessionState, kind: "oauth" };
      }

      if (generation !== this.sessionOperationGeneration) {
        return null;
      }

      this.sessionState = sessionState;
      return { ...sessionState };
    } catch (error) {
      if (
        error instanceof GuardhouseError &&
        (error.code === "SESSION_STORAGE_CLEAR_FAILED" ||
          error.code === "SESSION_STORAGE_READ_FAILED")
      ) {
        throw error;
      }
      if (!snapshotRead) {
        throw new GuardhouseError(
          "Failed to read persisted session state",
          "SESSION_STORAGE_READ_FAILED",
          { cause: error },
        );
      }
      if (generation !== this.sessionOperationGeneration) return null;
      if (isTransientAuthError(error)) throw error;
      if (persistedSnapshot !== null && persistedSnapshot !== undefined) {
        await this.clearSessionStateIfUnchanged(persistedSnapshot);
      }
      return null;
    }
  }

  async clearSessionState(resetSilentAuthCounter = true): Promise<void> {
    this.sessionOperationGeneration += 1;
    this.sessionState = null;

    if (resetSilentAuthCounter) {
      this.silentAuthAttemptCount = 0;
    }

    if (!this.config.storage) {
      return;
    }

    try {
      await this.runStorageOperation(async () => {
        await this.removePersistedSessionKeysDurably();
      });
      this.storageClearPending = false;
    } catch (error) {
      this.storageClearPending = true;
      this.logger.warn("Failed to clear persisted session state", {
        reason: error instanceof Error ? error.message : String(error),
      });
      throw new GuardhouseError(
        "Failed to durably clear persisted session state",
        "SESSION_STORAGE_CLEAR_FAILED",
        { cause: error },
      );
    }
  }

  async handleSilentAuthenticationError(
    errorCode: string,
    errorDescription?: string,
  ): Promise<never> {
    const normalizedErrorCode = this.requireNonEmptyString(
      errorCode,
      "errorCode",
    );
    const requiresInteraction =
      SILENT_AUTH_ERROR_CODES.has(normalizedErrorCode);

    if (requiresInteraction) {
      this.silentAuthAttemptCount += 1;

      if (this.silentAuthAttemptCount > this.maxSilentAuthAttempts) {
        await this.clearSessionState(false);
        throw new GuardhouseError(
          "Silent authentication retry limit exceeded",
          "SILENT_AUTH_RETRY_LIMIT_EXCEEDED",
        );
      }

      await this.clearSessionState(false);
      this.logger.warn("Silent authentication failed and session was cleared", {
        errorCode: normalizedErrorCode,
        errorDescription,
        attempt: this.silentAuthAttemptCount,
        maxAttempts: this.maxSilentAuthAttempts,
      });

      throw new GuardhouseError(
        "Silent authentication failed and local session state was cleared",
        "SILENT_AUTH_INTERACTION_REQUIRED",
      );
    }

    throw new GuardhouseError(
      errorDescription || normalizedErrorCode,
      normalizedErrorCode,
    );
  }

  async validateOAuthCallback(
    input: AuthorizationCallbackInput,
    transactionValue: AuthorizationTransaction,
  ): Promise<ValidatedAuthorizationCallback> {
    const transaction = this.restoreAuthorizationTransaction(transactionValue);
    if (
      !input ||
      typeof input !== "object" ||
      (input.mode !== "query" && input.mode !== "form_post") ||
      typeof input.url !== "string"
    ) {
      throw new GuardhouseError(
        "OAuth callback input is invalid",
        "INVALID_CALLBACK_RESPONSE",
      );
    }

    const responseParamNames = new Set([
      "code",
      "state",
      "iss",
      "error",
      "error_description",
      "error_uri",
      "access_token",
      "id_token",
      "refresh_token",
      "token_type",
      "expires_in",
      "response",
      "session_state",
    ]);
    let parsedInputUrl: URL;
    try {
      parsedInputUrl = new URL(input.url);
    } catch (error) {
      throw new GuardhouseError(
        "OAuth callback URL is invalid",
        "INVALID_CALLBACK",
        {
          cause: error,
        },
      );
    }
    let sanitizedInputUrl: string;
    try {
      sanitizedInputUrl = sanitizeOAuthCallbackUrl(input.url);
    } catch (error) {
      throw new GuardhouseError(
        "OAuth callback URL is invalid",
        "INVALID_CALLBACK",
        {
          cause: error,
        },
      );
    }
    // Clear recognized callback material before any later validation can fail,
    // including mode and mixed-channel failures.
    this.maybeClearSensitiveCallbackUrl(input.url, sanitizedInputUrl);

    if (input.mode !== transaction.responseMode) {
      throw new GuardhouseError(
        "OAuth callback response mode does not match the authorization transaction",
        "INVALID_CALLBACK_RESPONSE",
      );
    }
    const fragmentParams = new URLSearchParams(
      parsedInputUrl.hash.replace(/^#/, ""),
    );
    if (
      Array.from(fragmentParams.keys()).some((key) =>
        responseParamNames.has(key.toLowerCase()),
      )
    ) {
      throw new GuardhouseError(
        "OAuth callback response parameters must not appear in a fragment",
        "INVALID_CALLBACK_RESPONSE",
      );
    }

    let callbackUrl = input.url;
    if (input.mode === "form_post") {
      if (
        Array.from(parsedInputUrl.searchParams.keys()).some((key) =>
          responseParamNames.has(key.toLowerCase()),
        )
      ) {
        throw new GuardhouseError(
          "form_post callback response parameters must not appear in the URL",
          "INVALID_CALLBACK_RESPONSE",
        );
      }
      if (
        !(input.body instanceof URLSearchParams) &&
        (typeof input.body !== "object" ||
          input.body === null ||
          Array.isArray(input.body) ||
          Object.values(input.body).some((value) => typeof value !== "string"))
      ) {
        throw new GuardhouseError(
          "form_post callback body must contain only string values",
          "INVALID_CALLBACK_RESPONSE",
        );
      }
      const body =
        input.body instanceof URLSearchParams
          ? new URLSearchParams(input.body)
          : new URLSearchParams(Object.entries(input.body));
      for (const [key, value] of body) {
        parsedInputUrl.searchParams.append(key, value);
      }
      callbackUrl = parsedInputUrl.toString();
    }

    let callback;
    try {
      callback = parseOAuthCallbackUrl(callbackUrl);
    } catch (error) {
      throw new GuardhouseError(
        error instanceof Error
          ? error.message
          : "OAuth callback response is malformed",
        "INVALID_CALLBACK_RESPONSE",
        { cause: error },
      );
    }

    if (
      callback.accessToken !== undefined ||
      callback.idToken !== undefined ||
      callback.refreshToken !== undefined ||
      callback.response !== undefined ||
      callback.tokenType !== undefined ||
      callback.expiresIn !== undefined
    ) {
      throw new GuardhouseError(
        "Front-channel token responses are not supported; authorization code flow is required",
        "UNSUPPORTED_CALLBACK_RESPONSE",
      );
    }

    const hasCode = callback.code !== undefined;
    const hasError = callback.error !== undefined;
    if (hasCode === hasError) {
      throw new GuardhouseError(
        "OAuth callback must contain exactly one of code or error",
        "INVALID_CALLBACK_RESPONSE",
      );
    }
    if (!callback.state) {
      throw new GuardhouseError(
        "OAuth callback is missing state",
        "STATE_VALIDATION_FAILED",
      );
    }

    if (
      hasCode &&
      (!callback.code ||
        callback.code !== callback.code.trim() ||
        callback.code.length > 4096 ||
        !/^[\x20-\x7E]+$/.test(callback.code))
    ) {
      throw new GuardhouseError(
        "OAuth callback code is invalid",
        "INVALID_CALLBACK_RESPONSE",
      );
    }
    if (
      hasError &&
      (!callback.error ||
        callback.error !== callback.error.trim() ||
        callback.error.length > 128 ||
        !/^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/.test(callback.error))
    ) {
      throw new GuardhouseError(
        "OAuth callback error is invalid",
        "INVALID_CALLBACK_RESPONSE",
      );
    }
    if (
      !hasError &&
      (callback.errorDescription !== undefined ||
        callback.errorUri !== undefined)
    ) {
      throw new GuardhouseError(
        "OAuth success callback contains error-only parameters",
        "INVALID_CALLBACK_RESPONSE",
      );
    }
    if (
      callback.errorDescription !== undefined &&
      (callback.errorDescription.length > 1024 ||
        !/^[\x20-\x21\x23-\x5B\x5D-\x7E]*$/.test(callback.errorDescription))
    ) {
      throw new GuardhouseError(
        "OAuth callback error_description is invalid",
        "INVALID_CALLBACK_RESPONSE",
      );
    }
    if (
      callback.sessionState !== undefined &&
      (callback.sessionState.length === 0 ||
        callback.sessionState.length > 512 ||
        // eslint-disable-next-line no-control-regex -- protocol values must reject ASCII controls
        /[\u0000-\u001F\u007F]/.test(callback.sessionState))
    ) {
      throw new GuardhouseError(
        "OAuth callback session_state is invalid",
        "INVALID_CALLBACK_RESPONSE",
      );
    }

    if (callback.iss) {
      let callbackIssuer: string;
      try {
        // Parse only to validate the URL; do not normalize the protocol value.
        canonicalizeIssuer(callback.iss);
        callbackIssuer = callback.iss;
      } catch (error) {
        throw new GuardhouseError(
          "OAuth callback issuer is invalid",
          "ISSUER_VALIDATION_FAILED",
          { cause: error },
        );
      }
      if (callbackIssuer !== transaction.issuer) {
        throw new GuardhouseError(
          "OAuth callback issuer does not match the authorization transaction",
          "ISSUER_VALIDATION_FAILED",
        );
      }
    } else if (transaction.issRequired) {
      throw new GuardhouseError(
        "OAuth callback is missing the required issuer parameter",
        "ISSUER_VALIDATION_FAILED",
      );
    }

    const normalizedSanitizedUrl = new URL(callback.sanitizedUrl);
    const normalizedRedirectUrl = new URL(transaction.redirectUri);
    if (
      parsedInputUrl.username ||
      parsedInputUrl.password ||
      !callbackRedirectMatches(normalizedSanitizedUrl, normalizedRedirectUrl)
    ) {
      throw new GuardhouseError(
        "OAuth callback URL does not match the authorization transaction redirect URI",
        "REDIRECT_URI_MISMATCH",
      );
    }

    try {
      this.stateManager.validateAndConsumeState(
        transaction.state,
        callback.state,
      );
    } catch (error) {
      throw new GuardhouseError(
        "OAuth callback state validation failed",
        "STATE_VALIDATION_FAILED",
        { cause: error },
      );
    }

    if (hasError) {
      return Object.freeze({
        type: "error",
        error: callback.error!,
        errorDescription: callback.errorDescription,
        errorUri: callback.errorUri,
        state: callback.state,
        issuer: callback.iss,
        sanitizedUrl: callback.sanitizedUrl,
      }) as ValidatedAuthorizationCallback;
    }

    this.resetSilentAuthAttemptCounter();
    const validatedCallback = Object.freeze({
      type: "authorization_code",
      code: callback.code!,
      state: callback.state,
      issuer: callback.iss,
      sessionState: callback.sessionState,
      sanitizedUrl: callback.sanitizedUrl,
    }) as AuthorizationCodeCallback;
    validatedAuthorizationCodeEvidence.set(validatedCallback, {
      owner: this,
      transaction,
    });
    return validatedCallback;
  }
}
