import {
  isSilentAuthenticationError,
  OAuthStateManager,
  parseOAuthCallbackUrl,
} from "../auth";
import { GuardhouseError } from "../config";
import { decodeJWT, validateOidcHashClaims } from "../token";

import { SILENT_AUTH_ERROR_CODES } from "./constants";
import { GuardhouseClientBase } from "./base-client";
import type { TokenResponse } from "./types";

export class GuardhouseClientSession extends GuardhouseClientBase {
  private readonly stateManager = new OAuthStateManager();

  protected async cacheSessionState(
    tokenResponse: TokenResponse,
  ): Promise<void> {
    const sessionState = this.buildSessionStateFromTokenResponse(tokenResponse);
    this.sessionState = sessionState;

    if (!this.config.storage) {
      return;
    }

    try {
      await this.config.storage.setItem(
        this.sessionStorageKey,
        JSON.stringify(sessionState),
      );
    } catch (error) {
      this.logger.warn("Failed to persist session state", {
        reason: error instanceof Error ? error.message : String(error),
      });
    }
  }

  async getSessionState() {
    if (this.sessionState) {
      return { ...this.sessionState };
    }

    if (!this.config.storage) {
      return null;
    }

    try {
      const serialized = await this.config.storage.getItem(
        this.sessionStorageKey,
      );
      if (!serialized) {
        return null;
      }

      const parsed = JSON.parse(serialized);
      if (
        typeof parsed !== "object" ||
        parsed === null ||
        typeof parsed.accessToken !== "string" ||
        typeof parsed.tokenType !== "string" ||
        typeof parsed.expiresAt !== "number" ||
        typeof parsed.hasRefreshToken !== "boolean"
      ) {
        await this.clearSessionState();
        return null;
      }

      this.sessionState = parsed;
      return { ...parsed };
    } catch {
      await this.clearSessionState();
      return null;
    }
  }

  async clearSessionState(resetSilentAuthCounter = true): Promise<void> {
    this.sessionState = null;

    if (resetSilentAuthCounter) {
      this.silentAuthAttemptCount = 0;
    }

    if (!this.config.storage) {
      return;
    }

    try {
      await this.config.storage.removeItem(this.sessionStorageKey);
    } catch (error) {
      this.logger.warn("Failed to clear persisted session state", {
        reason: error instanceof Error ? error.message : String(error),
      });
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
    callbackUrl: string,
    expectedState: string,
    prompt?: string,
  ) {
    const callback = parseOAuthCallbackUrl(callbackUrl);
    this.maybeClearSensitiveCallbackUrl(callbackUrl, callback.sanitizedUrl);

    if (callback.idToken) {
      const decodedIdToken = decodeJWT(callback.idToken, {
        debug: this.config.debug,
      });
      const hashValidation = await validateOidcHashClaims(decodedIdToken, {
        accessToken: callback.accessToken,
        authorizationCode: callback.code,
        requireAtHash: Boolean(callback.accessToken),
        requireCHash: Boolean(callback.code),
        debug: this.config.debug,
      });

      if (!hashValidation.valid) {
        throw new GuardhouseError(
          "OIDC hash claim validation failed for callback tokens",
          "OIDC_HASH_VALIDATION_FAILED",
        );
      }
    }

    if (callback.error) {
      const normalizedPrompt = prompt?.trim().toLowerCase();

      if (
        normalizedPrompt === "none" &&
        isSilentAuthenticationError(callback.error)
      ) {
        await this.handleSilentAuthenticationError(
          callback.error,
          callback.errorDescription,
        );
      }

      throw new GuardhouseError(
        callback.errorDescription || callback.error,
        callback.error,
      );
    }

    if (!callback.state) {
      throw new GuardhouseError(
        "OAuth callback is missing state",
        "STATE_VALIDATION_FAILED",
      );
    }

    this.stateManager.validateAndConsumeState(expectedState, callback.state);
    this.resetSilentAuthAttemptCounter();

    return callback;
  }
}
