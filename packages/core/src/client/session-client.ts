import {
  isSilentAuthenticationError,
  OAuthStateManager,
  parseOAuthCallbackUrl,
} from "../auth";
import { GuardhouseError } from "../config";
import { decodeJWT, validateOidcHashClaims } from "../token";

import { SILENT_AUTH_ERROR_CODES } from "./constants";
import { GuardhouseClientBase } from "./base-client";
import type { SessionState, TokenResponse } from "./types";

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
        await this.clearSessionState();
        return null;
      }

      if (typeof parsed !== "object" || parsed === null) {
        await this.clearSessionState();
        return null;
      }

      const parsedRecord = parsed as Record<string, unknown>;

      if (
        typeof parsedRecord["accessToken"] !== "string" ||
        typeof parsedRecord["tokenType"] !== "string" ||
        typeof parsedRecord["expiresAt"] !== "number" ||
        typeof parsedRecord["hasRefreshToken"] !== "boolean"
      ) {
        await this.clearSessionState();
        return null;
      }

      const sessionState: SessionState = {
        accessToken: parsedRecord["accessToken"],
        tokenType: parsedRecord["tokenType"],
        expiresAt: parsedRecord["expiresAt"],
        hasRefreshToken: Boolean(parsedRecord["hasRefreshToken"]),
        scope:
          typeof parsedRecord["scope"] === "string"
            ? parsedRecord["scope"]
            : undefined,
        idToken:
          typeof parsedRecord["idToken"] === "string"
            ? parsedRecord["idToken"]
            : undefined,
      };

      this.sessionState = sessionState;
      return { ...sessionState };
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
      // SECURITY REQUIREMENT: The id_token received in the front-channel callback MUST be cryptographically verified (signature, iss, aud, exp) using the full validateToken flow BEFORE trusting the at_hash or c_hash. Decoding alone is insufficient and highly vulnerable to injection attacks.
      const decodedIdToken = decodeJWT(callback.idToken, {
        debug: this.config.debug,
      });
      const hashValidation = await validateOidcHashClaims(decodedIdToken, {
        idTokenAlg: decodedIdToken.header.alg,
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

    // OAuthStateManager performs TTL-based lazy cleanup internally during
    // validateAndConsumeState, so expired state entries are purged on each callback.
    this.stateManager.validateAndConsumeState(expectedState, callback.state);
    this.resetSilentAuthAttemptCounter();

    return callback;
  }
}
