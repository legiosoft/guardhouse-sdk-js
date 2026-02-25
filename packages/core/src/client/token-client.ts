import { GuardhouseError } from "../config";
import { OAuthPKCEManager } from "../pkce";
import { decodeJWT, validateOidcHashClaims } from "../token";
import {
  sanitizeUrlForLogs,
  timingSafeEqual,
  validateAndNormalizeRedirectUri,
} from "../security";

import { SILENT_AUTH_ERROR_CODES } from "./constants";
import { GuardhouseClientSession } from "./session-client";
import type {
  IntrospectionResponse,
  TokenResponse,
  UserInfoResponse,
} from "./types";

export class GuardhouseClientToken extends GuardhouseClientSession {
  private readonly pkceManager = new OAuthPKCEManager();

  async stashCodeVerifier(codeVerifier: string): Promise<string> {
    return this.pkceManager.stashCodeVerifier(codeVerifier);
  }

  async exchangeCodeForTokens(
    code: string,
    codeVerifier: string,
    redirectUri: string,
    params: Record<string, string> = {},
  ): Promise<TokenResponse> {
    const normalizedCode = this.requireNonEmptyString(code, "code");
    const normalizedCodeVerifier = this.validatePkceCodeVerifier(codeVerifier);
    const normalizedRedirectUri = validateAndNormalizeRedirectUri(redirectUri);

    const { safeParams, blockedKeys } = this.sanitizeTokenBodyParams(params);

    if (blockedKeys.length > 0) {
      this.logger.warn("Ignoring reserved token request keys in params", {
        blockedKeys,
      });
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code: normalizedCode,
      redirect_uri: normalizedRedirectUri,
      code_verifier: normalizedCodeVerifier,
    });

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    for (const [key, value] of Object.entries(safeParams)) {
      body.set(key, value);
    }

    this.logger.info("Exchanging authorization code for tokens", {
      redirectUri: sanitizeUrlForLogs(normalizedRedirectUri),
      hasCode: true,
      hasCodeVerifier: true,
    });

    const response = await this.fetch(this.endpoints.token, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });

    const tokenResponse = response.data as TokenResponse;
    const requestedScope = params.scope ?? this.config.scope;
    this.assertNoScopeEscalation(requestedScope, tokenResponse.scope);

    if (tokenResponse.id_token) {
      const decodedIdToken = decodeJWT(tokenResponse.id_token, {
        debug: this.config.debug,
      });
      const hashValidation = await validateOidcHashClaims(decodedIdToken, {
        accessToken: tokenResponse.access_token,
        authorizationCode: normalizedCode,
        requireAtHash: true,
        requireCHash: false,
        debug: this.config.debug,
      });

      if (!hashValidation.valid) {
        throw new GuardhouseError(
          "OIDC hash claim validation failed for token response",
          "OIDC_HASH_VALIDATION_FAILED",
        );
      }
    }

    await this.cacheSessionState(tokenResponse);
    this.resetSilentAuthAttemptCounter();

    this.logger.info("Authorization code exchange succeeded", {
      expiresIn: tokenResponse.expires_in,
      hasRefreshToken: Boolean(tokenResponse.refresh_token),
      hasIdToken: Boolean(tokenResponse.id_token),
    });

    return tokenResponse;
  }

  async exchangeCodeForTokensUsingHandle(
    code: string,
    codeVerifierHandle: string,
    redirectUri: string,
    params: Record<string, string> = {},
  ): Promise<TokenResponse> {
    const normalizedHandle = this.requireNonEmptyString(
      codeVerifierHandle,
      "codeVerifierHandle",
    );

    let verifier = "";

    try {
      verifier = this.pkceManager.consumeCodeVerifier(normalizedHandle);
      return await this.exchangeCodeForTokens(
        code,
        verifier,
        redirectUri,
        params,
      );
    } finally {
      verifier = "";
      this.pkceManager.dropCodeVerifier(normalizedHandle);
    }
  }

  async refreshToken(
    refreshToken: string,
    params: Record<string, string> = {},
  ): Promise<TokenResponse> {
    const normalizedRefreshToken = this.requireNonEmptyString(
      refreshToken,
      "refreshToken",
    );

    const { safeParams, blockedKeys } = this.sanitizeTokenBodyParams(params);

    if (blockedKeys.length > 0) {
      this.logger.warn("Ignoring reserved token request keys in params", {
        blockedKeys,
      });
    }

    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: normalizedRefreshToken,
    });

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    for (const [key, value] of Object.entries(safeParams)) {
      body.set(key, value);
    }

    this.logger.info("Refreshing access token");

    try {
      const response = await this.fetch(this.endpoints.token, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });

      const tokenResponse = response.data as TokenResponse;
      const requestedScope = params.scope ?? this.config.scope;
      this.assertNoScopeEscalation(requestedScope, tokenResponse.scope);

      if (tokenResponse.id_token) {
        const decodedIdToken = decodeJWT(tokenResponse.id_token, {
          debug: this.config.debug,
        });
        const hashValidation = await validateOidcHashClaims(decodedIdToken, {
          accessToken: tokenResponse.access_token,
          requireAtHash: true,
          requireCHash: false,
          debug: this.config.debug,
        });

        if (!hashValidation.valid) {
          throw new GuardhouseError(
            "OIDC hash claim validation failed for refreshed token response",
            "OIDC_HASH_VALIDATION_FAILED",
          );
        }
      }

      await this.cacheSessionState(tokenResponse);
      this.resetSilentAuthAttemptCounter();

      this.logger.info("Access token refreshed", {
        expiresIn: tokenResponse.expires_in,
        hasRefreshToken: Boolean(tokenResponse.refresh_token),
      });

      return tokenResponse;
    } catch (error) {
      if (
        error instanceof GuardhouseError &&
        (error.code === "invalid_grant" ||
          (typeof error.code === "string" &&
            SILENT_AUTH_ERROR_CODES.has(error.code)))
      ) {
        await this.clearSessionState(false);
        this.logger.warn("Refresh failed and session state was cleared", {
          errorCode: error.code,
        });
      }

      throw error;
    }
  }

  async getUserInfo(
    token: string,
    expectedSubject?: string,
  ): Promise<UserInfoResponse> {
    const normalizedToken = this.requireNonEmptyString(token, "token");
    const normalizedExpectedSubject =
      typeof expectedSubject === "string" && expectedSubject.trim() !== ""
        ? expectedSubject.trim()
        : undefined;

    this.logger.debug("Fetching user info", {
      hasToken: true,
    });

    const response = await this.fetch(this.endpoints.userInfo, {
      token: normalizedToken,
    });

    const user = response.data as UserInfoResponse;

    if (
      normalizedExpectedSubject &&
      !timingSafeEqual(user.sub ?? "", normalizedExpectedSubject)
    ) {
      throw new GuardhouseError(
        "UserInfo response subject does not match expected subject",
        "USERINFO_SUBJECT_MISMATCH",
      );
    }

    this.logger.debug("User info fetched", {
      hasSubject: Boolean(user.sub),
      hasEmail: Boolean(user.email),
    });

    return user;
  }

  async introspectToken(token: string): Promise<IntrospectionResponse> {
    const normalizedToken = this.requireNonEmptyString(token, "token");

    this.logger.debug("Introspecting token", {
      hasToken: true,
    });

    const body = new URLSearchParams({
      token: normalizedToken,
      token_type_hint: "access_token",
    });

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    const response = await this.postForm<IntrospectionResponse>(
      this.endpoints.introspection,
      body,
    );

    this.logger.debug("Token introspection completed", {
      active: Boolean(response.active),
      hasSubject: Boolean(response.sub),
    });

    return response;
  }

  async revokeToken(
    token: string,
    tokenTypeHint: "access_token" | "refresh_token" = "access_token",
  ): Promise<void> {
    this.assertRecentUserInteraction("Token revocation");

    const normalizedToken = this.requireNonEmptyString(token, "token");

    this.logger.info("Revoking token", {
      hasToken: true,
    });

    const body = new URLSearchParams({ token: normalizedToken });

    if (!this.config.clientSecret) {
      body.set("client_id", this.config.clientId);
    }

    body.set("token_type_hint", tokenTypeHint);

    await this.fetch(this.endpoints.revocation, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });

    await this.clearSessionState();

    this.logger.info("Token revoked");
  }
}
