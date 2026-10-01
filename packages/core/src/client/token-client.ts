import { GuardhouseError } from "../config";
import type { ValidatedAuthorizationCallback } from "../auth";
import { OAuthPKCEManager } from "../pkce";
import { validateOidcHashClaims } from "../token";
import type { IdTokenValidationContext } from "../token";
import {
  isOidcIdentityEvidence,
  verifyHistoricalIdTokenIdentity,
  type OidcIdentity,
  type OidcIdentityEvidence,
  type VerifiedIdToken,
} from "../token/id-token-verifier";
import {
  sanitizeUrlForLogs,
  validateAndNormalizeRedirectUri,
  validateResourceIndicator,
} from "../security";

import {
  MAX_TOKEN_PARAM_VALUE_LENGTH,
  SILENT_AUTH_ERROR_CODES,
} from "./constants";
import { GuardhouseClientSession } from "./session-client";
import type {
  AuthorizationCodeExchangeResult,
  ClientCredentialsTokenOptions,
  IntrospectionResponse,
  RefreshOAuthTokenOptions,
  RefreshOidcSessionOptions,
  RefreshOidcSessionResult,
  RestoreOidcSessionOptions,
  RestoredOidcSession,
  TokenResponse,
  UserInfoResponse,
} from "./types";

export class GuardhouseClientToken extends GuardhouseClientSession {
  private readonly pkceManager = new OAuthPKCEManager();
  private activeRefreshOperation: {
    key: string;
    promise: Promise<{ tokens: TokenResponse; idToken?: VerifiedIdToken }>;
  } | null = null;

  private createRefreshOperationKey(
    body: URLSearchParams,
    validationContext: IdTokenValidationContext | undefined,
    requestedScope: string | undefined,
  ): string {
    return JSON.stringify({
      request: body.toString(),
      validationContext,
      requestedScope,
    });
  }

  async stashCodeVerifier(codeVerifier: string): Promise<string> {
    return this.pkceManager.stashCodeVerifier(codeVerifier);
  }

  private async exchangeCodeForTokens(
    code: string,
    codeVerifier: string,
    redirectUri: string,
    params: Record<string, string> = {},
    validationContext?: IdTokenValidationContext,
    requestedScopeOverride?: string,
  ): Promise<AuthorizationCodeExchangeResult> {
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

    const sessionOperationGeneration = this.beginSessionOperation();
    const response = await this.fetch(this.endpoints.token, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });

    const tokenResponse = this.decodeTokenResponse(response.data);
    const requestedScope = requestedScopeOverride ?? this.config.scope;
    this.assertNoScopeEscalation(requestedScope, tokenResponse.scope);

    let verifiedIdToken: VerifiedIdToken | undefined;
    let verifiedIdentity: OidcIdentity | undefined;
    const expectsOidc = this.parseRequestedScope(requestedScope).has("openid");
    if (tokenResponse.id_token) {
      if (!expectsOidc) {
        throw new GuardhouseError(
          "An OAuth-only authorization response must not include an ID token",
          "UNEXPECTED_ID_TOKEN",
        );
      }
      if (!validationContext) {
        throw new GuardhouseError(
          "ID token validation context is required for authorization code exchange",
          "ID_TOKEN_CONTEXT_REQUIRED",
        );
      }
      verifiedIdToken = await this.verifyIdToken(
        tokenResponse.id_token,
        validationContext,
      );
      const hashValidation = await validateOidcHashClaims(
        {
          header: verifiedIdToken.header,
          payload: {
            ...verifiedIdToken.payload,
            aud:
              typeof verifiedIdToken.payload.aud === "string"
                ? verifiedIdToken.payload.aud
                : [...verifiedIdToken.payload.aud],
          },
        },
        {
          idTokenAlg: verifiedIdToken.header.alg,
          accessToken: tokenResponse.access_token,
          authorizationCode: normalizedCode,
          requireAtHash: false,
          requireCHash: false,
          debug: this.config.debug,
        },
      );

      if (!hashValidation.valid) {
        throw new GuardhouseError(
          "OIDC hash claim validation failed for token response",
          "OIDC_HASH_VALIDATION_FAILED",
        );
      }
      verifiedIdentity = verifiedIdToken.identity;
    } else if (expectsOidc) {
      throw new GuardhouseError(
        "An openid token response must include an ID token",
        "ID_TOKEN_REQUIRED",
      );
    }

    await this.cacheSessionState(tokenResponse, sessionOperationGeneration, {
      verifiedIdentity,
    });
    this.resetSilentAuthAttemptCounter();

    this.logger.info("Authorization code exchange succeeded", {
      expiresIn: tokenResponse.expires_in,
      hasRefreshToken: Boolean(tokenResponse.refresh_token),
      hasIdToken: Boolean(tokenResponse.id_token),
    });

    if (verifiedIdToken && verifiedIdentity) {
      return {
        mode: "oidc",
        tokens: tokenResponse,
        idToken: verifiedIdToken,
        identity: verifiedIdentity,
      };
    }
    return { mode: "oauth2", tokens: tokenResponse };
  }

  async exchangeAuthorizationCode(
    callback: Extract<
      ValidatedAuthorizationCallback,
      { type: "authorization_code" }
    >,
  ): Promise<AuthorizationCodeExchangeResult> {
    const restored = this.consumeValidatedAuthorizationCallback(callback);

    return this.exchangeCodeForTokens(
      callback.code,
      restored.codeVerifier,
      restored.redirectUri,
      {},
      {
        purpose: "authorization_code",
        nonce: restored.nonce,
        maxAgeSeconds: restored.maxAgeSeconds,
        requiredAcrValues: restored.requiredAcrValues,
        requiredAmrValues: restored.requiredAmrValues,
      } as IdTokenValidationContext,
      restored.requestedScope,
    );
  }

  private async refreshToken(
    refreshToken: string,
    params: Record<string, string> = {},
    validationContext?: IdTokenValidationContext,
    grantedScope?: string,
    requestOptions: Pick<RefreshOAuthTokenOptions, "scope" | "audience"> = {},
  ): Promise<{ tokens: TokenResponse; idToken?: VerifiedIdToken }> {
    const normalizedRefreshToken = this.requireNonEmptyString(
      refreshToken,
      "refreshToken",
    );

    if (normalizedRefreshToken.length > MAX_TOKEN_PARAM_VALUE_LENGTH) {
      throw new GuardhouseError(
        `refreshToken exceeds maximum allowed length (${MAX_TOKEN_PARAM_VALUE_LENGTH})`,
        "INVALID_REQUEST",
      );
    }

    // Reserved protocol fields enter through typed options, never extensions.
    const protocolParams: Record<string, string> = {};
    for (const name of ["scope", "audience"] as const) {
      if (requestOptions[name] === undefined) continue;
      const value = this.requireNonEmptyString(requestOptions[name], name);
      if (value.length > MAX_TOKEN_PARAM_VALUE_LENGTH) {
        throw new GuardhouseError(
          `${name} exceeds maximum allowed length (${MAX_TOKEN_PARAM_VALUE_LENGTH})`,
          "INVALID_REQUEST",
        );
      }
      protocolParams[name] = value;
    }
    if (protocolParams.scope !== undefined) {
      const granted = this.parseRequestedScope(grantedScope);
      if (granted.size === 0) {
        throw new GuardhouseError(
          "grantedScope is required when requesting a refresh scope",
          "INVALID_REQUEST",
        );
      }
      const requested = this.parseRequestedScope(protocolParams.scope);
      if ([...requested].some((scope) => !granted.has(scope))) {
        throw new GuardhouseError(
          "Refresh scope exceeds the previously granted scope",
          "SCOPE_ESCALATION_DETECTED",
        );
      }
      protocolParams.scope = [...requested].join(" ");
    }
    const effectiveScope =
      protocolParams.scope ?? grantedScope ?? this.config.scope;

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

    for (const key of Object.keys(safeParams).sort()) {
      body.set(key, safeParams[key]);
    }
    for (const [key, value] of Object.entries(protocolParams))
      body.set(key, value);

    const operationKey = this.createRefreshOperationKey(
      body,
      validationContext,
      effectiveScope,
    );
    const activeRefreshOperation = this.activeRefreshOperation;

    if (activeRefreshOperation) {
      if (activeRefreshOperation.key !== operationKey) {
        throw new GuardhouseError(
          "A different token refresh request is already in progress for this client",
          "REFRESH_OPERATION_CONFLICT",
        );
      }

      this.logger.debug("Joining in-flight token refresh request");
      return activeRefreshOperation.promise;
    }

    const sessionOperationGeneration = this.captureSessionOperation();
    const refreshPromise = this.executeRefreshTokenRequest(
      body,
      effectiveScope,
      validationContext,
      sessionOperationGeneration,
    );

    this.activeRefreshOperation = {
      key: operationKey,
      promise: refreshPromise,
    };

    try {
      return await refreshPromise;
    } finally {
      if (this.activeRefreshOperation?.promise === refreshPromise) {
        this.activeRefreshOperation = null;
      }
    }
  }

  private async executeRefreshTokenRequest(
    body: URLSearchParams,
    requestedScope: string | undefined,
    validationContext: IdTokenValidationContext | undefined,
    sessionOperationGeneration: number,
  ): Promise<{ tokens: TokenResponse; idToken?: VerifiedIdToken }> {
    this.logger.info("Refreshing access token");

    const previousSessionState =
      validationContext?.purpose === "refresh"
        ? null
        : await this.getSessionState();
    this.assertSessionOperationCurrent(sessionOperationGeneration);
    const persistedSessionSnapshot = this.config.storage
      ? await this.capturePersistedSessionState()
      : undefined;
    this.assertSessionOperationCurrent(sessionOperationGeneration);
    try {
      const response = await this.fetch(this.endpoints.token, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: body.toString(),
      });
      const decodedTokens = this.decodeTokenResponse(response.data);
      // RFC 6749 section 5.1: omitted response scope equals the requested scope.
      const sentScope = body.get("scope");
      const tokenResponse =
        decodedTokens.scope === undefined && sentScope !== null
          ? { ...decodedTokens, scope: sentScope }
          : decodedTokens;
      this.assertNoScopeEscalation(requestedScope, tokenResponse.scope);

      let replacementIdToken: VerifiedIdToken | undefined;
      let verifiedIdentity: OidcIdentity | undefined;
      if (tokenResponse.id_token) {
        if (validationContext?.purpose !== "refresh") {
          throw new GuardhouseError(
            "OAuth-only refresh unexpectedly returned an ID token",
            "UNEXPECTED_ID_TOKEN",
          );
        }
        const previousIdentity = validationContext.previousIdentity;
        if (!previousIdentity) {
          throw new GuardhouseError(
            "Cannot validate a refreshed ID token without a stored verified identity",
            "REFRESH_IDENTITY_REQUIRED",
          );
        }
        const refreshContext: IdTokenValidationContext = {
          purpose: "refresh",
          previousIdentity,
          requiredAcrValues:
            validationContext && "requiredAcrValues" in validationContext
              ? validationContext.requiredAcrValues
              : undefined,
          requiredAmrValues:
            validationContext && "requiredAmrValues" in validationContext
              ? validationContext.requiredAmrValues
              : undefined,
        };
        replacementIdToken = await this.verifyIdToken(
          tokenResponse.id_token,
          refreshContext,
        );
        const hashValidation = await validateOidcHashClaims(
          {
            header: replacementIdToken.header,
            payload: {
              ...replacementIdToken.payload,
              aud:
                typeof replacementIdToken.payload.aud === "string"
                  ? replacementIdToken.payload.aud
                  : [...replacementIdToken.payload.aud],
            },
          },
          {
            idTokenAlg: replacementIdToken.header.alg,
            accessToken: tokenResponse.access_token,
            requireAtHash: false,
            requireCHash: false,
            debug: this.config.debug,
          },
        );

        if (!hashValidation.valid) {
          throw new GuardhouseError(
            "OIDC hash claim validation failed for refreshed token response",
            "OIDC_HASH_VALIDATION_FAILED",
          );
        }
        verifiedIdentity = replacementIdToken.identity;
      }

      await this.cacheSessionState(tokenResponse, sessionOperationGeneration, {
        previousSessionState,
        preserveRefreshToken: true,
        verifiedIdentity,
      });
      this.resetSilentAuthAttemptCounter();

      this.logger.info("Access token refreshed", {
        expiresIn: tokenResponse.expires_in,
        hasRefreshToken: Boolean(tokenResponse.refresh_token),
      });

      return { tokens: tokenResponse, idToken: replacementIdToken };
    } catch (error) {
      this.assertSessionOperationCurrent(sessionOperationGeneration);

      if (
        error instanceof GuardhouseError &&
        (error.code === "invalid_grant" ||
          (typeof error.code === "string" &&
            SILENT_AUTH_ERROR_CODES.has(error.code)))
      ) {
        await this.clearSessionStateIfUnchanged(
          persistedSessionSnapshot,
          false,
        );
        this.logger.warn("Refresh failed and session state was cleared", {
          errorCode: error.code,
        });
      }

      throw error;
    }
  }

  async refreshOAuthToken(
    refreshToken: string,
    options: RefreshOAuthTokenOptions = {},
  ): Promise<TokenResponse> {
    const result = await this.refreshToken(
      refreshToken,
      options.requestParameters ?? {},
      undefined,
      options.grantedScope,
      options,
    );
    if (result.tokens.id_token) {
      throw new GuardhouseError(
        "OAuth-only refresh unexpectedly returned an ID token",
        "UNEXPECTED_ID_TOKEN",
      );
    }
    return result.tokens;
  }

  async refreshOidcSession(
    refreshToken: string,
    options: RefreshOidcSessionOptions,
  ): Promise<RefreshOidcSessionResult> {
    if (!options || typeof options !== "object") {
      throw new GuardhouseError(
        "OIDC refresh options are required",
        "INVALID_REQUEST",
      );
    }
    const previousIdToken = this.requireNonEmptyString(
      options.previousIdToken,
      "previousIdToken",
    );
    const previousIdentity = await verifyHistoricalIdTokenIdentity(
      previousIdToken,
      {
        authority: this.protocolIssuer,
        clientId: this.config.clientId,
        cacheTtlMs: this.discoveryCacheTtlMs,
        requiredAcrValues: options.requiredAcrValues,
        requiredAmrValues: options.requiredAmrValues,
      },
    );
    const context: IdTokenValidationContext = {
      purpose: "refresh",
      previousIdentity,
      requiredAcrValues: options.requiredAcrValues,
      requiredAmrValues: options.requiredAmrValues,
    };
    const result = await this.refreshToken(
      refreshToken,
      options.requestParameters ?? {},
      context,
      options.grantedScope,
      options,
    );
    if (result.idToken) {
      return {
        identityStatus: "current",
        tokens: result.tokens,
        identity: result.idToken.identity,
        idToken: result.idToken,
      };
    }
    return {
      identityStatus: "historical",
      tokens: result.tokens,
      identity: previousIdentity,
    };
  }

  /**
   * Rebuild historical identity evidence from a signed ID token and confirm the
   * access token online through subject-bound UserInfo. Does not rotate tokens,
   * write session state, or expose old ID-token claims as a current credential.
   */
  async restoreOidcSession(
    accessToken: string,
    options: RestoreOidcSessionOptions,
  ): Promise<RestoredOidcSession> {
    const token = this.requireNonEmptyString(accessToken, "accessToken");
    if (!options || typeof options !== "object") {
      throw new GuardhouseError(
        "OIDC restoration options are required",
        "INVALID_REQUEST",
      );
    }
    const idToken = this.requireNonEmptyString(options.idToken, "idToken");
    const identity = await verifyHistoricalIdTokenIdentity(idToken, {
      authority: this.protocolIssuer,
      clientId: this.config.clientId,
      cacheTtlMs: this.discoveryCacheTtlMs,
      requiredAcrValues: options.requiredAcrValues,
      requiredAmrValues: options.requiredAmrValues,
    });
    const userInfo = await this.getUserInfo(token, identity);
    return Object.freeze({ identity, userInfo });
  }

  async getUserInfo(
    token: string,
    identity: OidcIdentityEvidence,
  ): Promise<UserInfoResponse> {
    const normalizedToken = this.requireNonEmptyString(token, "token");
    if (
      !isOidcIdentityEvidence(identity) ||
      identity.issuer !== this.protocolIssuer ||
      identity.clientId !== this.config.clientId.trim() ||
      typeof identity.subject !== "string" ||
      identity.subject === ""
    ) {
      throw new GuardhouseError(
        "UserInfo requires a verified identity for this issuer and client",
        "INVALID_IDENTITY",
      );
    }

    this.logger.debug("Fetching user info", {
      hasToken: true,
    });

    const response = await this.fetch(this.endpoints.userInfo, {
      token: normalizedToken,
    });

    const user = this.decodeUserInfoResponse(response.data);

    if (user.sub !== identity.subject) {
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

  async requestClientCredentialsToken(
    options: ClientCredentialsTokenOptions = {},
  ): Promise<TokenResponse> {
    if (!this.config.clientSecret) {
      throw new GuardhouseError(
        "Client credentials require a confidential client secret",
        "CLIENT_SECRET_REQUIRED",
      );
    }
    const { safeParams, blockedKeys } = this.sanitizeTokenBodyParams(
      options.requestParameters ?? {},
    );
    if (blockedKeys.length > 0) {
      this.logger.warn("Ignoring reserved client credentials request keys", {
        blockedKeys,
      });
    }
    const body = new URLSearchParams({ grant_type: "client_credentials" });
    if (options.scope?.trim()) body.set("scope", options.scope.trim());
    if (options.audience?.trim()) body.set("audience", options.audience.trim());
    const unvalidatedResources =
      options.resource === undefined
        ? []
        : typeof options.resource === "string"
          ? [options.resource]
          : [...options.resource];
    if (unvalidatedResources.length > 16) {
      throw new GuardhouseError(
        "resource must contain no more than 16 values",
        "INVALID_REQUEST",
      );
    }
    let resources: string[];
    try {
      resources = unvalidatedResources.map((resource) =>
        validateResourceIndicator(resource),
      );
    } catch (error) {
      throw new GuardhouseError(
        error instanceof Error
          ? error.message
          : "resource values must be absolute URIs without fragments",
        "INVALID_REQUEST",
        { cause: error },
      );
    }
    for (const resource of resources) {
      body.append("resource", resource);
    }
    for (const [key, value] of Object.entries(safeParams)) body.set(key, value);
    const response = await this.fetch(this.endpoints.token, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const tokens = this.decodeTokenResponse(response.data);
    if (tokens.id_token || tokens.refresh_token) {
      throw new GuardhouseError(
        "Client credentials response contains disallowed user-session tokens",
        "INVALID_TOKEN_RESPONSE",
      );
    }
    this.assertNoScopeEscalation(options.scope, tokens.scope);
    return tokens;
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

    const rawResponse = await this.fetch(this.endpoints.introspection, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
    });
    const response = this.decodeIntrospectionResponse(rawResponse.data);

    this.logger.debug("Token introspection completed", {
      active: Boolean(response.active),
      hasSubject: response.active && Boolean(response.sub),
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
