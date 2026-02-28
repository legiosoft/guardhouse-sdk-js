import {
  GuardhouseClient as CoreGuardhouseClient,
  GuardhouseError as CoreGuardhouseError,
  generateAuthUrl,
  type CryptoAdapter,
  type TokenResponse as CoreTokenResponse,
  type User as CoreUser,
} from "@guardhouse/core";
import type {
  BrowserLoginOptions,
  ExchangeCodeForTokensOptions,
  GetAccessTokenOptions,
  GuardhouseAuthResult,
  GuardhouseLogoutOptions,
  GuardhouseSession,
  GuardhouseTokenResponse,
  RedirectTokenPayload,
  RefreshTokenOptions,
  RestoreSessionOptions,
} from "../types/index";
import type { GuardhouseErrorCode } from "../types/errors";
import { GuardhouseAuthError, GuardhouseNetworkError } from "../types/errors";
import type {
  BrowserSessionOptions,
  GuardhouseBrowserAdapter,
} from "../adapters/BrowserAdapter";
import type { GuardhouseStorageAdapter } from "../adapters/StorageAdapter";
import type { GuardhouseLogger } from "../utils/logger";
import { createPkceArtifacts, type PkceArtifacts } from "../utils/pkce";
import {
  createRedirectMatcher,
  parseAuthorizationCallback,
  parsePositiveInteger,
  trimToUndefined,
  toErrorMessage,
} from "../utils/url";

const CLIENT_STORAGE_KEYS = {
  TOKEN_TYPE: "gh_token_type",
  SCOPE: "gh_scope",
} as const;

const STORAGE_KEYS = {
  ACCESS_TOKEN: "gh_access_token",
  REFRESH_TOKEN: "gh_refresh_token",
  ID_TOKEN: "gh_id_token",
  EXPIRES_AT: "gh_expires_at",
  USER: "gh_user",
} as const;

interface PendingBrowserFlow {
  codeVerifier: string;
  state: string;
  appState?: Record<string, unknown>;
}

interface SessionCacheData {
  accessToken: string;
  idToken?: string;
  tokenType: string;
  scope?: string;
  expiresAt: number;
  user: CoreUser | null;
}

interface AuthManagerConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  defaultScope: string;
  defaultAudience?: string;
  defaultEphemeralSession: boolean;
  userInfoOnLogin: boolean;
  authorizationEndpoint: string;
  registrationEndpoint: string;
  tokenEndpoint: string;
  coreClient: CoreGuardhouseClient;
  browser?: GuardhouseBrowserAdapter;
  cryptoAdapter: CryptoAdapter;
  refreshTokenStorage: GuardhouseStorageAdapter;
  sessionStorage?: GuardhouseStorageAdapter;
  logger: GuardhouseLogger;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseStoredUser(serialized: string | null): CoreUser | null {
  if (!serialized) {
    return null;
  }

  try {
    const parsed = JSON.parse(serialized) as unknown;

    if (!isRecord(parsed)) {
      return null;
    }

    const subject = trimToUndefined(
      typeof parsed.sub === "string" ? parsed.sub : undefined,
    );

    if (!subject) {
      return null;
    }

    return {
      ...(parsed as CoreUser),
      sub: subject,
    };
  } catch {
    return null;
  }
}

function extractTokenContainer(payload: unknown): Record<string, unknown> {
  if (!isRecord(payload)) {
    throw new GuardhouseAuthError(
      "Token response payload is not a JSON object",
      "TOKEN_RESPONSE_ERROR",
      undefined,
      payload,
    );
  }

  if (typeof payload.access_token === "string") {
    return payload;
  }

  const nestedCandidates = [
    payload.token,
    payload.tokens,
    payload.tokenResponse,
    payload.data,
  ];

  for (const candidate of nestedCandidates) {
    if (isRecord(candidate) && typeof candidate.access_token === "string") {
      return candidate;
    }
  }

  throw new GuardhouseAuthError(
    "Token response payload did not include access_token",
    "TOKEN_RESPONSE_ERROR",
    undefined,
    payload,
  );
}

/**
 * Parses unknown token payloads into normalized token response shape.
 */
export function parseTokenResponsePayload(
  payload: unknown,
): GuardhouseTokenResponse {
  const container = extractTokenContainer(payload);

  const accessToken = trimToUndefined(
    typeof container.access_token === "string"
      ? container.access_token
      : undefined,
  );

  if (!accessToken) {
    throw new GuardhouseAuthError(
      "Token response did not include access_token",
      "TOKEN_RESPONSE_ERROR",
      undefined,
      payload,
    );
  }

  const expiresIn = parsePositiveInteger(container.expires_in);

  if (!expiresIn) {
    throw new GuardhouseAuthError(
      "Token response did not include a valid expires_in value",
      "TOKEN_RESPONSE_ERROR",
      undefined,
      payload,
    );
  }

  return {
    access_token: accessToken,
    token_type:
      trimToUndefined(
        typeof container.token_type === "string"
          ? container.token_type
          : undefined,
      ) ?? "Bearer",
    expires_in: expiresIn,
    refresh_token: trimToUndefined(
      typeof container.refresh_token === "string"
        ? container.refresh_token
        : undefined,
    ),
    id_token: trimToUndefined(
      typeof container.id_token === "string" ? container.id_token : undefined,
    ),
    scope: trimToUndefined(
      typeof container.scope === "string" ? container.scope : undefined,
    ),
  };
}

/**
 * React Native auth manager that composes `@guardhouse/core` OAuth primitives
 * with injected browser and storage adapters.
 */
export class AuthManager {
  private readonly authority: string;
  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly defaultScope: string;
  private readonly defaultAudience?: string;
  private readonly defaultEphemeralSession: boolean;
  private readonly userInfoOnLogin: boolean;
  private readonly authorizationEndpoint: string;
  private readonly registrationEndpoint: string;
  private readonly tokenEndpoint: string;
  private readonly coreClient: CoreGuardhouseClient;
  private readonly browser?: GuardhouseBrowserAdapter;
  private readonly cryptoAdapter: CryptoAdapter;
  private readonly refreshTokenStorage: GuardhouseStorageAdapter;
  private readonly sessionStorage?: GuardhouseStorageAdapter;
  private readonly logger: GuardhouseLogger;
  private readonly redirectUriDescriptor;

  private pendingBrowserFlow: PendingBrowserFlow | null = null;
  private sessionCache: SessionCacheData | null = null;
  private refreshTokenCache: string | null = null;
  private refreshPromise: Promise<GuardhouseAuthResult> | null = null;

  constructor(config: AuthManagerConfig) {
    this.authority = config.authority;
    this.clientId = config.clientId;
    this.redirectUri = config.redirectUri;
    this.defaultScope = config.defaultScope;
    this.defaultAudience = config.defaultAudience;
    this.defaultEphemeralSession = config.defaultEphemeralSession;
    this.userInfoOnLogin = config.userInfoOnLogin;
    this.authorizationEndpoint = config.authorizationEndpoint;
    this.registrationEndpoint = config.registrationEndpoint;
    this.tokenEndpoint = config.tokenEndpoint;
    this.coreClient = config.coreClient;
    this.browser = config.browser;
    this.cryptoAdapter = config.cryptoAdapter;
    this.refreshTokenStorage = config.refreshTokenStorage;
    this.sessionStorage = config.sessionStorage;
    this.logger = config.logger;
    this.redirectUriDescriptor = createRedirectMatcher(this.redirectUri);
  }

  /**
   * Starts OAuth browser login and finalizes callback via `@guardhouse/core` token exchange.
   */
  async loginWithBrowser(
    options: BrowserLoginOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.runBrowserAuthFlow(this.authorizationEndpoint, options);
  }

  /**
   * Starts browser registration flow and finalizes callback via `@guardhouse/core` token exchange.
   */
  async registerWithBrowser(
    options: BrowserLoginOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.runBrowserAuthFlow(this.registrationEndpoint, options, true);
  }

  /**
   * Exchanges an authorization code for tokens.
   * Uses `@guardhouse/core` exchange API when PKCE verifier is available.
   */
  async exchangeCodeForTokens(
    code: string,
    options: ExchangeCodeForTokensOptions = {},
  ): Promise<GuardhouseAuthResult> {
    const normalizedCode = this.requireString(code, "code");
    const codeVerifier =
      trimToUndefined(options.codeVerifier) ??
      this.pendingBrowserFlow?.codeVerifier;
    const scope = trimToUndefined(options.scope);
    const audience = this.resolveAudience(options.audience);

    const tokenResponse = await this.exchangeAuthorizationCode(
      normalizedCode,
      codeVerifier,
      scope,
      audience,
    );
    const currentSession = await this.getSession();

    return this.persistAuthResult(tokenResponse, currentSession ?? undefined);
  }

  /**
   * Applies tokens delivered via deep link callback directly.
   */
  async applyRedirectTokens(
    payload: RedirectTokenPayload,
  ): Promise<GuardhouseAuthResult> {
    const accessToken = this.requireString(payload.accessToken, "accessToken");
    const expiresIn = parsePositiveInteger(payload.expiresIn) ?? 3600;

    const tokenResponse: GuardhouseTokenResponse = {
      access_token: accessToken,
      token_type: trimToUndefined(payload.tokenType) ?? "Bearer",
      expires_in: expiresIn,
      refresh_token: trimToUndefined(payload.refreshToken),
      id_token: trimToUndefined(payload.idToken),
      scope: trimToUndefined(payload.scope),
    };

    return this.persistTokenResponse(tokenResponse);
  }

  /**
   * Persists a token response and returns normalized auth result.
   */
  async persistTokenResponse(
    tokenResponse: GuardhouseTokenResponse,
    appState?: Record<string, unknown>,
  ): Promise<GuardhouseAuthResult> {
    const existingSession = await this.getSession();
    return this.persistAuthResult(
      tokenResponse,
      existingSession ?? undefined,
      appState,
    );
  }

  /**
   * Performs refresh token grant via `@guardhouse/core`.
   */
  async refreshToken(
    options: RefreshTokenOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.withRefreshLock(async () => {
      const currentSession = await this.getSession();
      const refreshToken = await this.getStoredRefreshToken();

      if (!refreshToken) {
        throw new GuardhouseAuthError(
          "No refresh token available. User interaction is required.",
          "MISSING_REFRESH_TOKEN",
        );
      }

      const params: Record<string, string> = {};
      const scope = trimToUndefined(options.scope);
      const audience = this.resolveAudience(options.audience);

      if (scope) {
        params.scope = scope;
      }

      if (audience) {
        params.audience = audience;
      }

      try {
        const coreTokenResponse = await this.coreClient.refreshToken(
          refreshToken,
          params,
        );

        return this.persistAuthResult(
          this.normalizeCoreTokenResponse(coreTokenResponse),
          currentSession ?? undefined,
        );
      } catch (error) {
        const wrapped = this.wrapCoreError(
          error,
          "TOKEN_REQUEST_FAILED",
          "Refresh token request failed",
        );

        if (this.shouldClearSessionAfterRefreshFailure(wrapped)) {
          await this.clearSession();
        }

        throw wrapped;
      }
    });
  }

  /**
   * Restores session from storage and refreshes when needed.
   */
  async restoreSession(
    options: RestoreSessionOptions = {},
  ): Promise<GuardhouseAuthResult | null> {
    const minValiditySeconds =
      options.minValiditySeconds !== undefined
        ? Math.max(0, options.minValiditySeconds)
        : 60;

    const currentSession = await this.getSession();

    if (
      currentSession &&
      !this.isExpired(currentSession.expiresAt, minValiditySeconds)
    ) {
      return this.buildAuthResultFromSession(currentSession);
    }

    const refreshToken = await this.getStoredRefreshToken();
    if (!refreshToken) {
      return null;
    }

    try {
      return await this.refreshToken(options);
    } catch (error) {
      if (this.shouldClearSessionAfterRefreshFailure(error)) {
        await this.clearSession();
        return null;
      }

      throw error;
    }
  }

  /**
   * Returns normalized in-memory/session storage state.
   */
  async getSession(): Promise<GuardhouseSession | null> {
    const cache = await this.loadSessionCache();

    if (!cache) {
      return null;
    }

    const refreshToken = await this.getStoredRefreshToken();

    return {
      accessToken: cache.accessToken,
      refreshToken: refreshToken ?? undefined,
      idToken: cache.idToken,
      tokenType: cache.tokenType,
      scope: cache.scope,
      expiresAt: cache.expiresAt,
      user: cache.user,
    };
  }

  /**
   * Returns a valid access token, refreshing if requested.
   */
  async getAccessToken(
    options: GetAccessTokenOptions = {},
  ): Promise<string | null> {
    const currentSession = await this.getSession();
    const minValiditySeconds =
      options.minValiditySeconds !== undefined
        ? Math.max(0, options.minValiditySeconds)
        : 60;

    if (
      currentSession &&
      !this.isExpired(currentSession.expiresAt, minValiditySeconds)
    ) {
      return currentSession.accessToken;
    }

    if (options.autoRefresh === false) {
      return null;
    }

    const refreshToken = await this.getStoredRefreshToken();
    if (!refreshToken) {
      return null;
    }

    const refreshed = await this.refreshToken();
    return refreshed.session.accessToken;
  }

  /**
   * Logs out locally and optionally revokes tokens via `@guardhouse/core`.
   */
  async logout(options: GuardhouseLogoutOptions = {}): Promise<void> {
    const currentSession = await this.getSession();
    const refreshToken = await this.getStoredRefreshToken();
    const shouldRevoke = options.revoke ?? false;

    let revokeError: GuardhouseAuthError | null = null;

    if (shouldRevoke && currentSession) {
      const revokeAccessToken = options.revokeAccessToken ?? true;
      const revokeRefreshToken = options.revokeRefreshToken ?? true;

      if (revokeAccessToken && currentSession.accessToken) {
        try {
          await this.coreClient.revokeToken(
            currentSession.accessToken,
            "access_token",
          );
        } catch (error) {
          revokeError = this.wrapCoreError(
            error,
            "REVOCATION_FAILED",
            "Access token revocation failed",
          );
        }
      }

      if (revokeRefreshToken && refreshToken) {
        try {
          await this.coreClient.revokeToken(refreshToken, "refresh_token");
        } catch (error) {
          if (!revokeError) {
            revokeError = this.wrapCoreError(
              error,
              "REVOCATION_FAILED",
              "Refresh token revocation failed",
            );
          }
        }
      }
    }

    await this.clearSession();

    if (revokeError && options.throwOnRevokeFailure) {
      throw revokeError;
    }
  }

  private async runBrowserAuthFlow(
    endpoint: string,
    options: BrowserLoginOptions,
    registrationFlow = false,
  ): Promise<GuardhouseAuthResult> {
    const browser = this.requireBrowserAdapter();
    const scope = trimToUndefined(options.scope) ?? this.defaultScope;
    const audience = this.resolveAudience(options.audience);
    const artifacts = await createPkceArtifacts(this.cryptoAdapter, false);

    this.pendingBrowserFlow = {
      codeVerifier: artifacts.codeVerifier,
      state: artifacts.state,
      appState: options.appState,
    };

    const browserOptions: BrowserSessionOptions = {
      ephemeralSession:
        options.ephemeralSession ?? this.defaultEphemeralSession,
      timeoutMs: options.timeoutMs,
    };

    const authorizationUrl = registrationFlow
      ? this.buildRegistrationAuthorizationUrl(
          artifacts,
          scope,
          audience,
          options,
        )
      : this.buildAuthorizationUrl(
          endpoint,
          artifacts,
          scope,
          audience,
          options,
        );

    try {
      const browserResult = await browser.openAuthSession(
        authorizationUrl,
        this.redirectUri,
        browserOptions,
      );

      const callback = parseAuthorizationCallback(
        browserResult.url,
        this.redirectUriDescriptor,
      );

      if (callback.state !== this.pendingBrowserFlow?.state) {
        throw new GuardhouseAuthError(
          "OAuth state mismatch detected",
          "STATE_MISMATCH",
        );
      }

      const tokenResult = await this.exchangeCodeForTokens(callback.code, {
        codeVerifier: this.pendingBrowserFlow.codeVerifier,
      });

      return {
        ...tokenResult,
        appState: this.pendingBrowserFlow.appState,
      };
    } finally {
      this.pendingBrowserFlow = null;
    }
  }

  private buildRegistrationAuthorizationUrl(
    artifacts: PkceArtifacts,
    scope: string,
    audience: string | undefined,
    options: BrowserLoginOptions,
  ): string {
    const registrationUrl = new URL(this.registrationEndpoint, this.authority);
    const returnUrlParamName = this.findReturnUrlParamName(registrationUrl);

    if (!returnUrlParamName) {
      return this.buildAuthorizationUrl(
        this.registrationEndpoint,
        artifacts,
        scope,
        audience,
        options,
      );
    }

    const authorizeUrl = this.buildAuthorizationUrl(
      this.authorizationEndpoint,
      artifacts,
      scope,
      audience,
      options,
    );

    registrationUrl.searchParams.set(returnUrlParamName, authorizeUrl);
    return registrationUrl.toString();
  }

  private buildAuthorizationUrl(
    endpoint: string,
    artifacts: PkceArtifacts,
    scope: string,
    audience: string | undefined,
    options: BrowserLoginOptions,
  ): string {
    return generateAuthUrl({
      authority: this.authority,
      authorizationEndpoint: endpoint,
      clientId: this.clientId,
      redirectUri: this.redirectUri,
      responseType: "code",
      scope,
      state: artifacts.state,
      nonce: artifacts.nonce,
      prompt: trimToUndefined(options.prompt),
      audience,
      allowAuthorizationWithoutAudience: true,
      allowOfflineAccessScope: true,
      codeChallenge: artifacts.codeChallenge,
      codeChallengeMethod: "S256",
      extraParams: options.extraParams,
    });
  }

  private findReturnUrlParamName(url: URL): string | null {
    for (const key of url.searchParams.keys()) {
      if (key.trim().toLowerCase() === "returnurl") {
        return key;
      }
    }

    return null;
  }

  private async exchangeAuthorizationCode(
    code: string,
    codeVerifier: string | undefined,
    scope?: string,
    audience?: string,
  ): Promise<GuardhouseTokenResponse> {
    const extraParams: Record<string, string> = {};

    if (scope) {
      extraParams.scope = scope;
    }

    if (audience) {
      extraParams.audience = audience;
    }

    if (codeVerifier) {
      try {
        const response = await this.coreClient.exchangeCodeForTokens(
          code,
          codeVerifier,
          this.redirectUri,
          extraParams,
        );

        return this.normalizeCoreTokenResponse(response);
      } catch (error) {
        throw this.wrapCoreError(
          error,
          "TOKEN_REQUEST_FAILED",
          "Authorization code exchange failed",
        );
      }
    }

    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
    });

    if (scope) {
      body.set("scope", scope);
    }

    if (audience) {
      body.set("audience", audience);
    }

    try {
      const response = await this.coreClient.postForm<CoreTokenResponse>(
        this.tokenEndpoint,
        body,
      );

      return this.normalizeCoreTokenResponse(response);
    } catch (error) {
      throw this.wrapCoreError(
        error,
        "TOKEN_REQUEST_FAILED",
        "Authorization code exchange failed",
      );
    }
  }

  private async persistAuthResult(
    tokenResponse: GuardhouseTokenResponse,
    existingSession?: GuardhouseSession,
    appState?: Record<string, unknown>,
  ): Promise<GuardhouseAuthResult> {
    const persistedRefreshToken = await this.getStoredRefreshToken();
    const expiresAt = Math.floor(Date.now() / 1000) + tokenResponse.expires_in;

    const session: GuardhouseSession = {
      accessToken: tokenResponse.access_token,
      refreshToken:
        tokenResponse.refresh_token ??
        existingSession?.refreshToken ??
        persistedRefreshToken ??
        undefined,
      idToken: tokenResponse.id_token ?? existingSession?.idToken,
      tokenType:
        trimToUndefined(tokenResponse.token_type) ??
        existingSession?.tokenType ??
        "Bearer",
      scope:
        trimToUndefined(tokenResponse.scope) ??
        existingSession?.scope ??
        this.defaultScope,
      expiresAt,
      user: existingSession?.user ?? null,
    };

    session.user = await this.fetchUserInfo(session.accessToken, session.user);
    await this.persistSession(session);

    return {
      session,
      tokenResponse: {
        ...tokenResponse,
        refresh_token: session.refreshToken,
        id_token: session.idToken,
        scope: session.scope,
        token_type: session.tokenType,
      },
      user: session.user,
      appState,
    };
  }

  private async fetchUserInfo(
    accessToken: string,
    fallbackUser: CoreUser | null,
  ): Promise<CoreUser | null> {
    if (!this.userInfoOnLogin) {
      return fallbackUser;
    }

    try {
      const user = await this.coreClient.getUserInfo(accessToken);

      if (!user || typeof user.sub !== "string" || user.sub.trim() === "") {
        return fallbackUser;
      }

      return {
        ...(user as CoreUser),
        sub: user.sub.trim(),
      };
    } catch (error) {
      this.logger.warn("Failed to fetch user profile", {
        error: toErrorMessage(error),
      });
      return fallbackUser;
    }
  }

  private normalizeCoreTokenResponse(
    tokenResponse: CoreTokenResponse,
  ): GuardhouseTokenResponse {
    return {
      access_token: tokenResponse.access_token,
      token_type: tokenResponse.token_type,
      expires_in: tokenResponse.expires_in,
      refresh_token: tokenResponse.refresh_token,
      id_token: tokenResponse.id_token,
      scope: tokenResponse.scope,
    };
  }

  private wrapCoreError(
    error: unknown,
    fallbackCode: GuardhouseErrorCode,
    fallbackMessage: string,
  ): GuardhouseAuthError {
    if (error instanceof GuardhouseAuthError) {
      return error;
    }

    if (error instanceof GuardhouseNetworkError) {
      return new GuardhouseAuthError(
        error.message,
        "NETWORK_ERROR",
        error.statusCode,
        error.details,
      );
    }

    if (error instanceof CoreGuardhouseError) {
      const mappedCode = this.mapCoreCode(error.code, fallbackCode);

      if (mappedCode === "NETWORK_ERROR") {
        return new GuardhouseAuthError(
          error.message,
          "NETWORK_ERROR",
          error.statusCode,
          error,
        );
      }

      return new GuardhouseAuthError(
        error.message,
        mappedCode,
        error.statusCode,
        {
          error: error.code,
          cause: error,
        },
      );
    }

    return new GuardhouseAuthError(
      `${fallbackMessage}: ${toErrorMessage(error)}`,
      fallbackCode,
      undefined,
      error,
    );
  }

  private mapCoreCode(
    coreCode: string | undefined,
    fallbackCode: GuardhouseErrorCode,
  ): GuardhouseErrorCode {
    if (!coreCode) {
      return fallbackCode;
    }

    if (coreCode === "NETWORK_ERROR" || coreCode === "REQUEST_TIMEOUT") {
      return "NETWORK_ERROR";
    }

    if (coreCode === "invalid_grant" || coreCode === "invalid_token") {
      return "TOKEN_REQUEST_FAILED";
    }

    return fallbackCode;
  }

  private async persistSession(session: GuardhouseSession): Promise<void> {
    await this.persistRefreshToken(session.refreshToken);

    await this.persistSessionCache({
      accessToken: session.accessToken,
      idToken: session.idToken,
      tokenType: session.tokenType,
      scope: session.scope,
      expiresAt: session.expiresAt,
      user: session.user,
    });
  }

  private async clearSession(): Promise<void> {
    this.pendingBrowserFlow = null;
    this.sessionCache = null;

    await Promise.all([
      this.persistRefreshToken(undefined),
      this.clearPersistedSessionCache(),
    ]);
  }

  private shouldClearSessionAfterRefreshFailure(error: unknown): boolean {
    if (!(error instanceof GuardhouseAuthError)) {
      return false;
    }

    if (error.code !== "TOKEN_REQUEST_FAILED") {
      return false;
    }

    if (error.statusCode !== 400 && error.statusCode !== 401) {
      return false;
    }

    if (!isRecord(error.details)) {
      return true;
    }

    const serverError = trimToUndefined(
      typeof error.details.error === "string" ? error.details.error : undefined,
    );

    return (
      serverError === undefined ||
      serverError === "invalid_grant" ||
      serverError === "invalid_token"
    );
  }

  private async getStoredRefreshToken(): Promise<string | null> {
    if (this.refreshTokenCache) {
      return this.refreshTokenCache;
    }

    const persisted = trimToUndefined(
      await this.refreshTokenStorage.getItem(STORAGE_KEYS.REFRESH_TOKEN),
    );
    this.refreshTokenCache = persisted ?? null;

    return this.refreshTokenCache;
  }

  private async persistRefreshToken(
    refreshToken: string | undefined,
  ): Promise<void> {
    const normalized = trimToUndefined(refreshToken);
    this.refreshTokenCache = normalized ?? null;

    if (!normalized) {
      await this.refreshTokenStorage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
      return;
    }

    await this.refreshTokenStorage.setItem(
      STORAGE_KEYS.REFRESH_TOKEN,
      normalized,
    );
  }

  private async loadSessionCache(): Promise<SessionCacheData | null> {
    if (this.sessionCache) {
      return this.sessionCache;
    }

    if (!this.sessionStorage) {
      return null;
    }

    const [
      accessToken,
      idTokenRaw,
      expiresAtRaw,
      tokenTypeRaw,
      scopeRaw,
      userRaw,
    ] = await Promise.all([
      this.sessionStorage.getItem(STORAGE_KEYS.ACCESS_TOKEN),
      this.sessionStorage.getItem(STORAGE_KEYS.ID_TOKEN),
      this.sessionStorage.getItem(STORAGE_KEYS.EXPIRES_AT),
      this.sessionStorage.getItem(CLIENT_STORAGE_KEYS.TOKEN_TYPE),
      this.sessionStorage.getItem(CLIENT_STORAGE_KEYS.SCOPE),
      this.sessionStorage.getItem(STORAGE_KEYS.USER),
    ]);

    if (!accessToken) {
      return null;
    }

    const expiresAt = parsePositiveInteger(expiresAtRaw);

    if (!expiresAt) {
      await this.clearPersistedSessionCache();
      return null;
    }

    this.sessionCache = {
      accessToken,
      idToken: trimToUndefined(idTokenRaw),
      tokenType: trimToUndefined(tokenTypeRaw) ?? "Bearer",
      scope: trimToUndefined(scopeRaw),
      expiresAt,
      user: parseStoredUser(userRaw),
    };

    return this.sessionCache;
  }

  private async persistSessionCache(cache: SessionCacheData): Promise<void> {
    this.sessionCache = cache;

    if (!this.sessionStorage) {
      return;
    }

    await Promise.all([
      this.sessionStorage.setItem(STORAGE_KEYS.ACCESS_TOKEN, cache.accessToken),
      this.sessionStorage.setItem(
        STORAGE_KEYS.EXPIRES_AT,
        String(cache.expiresAt),
      ),
      this.sessionStorage.setItem(
        CLIENT_STORAGE_KEYS.TOKEN_TYPE,
        cache.tokenType,
      ),
      cache.scope
        ? this.sessionStorage.setItem(CLIENT_STORAGE_KEYS.SCOPE, cache.scope)
        : this.sessionStorage.removeItem(CLIENT_STORAGE_KEYS.SCOPE),
      cache.idToken
        ? this.sessionStorage.setItem(STORAGE_KEYS.ID_TOKEN, cache.idToken)
        : this.sessionStorage.removeItem(STORAGE_KEYS.ID_TOKEN),
      cache.user
        ? this.sessionStorage.setItem(
            STORAGE_KEYS.USER,
            JSON.stringify(cache.user),
          )
        : this.sessionStorage.removeItem(STORAGE_KEYS.USER),
    ]);
  }

  private async clearPersistedSessionCache(): Promise<void> {
    this.sessionCache = null;

    if (!this.sessionStorage) {
      return;
    }

    await Promise.all([
      this.sessionStorage.removeItem(STORAGE_KEYS.ACCESS_TOKEN),
      this.sessionStorage.removeItem(STORAGE_KEYS.ID_TOKEN),
      this.sessionStorage.removeItem(STORAGE_KEYS.EXPIRES_AT),
      this.sessionStorage.removeItem(CLIENT_STORAGE_KEYS.TOKEN_TYPE),
      this.sessionStorage.removeItem(CLIENT_STORAGE_KEYS.SCOPE),
      this.sessionStorage.removeItem(STORAGE_KEYS.USER),
    ]);
  }

  private buildAuthResultFromSession(
    session: GuardhouseSession,
  ): GuardhouseAuthResult {
    return {
      session,
      tokenResponse: {
        access_token: session.accessToken,
        token_type: session.tokenType,
        expires_in: Math.max(
          0,
          session.expiresAt - Math.floor(Date.now() / 1000),
        ),
        refresh_token: session.refreshToken,
        id_token: session.idToken,
        scope: session.scope,
      },
      user: session.user,
    };
  }

  private resolveAudience(audience: string | undefined): string | undefined {
    return trimToUndefined(audience) ?? this.defaultAudience;
  }

  private isExpired(expiresAt: number, minValiditySeconds: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return expiresAt <= now + minValiditySeconds;
  }

  private requireBrowserAdapter(): GuardhouseBrowserAdapter {
    if (this.browser) {
      return this.browser;
    }

    throw new GuardhouseAuthError(
      "No browser adapter configured",
      "BROWSER_ADAPTER_MISSING",
    );
  }

  private requireString(value: string, fieldName: string): string {
    const normalized = trimToUndefined(value);

    if (normalized) {
      return normalized;
    }

    throw new GuardhouseAuthError(`${fieldName} is required`, "CONFIG_ERROR");
  }

  private withRefreshLock(
    action: () => Promise<GuardhouseAuthResult>,
  ): Promise<GuardhouseAuthResult> {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = action().finally(() => {
      this.refreshPromise = null;
    });

    return this.refreshPromise;
  }
}
