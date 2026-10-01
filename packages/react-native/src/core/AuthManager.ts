import {
  GuardhouseError as CoreGuardhouseError,
  canonicalizeIssuer,
  isTransientAuthError,
} from "@guardhouse/core";
import type {
  AuthorizationCodeExchangeResult,
  AuthorizationTransaction,
  GuardhouseClient as CoreGuardhouseClient,
  OidcIdentityEvidence,
  OidcIdentityMetadata,
  TokenResponse as CoreTokenResponse,
  User as CoreUser,
  VerifiedIdToken,
  VerifiedIdTokenPayload,
} from "@guardhouse/core";
import type {
  BrowserLoginOptions,
  GetAccessTokenOptions,
  GuardhouseAuthResult,
  GuardhouseLogoutOptions,
  GuardhouseSession,
  GuardhouseTokenResponse,
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
import { trimToUndefined } from "../utils/url";

interface StoredSessionBase {
  readonly version: 3;
  readonly issuer: string;
  readonly clientId: string;
  readonly accessToken: string;
  readonly tokenType: string;
  readonly scope?: string;
  readonly expiresAt: number;
}

interface StoredOAuthSession extends StoredSessionBase {
  readonly kind: "oauth";
}

interface StoredOidcSession extends StoredSessionBase {
  readonly kind: "oidc";
  /** Signed identity evidence retained for refresh continuity. */
  readonly idToken: string;
  readonly identity: OidcIdentityMetadata;
  /** False when the token is retained only as historical refresh evidence. */
  readonly idTokenCurrent: boolean;
}

type StoredSession = StoredOAuthSession | StoredOidcSession;

interface SessionCacheData {
  readonly record: StoredSession;
  readonly user: CoreUser | null;
}

interface PersistedIdentity {
  readonly evidence: OidcIdentityEvidence;
  readonly metadata: OidcIdentityMetadata;
  readonly rawIdToken: string;
  readonly verifiedIdToken?: VerifiedIdToken;
  readonly idTokenCurrent: boolean;
}

interface PersistTokenOptions {
  readonly existingSession?: StoredSession;
  readonly requestedScope?: string;
  readonly identity?: PersistedIdentity;
  readonly appState?: Record<string, unknown>;
}

interface AuthManagerConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  defaultScope: string;
  defaultAudience?: string;
  defaultEphemeralSession: boolean;
  userInfoOnLogin: boolean;
  registrationEndpoint: string;
  requiredAcrValues?: readonly string[];
  requiredAmrValues?: readonly string[];
  coreClient: CoreGuardhouseClient;
  browser?: GuardhouseBrowserAdapter;
  refreshTokenStorage: GuardhouseStorageAdapter;
  sessionStorage?: GuardhouseStorageAdapter;
  logger: GuardhouseLogger;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeStringArray(value: unknown): readonly string[] | null {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== "string")
  ) {
    return null;
  }

  return Object.freeze([...value]);
}

function identityEquals(
  left: OidcIdentityMetadata,
  right: OidcIdentityMetadata,
): boolean {
  return (
    left.issuer === right.issuer &&
    left.clientId === right.clientId &&
    left.subject === right.subject &&
    left.authorizedParty === right.authorizedParty &&
    left.issuedAt === right.issuedAt &&
    left.expiresAt === right.expiresAt &&
    left.nonce === right.nonce &&
    left.authTime === right.authTime &&
    left.acr === right.acr &&
    left.sessionId === right.sessionId &&
    left.audiences.length === right.audiences.length &&
    left.audiences.every((value, index) => value === right.audiences[index]) &&
    left.amr.length === right.amr.length &&
    left.amr.every((value, index) => value === right.amr[index])
  );
}

function toIdentityMetadata(
  identity: OidcIdentityMetadata,
): OidcIdentityMetadata {
  return Object.freeze({
    issuer: identity.issuer,
    clientId: identity.clientId,
    subject: identity.subject,
    audiences: Object.freeze([...identity.audiences]),
    authorizedParty: identity.authorizedParty,
    issuedAt: identity.issuedAt,
    expiresAt: identity.expiresAt,
    nonce: identity.nonce,
    authTime: identity.authTime,
    acr: identity.acr,
    amr: Object.freeze([...identity.amr]),
    sessionId: identity.sessionId,
  });
}

function deepFreezeJson(value: unknown): void {
  if (!value || typeof value !== "object" || Object.isFrozen(value)) {
    return;
  }

  for (const nested of Object.values(value)) {
    deepFreezeJson(nested);
  }
  Object.freeze(value);
}

function freezeUser(user: CoreUser): CoreUser {
  let cloned: unknown;
  try {
    cloned = JSON.parse(JSON.stringify(user)) as unknown;
  } catch {
    throw new GuardhouseAuthError(
      "Authenticated user claims are not valid JSON data",
      "TOKEN_RESPONSE_ERROR",
    );
  }

  if (
    !isRecord(cloned) ||
    typeof cloned.sub !== "string" ||
    cloned.sub.trim() === ""
  ) {
    throw new GuardhouseAuthError(
      "Authenticated user claims are missing subject",
      "TOKEN_RESPONSE_ERROR",
    );
  }

  deepFreezeJson(cloned);
  return cloned as CoreUser;
}

function parseStoredIdentity(value: unknown): OidcIdentityMetadata | null {
  if (!isRecord(value)) {
    return null;
  }

  const audiences = normalizeStringArray(value.audiences);
  const amr = normalizeStringArray(value.amr);
  const requiredStrings = [value.issuer, value.clientId, value.subject];
  const nullableStrings = [
    value.authorizedParty,
    value.nonce,
    value.acr,
    value.sessionId,
  ];
  const requiredNumbers = [value.issuedAt, value.expiresAt];

  if (
    !audiences ||
    audiences.length === 0 ||
    !amr ||
    requiredStrings.some(
      (entry) => typeof entry !== "string" || entry.trim() === "",
    ) ||
    nullableStrings.some(
      (entry) => entry !== null && typeof entry !== "string",
    ) ||
    requiredNumbers.some(
      (entry) => typeof entry !== "number" || !Number.isFinite(entry),
    ) ||
    (value.authTime !== null &&
      (typeof value.authTime !== "number" || !Number.isFinite(value.authTime)))
  ) {
    return null;
  }

  return Object.freeze({
    issuer: value.issuer as string,
    clientId: value.clientId as string,
    subject: value.subject as string,
    audiences,
    authorizedParty: value.authorizedParty as string | null,
    issuedAt: value.issuedAt as number,
    expiresAt: value.expiresAt as number,
    nonce: value.nonce as string | null,
    authTime: value.authTime as number | null,
    acr: value.acr as string | null,
    amr,
    sessionId: value.sessionId as string | null,
  });
}

function extractTokenContainer(payload: unknown): Record<string, unknown> {
  if (!isRecord(payload)) {
    throw new GuardhouseAuthError(
      "Token response payload is not a JSON object",
      "TOKEN_RESPONSE_ERROR",
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
  );
}

/** Runtime-decodes the Guardhouse passkey token response from unknown input. */
export function parseTokenResponsePayload(
  payload: unknown,
): GuardhouseTokenResponse {
  const container = extractTokenContainer(payload);
  const accessToken = trimToUndefined(
    typeof container.access_token === "string"
      ? container.access_token
      : undefined,
  );
  const tokenType = trimToUndefined(
    typeof container.token_type === "string" ? container.token_type : undefined,
  );
  const expiresIn =
    typeof container.expires_in === "number" &&
    Number.isInteger(container.expires_in) &&
    container.expires_in > 0 &&
    container.expires_in <= 2_147_483_647
      ? container.expires_in
      : undefined;

  if (!accessToken || !tokenType || !expiresIn) {
    throw new GuardhouseAuthError(
      "Token response is missing a valid access_token, token_type, or expires_in",
      "TOKEN_RESPONSE_ERROR",
    );
  }

  return {
    access_token: accessToken,
    token_type: tokenType,
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
 * React Native auth manager built around Core v2 authorization transactions and
 * cryptographically verified OIDC identities.
 */
export class AuthManager {
  private readonly issuer: string;
  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly defaultScope: string;
  private readonly defaultAudience?: string;
  private readonly defaultEphemeralSession: boolean;
  private readonly userInfoOnLogin: boolean;
  private readonly registrationEndpoint: string;
  private readonly requiredAcrValues: readonly string[];
  private readonly requiredAmrValues: readonly string[];
  private readonly coreClient: CoreGuardhouseClient;
  private readonly browser?: GuardhouseBrowserAdapter;
  private readonly refreshTokenStorage: GuardhouseStorageAdapter;
  private readonly sessionStorage?: GuardhouseStorageAdapter;
  private readonly logger: GuardhouseLogger;
  private readonly sessionStorageKey: string;
  private readonly refreshTokenStorageKey: string;

  private pendingBrowserFlow: AuthorizationTransaction | null = null;
  private browserAuthPromise: Promise<GuardhouseAuthResult> | null = null;
  private sessionCache: SessionCacheData | null = null;
  private refreshTokenCache: string | null = null;
  private refreshPromise: Promise<GuardhouseAuthResult> | null = null;

  constructor(config: AuthManagerConfig) {
    this.issuer = canonicalizeIssuer(config.authority);
    this.clientId = config.clientId.trim();
    this.redirectUri = config.redirectUri;
    this.defaultScope = config.defaultScope;
    this.defaultAudience = config.defaultAudience;
    this.defaultEphemeralSession = config.defaultEphemeralSession;
    this.userInfoOnLogin = config.userInfoOnLogin;
    this.registrationEndpoint = config.registrationEndpoint;
    this.requiredAcrValues = Object.freeze([
      ...(config.requiredAcrValues ?? []),
    ]);
    this.requiredAmrValues = Object.freeze([
      ...(config.requiredAmrValues ?? []),
    ]);
    this.coreClient = config.coreClient;
    this.browser = config.browser;
    this.refreshTokenStorage = config.refreshTokenStorage;
    this.sessionStorage = config.sessionStorage;
    this.logger = config.logger;

    const storageNamespace = `${encodeURIComponent(this.issuer)}:${encodeURIComponent(
      this.clientId,
    )}`;
    this.sessionStorageKey = `gh:v3:${storageNamespace}:session`;
    this.refreshTokenStorageKey = `gh:v3:${storageNamespace}:refresh-token`;
  }

  async loginWithBrowser(
    options: BrowserLoginOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.startBrowserAuthFlow(options, false);
  }

  async registerWithBrowser(
    options: BrowserLoginOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.startBrowserAuthFlow(options, true);
  }

  /**
   * Persists tokens returned by the Guardhouse passkey verification endpoint.
   * OIDC responses are verified before any identity is trusted.
   */
  async persistTokenResponse(
    tokenResponse: GuardhouseTokenResponse,
    requestedScope = this.defaultScope,
  ): Promise<GuardhouseAuthResult> {
    const existingSession = await this.loadStoredSession();
    const responseScope = tokenResponse.scope ?? requestedScope;
    this.assertScopeNotEscalated(requestedScope, responseScope);
    const expectsOidc = this.scopeSet(requestedScope).has("openid");

    if (tokenResponse.id_token) {
      if (!expectsOidc) {
        throw new GuardhouseAuthError(
          "An OAuth-only passkey response must not include an ID token",
          "TOKEN_RESPONSE_ERROR",
        );
      }
      const verifiedIdToken = await this.coreClient.verifyIdToken(
        tokenResponse.id_token,
        {
          purpose: "session",
          requiredAcrValues: this.requiredAcrValues,
          requiredAmrValues: this.requiredAmrValues,
        },
      );

      return this.persistAuthResult(tokenResponse, {
        existingSession: existingSession ?? undefined,
        requestedScope,
        identity: {
          evidence: verifiedIdToken.identity,
          metadata: toIdentityMetadata(verifiedIdToken.identity),
          rawIdToken: tokenResponse.id_token,
          verifiedIdToken,
          idTokenCurrent: true,
        },
      });
    }

    if (expectsOidc) {
      throw new GuardhouseAuthError(
        "An OpenID passkey response must include a signed ID token",
        "TOKEN_RESPONSE_ERROR",
      );
    }

    return this.persistAuthResult(tokenResponse, {
      existingSession: existingSession ?? undefined,
      requestedScope,
    });
  }

  async refreshToken(
    options: RefreshTokenOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.withRefreshLock(async () => {
      const currentSession = await this.loadStoredSession();
      const refreshToken = await this.getStoredRefreshToken();

      if (!currentSession || !refreshToken) {
        await this.clearSession();
        throw new GuardhouseAuthError(
          "No complete refreshable session is available; user interaction is required",
          "MISSING_REFRESH_TOKEN",
        );
      }

      const grantedScope = currentSession.scope ?? this.defaultScope;
      const requestedScope = trimToUndefined(options.scope) ?? grantedScope;
      this.assertScopeNotEscalated(grantedScope, requestedScope);
      const audience = this.resolveAudience(options.audience);
      const requestParameters = audience ? { audience } : undefined;
      let tokenRefreshCompleted = false;

      try {
        if (currentSession.kind === "oidc") {
          const refreshed = await this.coreClient.refreshOidcSession(
            refreshToken,
            {
              previousIdToken: currentSession.idToken,
              grantedScope: requestedScope,
              requestParameters,
              requiredAcrValues: this.requiredAcrValues,
              requiredAmrValues: this.requiredAmrValues,
            },
          );
          tokenRefreshCompleted = true;
          if (refreshed.identityStatus === "current") {
            const replacementRawIdToken = refreshed.tokens.id_token;
            if (!replacementRawIdToken) {
              throw new GuardhouseAuthError(
                "A current refreshed identity must include its signed ID token",
                "TOKEN_RESPONSE_ERROR",
              );
            }

            return await this.persistAuthResult(refreshed.tokens, {
              existingSession: currentSession,
              requestedScope,
              identity: {
                evidence: refreshed.identity,
                metadata: toIdentityMetadata(refreshed.identity),
                rawIdToken: replacementRawIdToken,
                verifiedIdToken: refreshed.idToken,
                idTokenCurrent: true,
              },
            });
          }

          return await this.persistAuthResult(refreshed.tokens, {
            existingSession: currentSession,
            requestedScope,
            identity: {
              evidence: refreshed.identity,
              metadata: toIdentityMetadata(refreshed.identity),
              rawIdToken: currentSession.idToken,
              idTokenCurrent: false,
            },
          });
        }

        const tokens = await this.coreClient.refreshOAuthToken(refreshToken, {
          grantedScope: requestedScope,
          requestParameters,
        });
        tokenRefreshCompleted = true;

        return await this.persistAuthResult(tokens, {
          existingSession: currentSession,
          requestedScope,
        });
      } catch (error) {
        const wrapped = this.wrapCoreError(
          error,
          "TOKEN_REQUEST_FAILED",
          "Refresh token request failed",
        );

        if (
          tokenRefreshCompleted ||
          this.shouldClearSessionAfterRefreshFailure(error)
        ) {
          await this.clearSession();
        }

        throw wrapped;
      }
    });
  }

  async restoreSession(
    options: RestoreSessionOptions = {},
  ): Promise<GuardhouseAuthResult | null> {
    const minValiditySeconds =
      options.minValiditySeconds === undefined
        ? 60
        : Math.max(0, options.minValiditySeconds);
    const currentSession = await this.loadStoredSession();

    if (!currentSession) {
      if (await this.getStoredRefreshToken()) {
        await this.clearSession();
      }
      return null;
    }

    if (!this.isExpired(currentSession.expiresAt, minValiditySeconds)) {
      try {
        return await this.restoreCurrentSession(currentSession);
      } catch (error) {
        if (!isTransientAuthError(error)) await this.clearSession();
        throw this.wrapCoreError(
          error,
          "TOKEN_REQUEST_FAILED",
          "Stored session validation failed",
        );
      }
    }

    if (!(await this.getStoredRefreshToken())) {
      await this.clearSession();
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

  async getSession(): Promise<GuardhouseSession | null> {
    const stored = await this.loadStoredSession();
    if (!stored || this.isExpired(stored.expiresAt, 0)) {
      return null;
    }

    try {
      return (await this.restoreCurrentSession(stored)).session;
    } catch (error) {
      if (!isTransientAuthError(error)) await this.clearSession();
      throw this.wrapCoreError(
        error,
        "TOKEN_REQUEST_FAILED",
        "Stored session validation failed",
      );
    }
  }

  async getAccessToken(
    options: GetAccessTokenOptions = {},
  ): Promise<string | null> {
    const stored = await this.loadStoredSession();
    const minValiditySeconds =
      options.minValiditySeconds === undefined
        ? 60
        : Math.max(0, options.minValiditySeconds);

    if (stored && !this.isExpired(stored.expiresAt, minValiditySeconds)) {
      try {
        await this.restoreCurrentSession(stored);
        return stored.accessToken;
      } catch (error) {
        if (!isTransientAuthError(error)) await this.clearSession();
        throw this.wrapCoreError(
          error,
          "TOKEN_REQUEST_FAILED",
          "Stored session validation failed",
        );
      }
    }

    if (
      options.autoRefresh === false ||
      !(await this.getStoredRefreshToken())
    ) {
      return null;
    }

    return (await this.refreshToken()).session.accessToken;
  }

  async logout(options: GuardhouseLogoutOptions = {}): Promise<void> {
    const currentSession = await this.loadStoredSession();
    const refreshToken = await this.getStoredRefreshToken();
    let revokeError: GuardhouseAuthError | null = null;

    if (options.revoke && currentSession) {
      if (options.revokeAccessToken ?? true) {
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

      if ((options.revokeRefreshToken ?? true) && refreshToken) {
        try {
          await this.coreClient.revokeToken(refreshToken, "refresh_token");
        } catch (error) {
          revokeError ??= this.wrapCoreError(
            error,
            "REVOCATION_FAILED",
            "Refresh token revocation failed",
          );
        }
      }
    }

    await this.clearSession();

    if (revokeError && options.throwOnRevokeFailure) {
      throw revokeError;
    }
  }

  private async runBrowserAuthFlow(
    options: BrowserLoginOptions,
    registrationFlow: boolean,
  ): Promise<GuardhouseAuthResult> {
    if (this.pendingBrowserFlow) {
      throw new GuardhouseAuthError(
        "An authorization transaction is already in progress",
        "INVALID_CALLBACK",
      );
    }

    const browser = this.requireBrowserAdapter();
    const scope = trimToUndefined(options.scope) ?? this.defaultScope;
    const audience = this.resolveAudience(options.audience);
    this.logger.info("Starting transaction-bound browser authorization", {
      registrationFlow,
      hasAudience: Boolean(audience),
    });
    const created = await this.coreClient.createAuthorizationRequest({
      redirectUri: this.redirectUri,
      scope,
      audience,
      resource: options.resource,
      audiencePolicy: "oidc-optional",
      prompt: trimToUndefined(options.prompt),
      maxAgeSeconds: options.maxAgeSeconds,
      responseMode: "query",
      applicationState: options.appState,
      allowOfflineAccessScope: true,
      requiredAcrValues: this.mergeAssuranceRequirements(
        this.requiredAcrValues,
        options.requiredAcrValues,
      ),
      requiredAmrValues: this.mergeAssuranceRequirements(
        this.requiredAmrValues,
        options.requiredAmrValues,
      ),
    });
    this.pendingBrowserFlow = created.transaction;

    const browserOptions: BrowserSessionOptions = {
      ephemeralSession:
        options.ephemeralSession ?? this.defaultEphemeralSession,
      timeoutMs: options.timeoutMs,
    };
    const authorizationUrl = registrationFlow
      ? this.buildRegistrationAuthorizationUrl(created.authorizationUrl)
      : created.authorizationUrl;

    try {
      const browserResult = await browser.openAuthSession(
        authorizationUrl,
        this.redirectUri,
        browserOptions,
      );
      const callback = await this.coreClient.validateOAuthCallback(
        { mode: "query", url: browserResult.url },
        created.transaction,
      );

      if (callback.type === "error") {
        throw new GuardhouseAuthError(
          `Authorization failed: ${callback.error}`,
          "INVALID_CALLBACK",
        );
      }

      const exchanged =
        await this.coreClient.exchangeAuthorizationCode(callback);

      return await this.persistAuthorizationResult(
        exchanged,
        created.transaction,
      );
    } catch (error) {
      await this.coreClient.clearSessionState();
      throw this.wrapCoreError(
        error,
        "TOKEN_REQUEST_FAILED",
        "Browser authorization failed",
      );
    } finally {
      this.pendingBrowserFlow = null;
    }
  }

  private startBrowserAuthFlow(
    options: BrowserLoginOptions,
    registrationFlow: boolean,
  ): Promise<GuardhouseAuthResult> {
    if (this.browserAuthPromise) {
      return Promise.reject(
        new GuardhouseAuthError(
          "An authorization transaction is already in progress",
          "INVALID_CALLBACK",
        ),
      );
    }

    const operation = (async () => {
      try {
        return await this.runBrowserAuthFlow(options, registrationFlow);
      } finally {
        this.browserAuthPromise = null;
      }
    })();
    this.browserAuthPromise = operation;
    return operation;
  }

  private buildRegistrationAuthorizationUrl(authorizationUrl: string): string {
    const registrationUrl = new URL(this.registrationEndpoint, this.issuer);
    const returnUrlParamName = Array.from(
      registrationUrl.searchParams.keys(),
    ).find((key) => key.trim().toLowerCase() === "returnurl");

    if (returnUrlParamName) {
      registrationUrl.searchParams.set(returnUrlParamName, authorizationUrl);
      return registrationUrl.toString();
    }

    const authorization = new URL(authorizationUrl);
    for (const [key, value] of authorization.searchParams) {
      registrationUrl.searchParams.set(key, value);
    }
    return registrationUrl.toString();
  }

  private async persistAuthorizationResult(
    result: AuthorizationCodeExchangeResult,
    transaction: AuthorizationTransaction,
  ): Promise<GuardhouseAuthResult> {
    const existingSession = await this.loadStoredSession();
    const appState = isRecord(transaction.applicationState)
      ? transaction.applicationState
      : undefined;

    if (result.mode === "oidc") {
      return this.persistAuthResult(result.tokens, {
        existingSession: existingSession ?? undefined,
        requestedScope: transaction.requestedScope,
        appState,
        identity: {
          evidence: result.identity,
          metadata: toIdentityMetadata(result.identity),
          rawIdToken: result.tokens.id_token as string,
          verifiedIdToken: result.idToken,
          idTokenCurrent: true,
        },
      });
    }

    return this.persistAuthResult(result.tokens, {
      existingSession: existingSession ?? undefined,
      requestedScope: transaction.requestedScope,
      appState,
    });
  }

  private async persistAuthResult(
    tokenResponse: CoreTokenResponse,
    options: PersistTokenOptions,
  ): Promise<GuardhouseAuthResult> {
    const expiresAt = Math.floor(Date.now() / 1000) + tokenResponse.expires_in;
    if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) {
      throw new GuardhouseAuthError(
        "Token response produced an invalid expiration time",
        "TOKEN_RESPONSE_ERROR",
      );
    }

    const scope =
      trimToUndefined(tokenResponse.scope) ??
      options.requestedScope ??
      options.existingSession?.scope ??
      this.defaultScope;
    if (options.requestedScope) {
      this.assertScopeNotEscalated(options.requestedScope, scope);
    }

    let record: StoredSession;
    let user: CoreUser | null = null;
    if (options.identity) {
      record = Object.freeze({
        version: 3,
        kind: "oidc",
        issuer: this.issuer,
        clientId: this.clientId,
        accessToken: tokenResponse.access_token,
        tokenType: tokenResponse.token_type,
        scope,
        expiresAt,
        idToken: options.identity.rawIdToken,
        identity: options.identity.metadata,
        idTokenCurrent: options.identity.idTokenCurrent,
      });
      user = await this.resolveAuthenticatedUser(
        record.accessToken,
        options.identity.evidence,
        options.identity.verifiedIdToken?.payload,
      );
    } else {
      if (tokenResponse.id_token) {
        throw new GuardhouseAuthError(
          "An ID token cannot be persisted without verified identity evidence",
          "TOKEN_RESPONSE_ERROR",
        );
      }
      record = Object.freeze({
        version: 3,
        kind: "oauth",
        issuer: this.issuer,
        clientId: this.clientId,
        accessToken: tokenResponse.access_token,
        tokenType: tokenResponse.token_type,
        scope,
        expiresAt,
      });
    }

    const persistedRefreshToken = await this.getStoredRefreshToken();
    const refreshToken =
      tokenResponse.refresh_token ?? persistedRefreshToken ?? undefined;
    try {
      await this.persistRefreshToken(refreshToken);
      await this.persistSessionRecord(record, user);
    } catch (error) {
      await this.clearSession();
      throw error;
    }

    const session = this.toPublicSession(record, refreshToken, user);
    return {
      session,
      tokenResponse: {
        ...tokenResponse,
        refresh_token: refreshToken,
        scope,
      },
      user,
      appState: options.appState,
    };
  }

  private async restoreCurrentSession(
    record: StoredSession,
  ): Promise<GuardhouseAuthResult> {
    let user: CoreUser | null = null;
    if (record.kind === "oidc") {
      if (
        !record.idTokenCurrent ||
        record.identity.expiresAt <= Math.floor(Date.now() / 1000)
      ) {
        if (
          !record.idTokenCurrent &&
          this.sessionCache?.record === record &&
          this.sessionCache.user !== null
        ) {
          const refreshToken = await this.getStoredRefreshToken();
          const session = this.toPublicSession(
            record,
            refreshToken ?? undefined,
            this.sessionCache.user,
          );
          return this.buildAuthResultFromSession(session);
        }
        const restored = await this.coreClient.restoreOidcSession(
          record.accessToken,
          {
            idToken: record.idToken,
            requiredAcrValues: this.requiredAcrValues,
            requiredAmrValues: this.requiredAmrValues,
          },
        );
        if (!identityEquals(restored.identity, record.identity)) {
          throw new GuardhouseAuthError(
            "Stored identity metadata does not match the signed ID token",
            "TOKEN_REQUEST_FAILED",
          );
        }
        user = freezeUser(
          this.userInfoOnLogin
            ? { ...restored.userInfo, sub: restored.identity.subject }
            : { sub: restored.identity.subject },
        );
        // Never expose an expired raw ID token as a current credential.
        record = Object.freeze({ ...record, idTokenCurrent: false });
      } else {
        const verified = await this.coreClient.verifyIdToken(record.idToken, {
          purpose: "session",
          requiredAcrValues: this.requiredAcrValues,
          requiredAmrValues: this.requiredAmrValues,
        });
        if (!identityEquals(verified.identity, record.identity)) {
          throw new GuardhouseAuthError(
            "Stored identity metadata does not match the signed ID token",
            "TOKEN_REQUEST_FAILED",
          );
        }
        user = await this.resolveAuthenticatedUser(
          record.accessToken,
          verified.identity,
          verified.payload,
        );
      }
    }

    const refreshToken = await this.getStoredRefreshToken();
    this.sessionCache = { record, user };
    const session = this.toPublicSession(
      record,
      refreshToken ?? undefined,
      user,
    );
    return this.buildAuthResultFromSession(session);
  }

  private async resolveAuthenticatedUser(
    accessToken: string,
    identity: OidcIdentityEvidence,
    payload?: VerifiedIdTokenPayload,
  ): Promise<CoreUser> {
    if (this.userInfoOnLogin) {
      const userInfo = await this.coreClient.getUserInfo(accessToken, identity);
      return freezeUser({ ...userInfo, sub: userInfo.sub });
    }

    if (payload) {
      return freezeUser({ ...payload, sub: identity.subject } as CoreUser);
    }

    return freezeUser({ sub: identity.subject });
  }

  private async loadStoredSession(): Promise<StoredSession | null> {
    if (this.sessionCache) {
      return this.sessionCache.record;
    }
    if (!this.sessionStorage) {
      return null;
    }

    const serialized = await this.sessionStorage.getItem(
      this.sessionStorageKey,
    );
    if (!serialized) {
      return null;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(serialized) as unknown;
    } catch {
      await this.clearSession();
      return null;
    }

    const record = this.parseStoredSession(parsed);
    if (!record) {
      await this.clearSession();
      return null;
    }

    this.sessionCache = { record, user: null };
    return record;
  }

  private parseStoredSession(value: unknown): StoredSession | null {
    if (
      !isRecord(value) ||
      value.version !== 3 ||
      value.issuer !== this.issuer ||
      value.clientId !== this.clientId ||
      (value.kind !== "oauth" && value.kind !== "oidc") ||
      typeof value.accessToken !== "string" ||
      value.accessToken.trim() === "" ||
      typeof value.tokenType !== "string" ||
      value.tokenType.trim() === "" ||
      typeof value.expiresAt !== "number" ||
      !Number.isSafeInteger(value.expiresAt) ||
      value.expiresAt <= 0 ||
      (value.scope !== undefined && typeof value.scope !== "string")
    ) {
      return null;
    }

    const base: StoredSessionBase = {
      version: 3,
      issuer: this.issuer,
      clientId: this.clientId,
      accessToken: value.accessToken,
      tokenType: value.tokenType,
      scope: trimToUndefined(value.scope as string | undefined),
      expiresAt: value.expiresAt,
    };

    if (value.kind === "oauth") {
      return Object.freeze({ ...base, kind: "oauth" });
    }

    const identity = parseStoredIdentity(value.identity);
    if (
      !identity ||
      identity.issuer !== this.issuer ||
      identity.clientId !== this.clientId ||
      typeof value.idToken !== "string" ||
      value.idToken.trim() === "" ||
      typeof value.idTokenCurrent !== "boolean"
    ) {
      return null;
    }

    return Object.freeze({
      ...base,
      kind: "oidc",
      idToken: value.idToken,
      identity,
      idTokenCurrent: value.idTokenCurrent,
    });
  }

  private async persistSessionRecord(
    record: StoredSession,
    user: CoreUser | null,
  ): Promise<void> {
    if (this.sessionStorage) {
      await this.sessionStorage.setItem(
        this.sessionStorageKey,
        JSON.stringify(record),
      );
      const readBack = await this.sessionStorage.getItem(
        this.sessionStorageKey,
      );
      if (readBack !== JSON.stringify(record)) {
        throw new GuardhouseAuthError(
          "Session storage did not durably retain the v3 session record",
          "STORAGE_ERROR",
        );
      }
    }
    this.sessionCache = { record, user };
  }

  private async getStoredRefreshToken(): Promise<string | null> {
    if (this.refreshTokenCache) {
      return this.refreshTokenCache;
    }
    const persisted = trimToUndefined(
      await this.refreshTokenStorage.getItem(this.refreshTokenStorageKey),
    );
    this.refreshTokenCache = persisted ?? null;
    return this.refreshTokenCache;
  }

  private async persistRefreshToken(
    refreshToken: string | undefined,
  ): Promise<void> {
    const normalized = trimToUndefined(refreshToken);
    if (!normalized) {
      await this.refreshTokenStorage.removeItem(this.refreshTokenStorageKey);
      this.refreshTokenCache = null;
      return;
    }
    await this.refreshTokenStorage.setItem(
      this.refreshTokenStorageKey,
      normalized,
    );
    const readBack = await this.refreshTokenStorage.getItem(
      this.refreshTokenStorageKey,
    );
    if (readBack !== normalized) {
      throw new GuardhouseAuthError(
        "Refresh-token storage did not durably retain the token",
        "STORAGE_ERROR",
      );
    }
    this.refreshTokenCache = normalized;
  }

  private async clearSession(): Promise<void> {
    this.pendingBrowserFlow = null;
    this.sessionCache = null;
    this.refreshTokenCache = null;

    await Promise.all([
      this.refreshTokenStorage.removeItem(this.refreshTokenStorageKey),
      this.sessionStorage?.removeItem(this.sessionStorageKey),
      this.coreClient.clearSessionState(),
    ]);

    const [refreshToken, session] = await Promise.all([
      this.refreshTokenStorage.getItem(this.refreshTokenStorageKey),
      this.sessionStorage?.getItem(this.sessionStorageKey),
    ]);
    if (refreshToken !== null || (session !== null && session !== undefined)) {
      throw new GuardhouseAuthError(
        "Storage retained authentication state after logout",
        "STORAGE_ERROR",
      );
    }
  }

  private toPublicSession(
    record: StoredSession,
    refreshToken: string | undefined,
    user: CoreUser | null,
  ): GuardhouseSession {
    return {
      accessToken: record.accessToken,
      refreshToken,
      idToken:
        record.kind === "oidc" && record.idTokenCurrent
          ? record.idToken
          : undefined,
      identity: record.kind === "oidc" ? record.identity : undefined,
      tokenType: record.tokenType,
      scope: record.scope,
      expiresAt: record.expiresAt,
      user,
    };
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

  private assertScopeNotEscalated(
    grantedOrRequestedScope: string,
    returnedOrRequestedScope: string,
  ): void {
    const allowed = this.scopeSet(grantedOrRequestedScope);
    for (const scope of this.scopeSet(returnedOrRequestedScope)) {
      if (!allowed.has(scope)) {
        throw new GuardhouseAuthError(
          "The token request or response attempted to escalate scope",
          "TOKEN_RESPONSE_ERROR",
        );
      }
    }
  }

  private scopeSet(scope: string): Set<string> {
    return new Set(scope.split(/\s+/).filter(Boolean));
  }

  private mergeAssuranceRequirements(
    configured: readonly string[],
    requested: readonly string[] | undefined,
  ): readonly string[] {
    return Array.from(new Set([...configured, ...(requested ?? [])]));
  }

  private resolveAudience(audience: string | undefined): string | undefined {
    return trimToUndefined(audience) ?? this.defaultAudience;
  }

  private isExpired(expiresAt: number, minValiditySeconds: number): boolean {
    return expiresAt <= Math.floor(Date.now() / 1000) + minValiditySeconds;
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
      );
    }
    if (error instanceof CoreGuardhouseError) {
      return new GuardhouseAuthError(
        error.message,
        isTransientAuthError(error) ? "NETWORK_ERROR" : fallbackCode,
        error.statusCode,
        error,
      );
    }
    return new GuardhouseAuthError(
      fallbackMessage,
      fallbackCode,
      undefined,
      error,
    );
  }

  private shouldClearSessionAfterRefreshFailure(error: unknown): boolean {
    const code =
      error instanceof CoreGuardhouseError
        ? error.code
        : error instanceof GuardhouseAuthError
          ? error.code
          : undefined;

    return (
      code === "invalid_grant" ||
      code === "invalid_token" ||
      code === "ID_TOKEN_VALIDATION_FAILED" ||
      code === "REFRESH_IDENTITY_REQUIRED" ||
      code === "USERINFO_SUBJECT_MISMATCH" ||
      code === "INVALID_IDENTITY" ||
      code === "TOKEN_RESPONSE_ERROR"
    );
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
