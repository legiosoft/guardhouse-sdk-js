import {
  generateAuthUrl,
  generateNonce,
  generatePKCE,
  generateState,
  parseOAuthCallbackUrl,
} from "@guardhouse/core";
import type { CryptoAdapter, User as CoreUser } from "@guardhouse/core";
import { Linking } from "react-native";
import InAppBrowser from "react-native-inappbrowser-reborn";
import { resolveReactNativeCryptoAdapter } from "./crypto";
import { createReactNativeLogger } from "./debug";
import {
  createRedirectUriDescriptor,
  matchesRedirectUri,
} from "./utils/idToken";
import { PromiseLock, STORAGE_KEYS, SecureStorage } from "./utils/storage";

const DEFAULT_SCOPE = "openid profile offline_access";
const DEFAULT_BROWSER_TIMEOUT_MS = 180000;

const CLIENT_STORAGE_KEYS = {
  TOKEN_TYPE: "gh_token_type",
  SCOPE: "gh_scope",
} as const;

const DEFAULT_ENDPOINTS = {
  authorization: "/connect/authorize",
  registration: "/account/signup",
  token: "/connect/token",
  userInfo: "/connect/userinfo",
  revocation: "/connect/revocation",
  passkeyChallenge: "/connect/webauthn/challenge",
  passkeyAssertion: "/connect/webauthn/verify",
} as const;

type FetchFn = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

function trimToUndefined(value: string | null | undefined): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed === "" ? undefined : trimmed;
}

function sanitizeAuthority(authority: string): string {
  const parsed = new URL(authority);
  parsed.hash = "";
  parsed.search = "";
  parsed.pathname = parsed.pathname.replace(/\/+$/, "");

  if (parsed.pathname === "") {
    parsed.pathname = "/";
  }

  return parsed.toString();
}

function compactRecord(
  value: Record<string, unknown>,
): Record<string, unknown> {
  const output: Record<string, unknown> = {};

  for (const [key, entry] of Object.entries(value)) {
    if (entry === undefined || entry === null || entry === "") {
      continue;
    }

    output[key] = entry;
  }

  return output;
}

function parsePositiveInteger(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isInteger(value) && value > 0) {
    return value;
  }

  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10);
    if (Number.isInteger(parsed) && parsed > 0) {
      return parsed;
    }
  }

  return undefined;
}

export type GuardhouseClientErrorCode =
  | "CONFIG_ERROR"
  | "BROWSER_ERROR"
  | "PASSKEY_ERROR"
  | "STATE_MISMATCH"
  | "INVALID_CALLBACK"
  | "TOKEN_RESPONSE_ERROR"
  | "NETWORK_ERROR"
  | "TOKEN_REQUEST_FAILED"
  | "MISSING_REFRESH_TOKEN"
  | "PASSKEY_ADAPTER_MISSING"
  | "BROWSER_ADAPTER_MISSING"
  | "REVOCATION_FAILED";

export class GuardhouseClientError extends Error {
  constructor(
    message: string,
    public readonly code: GuardhouseClientErrorCode,
    public readonly statusCode?: number,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = "GuardhouseClientError";
  }
}

export interface GuardhouseStorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
}

export interface BrowserSessionOptions {
  ephemeralSession?: boolean;
  timeoutMs?: number;
}

export interface BrowserAuthSessionResult {
  url: string;
}

export interface GuardhouseBrowserAdapter {
  name?: string;
  openAuthSession(
    authorizationUrl: string,
    redirectUri: string,
    options?: BrowserSessionOptions,
  ): Promise<BrowserAuthSessionResult>;
}

export interface PasskeyCredentialDescriptor {
  id: string;
  type: "public-key";
  transports?: Array<"usb" | "nfc" | "ble" | "hybrid" | "internal">;
}

export interface PasskeyCredentialRequestOptions {
  challenge: string;
  rpId?: string;
  timeout?: number;
  userVerification?: "required" | "preferred" | "discouraged";
  allowCredentials?: PasskeyCredentialDescriptor[];
  extensions?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface PasskeyAssertionResponse {
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string | null;
  [key: string]: unknown;
}

export interface PasskeyAssertionResult {
  id: string;
  rawId?: string;
  type: "public-key";
  response: PasskeyAssertionResponse;
  clientExtensionResults?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface GuardhousePasskeyAdapter {
  name?: string;
  get(
    requestOptions: PasskeyCredentialRequestOptions,
  ): Promise<PasskeyAssertionResult>;
}

export interface GuardhouseTokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  id_token?: string;
  scope?: string;
}

export interface GuardhouseSession {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  tokenType: string;
  scope?: string;
  expiresAt: number;
  user: CoreUser | null;
}

export interface GuardhouseAuthResult {
  session: GuardhouseSession;
  tokenResponse: GuardhouseTokenResponse;
  user: CoreUser | null;
  appState?: Record<string, unknown>;
}

export interface BrowserLoginOptions {
  ephemeralSession?: boolean;
  timeoutMs?: number;
  scope?: string;
  audience?: string;
  prompt?: string;
  appState?: Record<string, unknown>;
  extraParams?: Record<string, string | number | null | undefined>;
}

export interface LoginWithPasskeyOptions {
  scope?: string;
  audience?: string;
  challengeBody?: Record<string, unknown>;
  assertionBody?: Record<string, unknown>;
}

export interface RefreshTokenOptions {
  scope?: string;
  audience?: string;
}

export interface RestoreSessionOptions extends RefreshTokenOptions {
  minValiditySeconds?: number;
}

export interface GuardhouseLogoutOptions {
  revoke?: boolean;
  revokeAccessToken?: boolean;
  revokeRefreshToken?: boolean;
  throwOnRevokeFailure?: boolean;
}

export interface GetAccessTokenOptions {
  autoRefresh?: boolean;
  minValiditySeconds?: number;
}

export interface GuardhouseClientEndpoints {
  authorization: string;
  registration: string;
  token: string;
  userInfo: string;
  revocation: string;
  passkeyChallenge: string;
  passkeyAssertion: string;
}

export interface GuardhouseClientConfig {
  authority: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  audience?: string;
  debug?: boolean;
  requireBiometrics?: boolean;
  cryptoAdapter?: CryptoAdapter;
  /**
   * @deprecated Use refreshTokenStorage instead.
   */
  storage?: GuardhouseStorageAdapter;
  refreshTokenStorage?: GuardhouseStorageAdapter;
  sessionStorage?: GuardhouseStorageAdapter;
  browser?: GuardhouseBrowserAdapter;
  passkey?: GuardhousePasskeyAdapter;
  fetch?: FetchFn;
  defaultEphemeralSession?: boolean;
  userInfoOnLogin?: boolean;
  endpoints?: Partial<GuardhouseClientEndpoints>;
}

interface ParsedPasskeyChallenge {
  challengeId?: string;
  requestOptions: PasskeyCredentialRequestOptions;
}

interface SessionCacheData {
  accessToken: string;
  idToken?: string;
  tokenType: string;
  scope?: string;
  expiresAt: number;
  user: CoreUser | null;
}

interface PendingBrowserFlow {
  codeVerifier: string;
  state: string;
  nonce: string;
  appState?: Record<string, unknown>;
}

export class InAppBrowserAuthAdapter implements GuardhouseBrowserAdapter {
  public readonly name = "InAppBrowserAuthAdapter";
  private readonly logger: ReturnType<typeof createReactNativeLogger>;

  constructor(debug = false) {
    this.logger = createReactNativeLogger("InAppBrowserAdapter", debug);
  }

  async openAuthSession(
    authorizationUrl: string,
    redirectUri: string,
    options: BrowserSessionOptions = {},
  ): Promise<BrowserAuthSessionResult> {
    const hasInAppBrowser = await this.isInAppBrowserAvailable();

    if (hasInAppBrowser) {
      const result = await InAppBrowser.openAuth(
        authorizationUrl,
        redirectUri,
        {
          ephemeralWebSession: options.ephemeralSession ?? false,
          showTitle: false,
          enableDefaultShare: false,
          enableUrlBarHiding: true,
          showInRecents: true,
        },
      );

      if (result.type === "success" && typeof result.url === "string") {
        return { url: result.url };
      }

      if (result.type === "cancel") {
        throw new GuardhouseClientError(
          "Authentication cancelled by user",
          "BROWSER_ERROR",
        );
      }

      if (result.type === "dismiss") {
        throw new GuardhouseClientError(
          "Authentication session dismissed",
          "BROWSER_ERROR",
        );
      }

      throw new GuardhouseClientError(
        `Unsupported browser result: ${String(result.type)}`,
        "BROWSER_ERROR",
      );
    }

    this.logger.warn(
      "InAppBrowser unavailable, falling back to deep-link listener",
    );

    return this.openExternalAuthSession(
      authorizationUrl,
      redirectUri,
      options.timeoutMs,
    );
  }

  private async isInAppBrowserAvailable(): Promise<boolean> {
    try {
      return await InAppBrowser.isAvailable();
    } catch (error) {
      this.logger.warn("InAppBrowser availability check failed", {
        error: toErrorMessage(error),
      });
      return false;
    }
  }

  private async openExternalAuthSession(
    authorizationUrl: string,
    redirectUri: string,
    timeoutMs = DEFAULT_BROWSER_TIMEOUT_MS,
  ): Promise<BrowserAuthSessionResult> {
    const redirectDescriptor = createRedirectUriDescriptor(redirectUri);

    return new Promise((resolve, reject) => {
      let settled = false;
      let subscription: { remove: () => void } | undefined;

      const timeoutHandle = setTimeout(() => {
        if (settled) {
          return;
        }

        settled = true;
        subscription?.remove();

        reject(
          new GuardhouseClientError(
            "Authentication redirect timed out",
            "BROWSER_ERROR",
          ),
        );
      }, timeoutMs);

      const complete = (value: BrowserAuthSessionResult) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timeoutHandle);
        subscription?.remove();
        resolve(value);
      };

      const fail = (error: unknown) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timeoutHandle);
        subscription?.remove();

        reject(
          error instanceof GuardhouseClientError
            ? error
            : new GuardhouseClientError(
                `External auth session failed: ${toErrorMessage(error)}`,
                "BROWSER_ERROR",
              ),
        );
      };

      subscription = Linking.addEventListener("url", ({ url }) => {
        if (!matchesRedirectUri(url, redirectDescriptor)) {
          return;
        }

        complete({ url });
      });

      Linking.openURL(authorizationUrl).catch(fail);
    });
  }
}

export class GuardhouseClient {
  private readonly authority: string;
  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly defaultScope: string;
  private readonly defaultAudience?: string;
  private readonly debug: boolean;
  private readonly defaultEphemeralSession: boolean;
  private readonly userInfoOnLogin: boolean;
  private readonly endpoints: GuardhouseClientEndpoints;
  private readonly refreshTokenStorage: GuardhouseStorageAdapter;
  private readonly sessionStorage?: GuardhouseStorageAdapter;
  private readonly browser?: GuardhouseBrowserAdapter;
  private readonly passkey?: GuardhousePasskeyAdapter;
  private readonly cryptoAdapter: CryptoAdapter;
  private readonly fetchFn: FetchFn;
  private readonly refreshLock: PromiseLock;
  private readonly redirectUriDescriptor: ReturnType<
    typeof createRedirectUriDescriptor
  >;
  private readonly logger: ReturnType<typeof createReactNativeLogger>;
  private sessionCache: SessionCacheData | null = null;
  private refreshTokenCache: string | null = null;
  private pendingBrowserFlow: PendingBrowserFlow | null = null;

  constructor(config: GuardhouseClientConfig) {
    if (!config || typeof config !== "object") {
      throw new GuardhouseClientError(
        "GuardhouseClient configuration is required",
        "CONFIG_ERROR",
      );
    }

    this.authority = sanitizeAuthority(
      this.requireString(config.authority, "authority"),
    );
    this.clientId = this.requireString(config.clientId, "clientId");
    this.redirectUri = this.requireString(config.redirectUri, "redirectUri");
    this.defaultScope = trimToUndefined(config.scope) ?? DEFAULT_SCOPE;
    this.defaultAudience = trimToUndefined(config.audience);
    this.defaultEphemeralSession = config.defaultEphemeralSession ?? false;
    this.userInfoOnLogin = config.userInfoOnLogin ?? true;

    const debug = config.debug ?? false;
    this.debug = debug;
    this.logger = createReactNativeLogger("GuardhouseClient", debug);
    this.refreshLock = new PromiseLock(debug);
    this.redirectUriDescriptor = createRedirectUriDescriptor(this.redirectUri);

    this.refreshTokenStorage =
      config.refreshTokenStorage ??
      config.storage ??
      new SecureStorage(config.requireBiometrics ?? false, debug);
    this.sessionStorage = config.sessionStorage;

    this.browser = config.browser ?? new InAppBrowserAuthAdapter(debug);
    this.passkey = config.passkey;

    const fetchImpl = config.fetch ?? globalThis.fetch;
    if (typeof fetchImpl !== "function") {
      throw new GuardhouseClientError(
        "No fetch implementation available. Pass fetch in GuardhouseClientConfig.",
        "CONFIG_ERROR",
      );
    }
    this.fetchFn = (input: RequestInfo | URL, init?: RequestInit) =>
      fetchImpl(input, init);

    this.cryptoAdapter = resolveReactNativeCryptoAdapter(
      config.cryptoAdapter,
      debug,
    );

    const configuredEndpoints = config.endpoints ?? {};
    this.endpoints = {
      authorization: this.resolveEndpoint(
        configuredEndpoints.authorization ?? DEFAULT_ENDPOINTS.authorization,
      ),
      registration: this.resolveEndpoint(
        configuredEndpoints.registration ?? DEFAULT_ENDPOINTS.registration,
      ),
      token: this.resolveEndpoint(
        configuredEndpoints.token ?? DEFAULT_ENDPOINTS.token,
      ),
      userInfo: this.resolveEndpoint(
        configuredEndpoints.userInfo ?? DEFAULT_ENDPOINTS.userInfo,
      ),
      revocation: this.resolveEndpoint(
        configuredEndpoints.revocation ?? DEFAULT_ENDPOINTS.revocation,
      ),
      passkeyChallenge: this.resolveEndpoint(
        configuredEndpoints.passkeyChallenge ??
          DEFAULT_ENDPOINTS.passkeyChallenge,
      ),
      passkeyAssertion: this.resolveEndpoint(
        configuredEndpoints.passkeyAssertion ??
          DEFAULT_ENDPOINTS.passkeyAssertion,
      ),
    };
  }

  async loginWithBrowser(
    options: BrowserLoginOptions = {},
  ): Promise<GuardhouseAuthResult> {
    this.requireBrowserAdapter();
    return this.runBrowserAuthFlow(this.endpoints.authorization, options);
  }

  async registerWithBrowser(
    options: BrowserLoginOptions = {},
  ): Promise<GuardhouseAuthResult> {
    this.requireBrowserAdapter();
    return this.runBrowserAuthFlow(this.endpoints.registration, options);
  }

  async loginWithPasskey(
    options: LoginWithPasskeyOptions = {},
  ): Promise<GuardhouseAuthResult> {
    const passkeyAdapter = this.requirePasskeyAdapter();
    const scope = trimToUndefined(options.scope) ?? this.defaultScope;
    const audience = this.resolveAudience(options.audience);

    const challengeRequestBody = compactRecord({
      client_id: this.clientId,
      scope,
      audience,
      ...(options.challengeBody ?? {}),
    });

    const challengePayload = await this.postJson(
      this.endpoints.passkeyChallenge,
      challengeRequestBody,
      "Passkey challenge request",
      "PASSKEY_ERROR",
    );

    const challenge = this.parsePasskeyChallenge(challengePayload);

    const assertion = await passkeyAdapter.get(challenge.requestOptions);
    this.validatePasskeyAssertion(assertion);

    const assertionBody = compactRecord({
      client_id: this.clientId,
      scope,
      audience,
      challenge_id: challenge.challengeId,
      challengeId: challenge.challengeId,
      credential: assertion,
      assertion,
      ...(options.assertionBody ?? {}),
    });

    const verificationPayload = await this.postJson(
      this.endpoints.passkeyAssertion,
      assertionBody,
      "Passkey assertion verification",
      "PASSKEY_ERROR",
    );

    const tokenResponse = this.parseTokenResponse(verificationPayload);
    const currentSession = await this.getSession();

    return this.persistAuthResult(tokenResponse, currentSession ?? undefined);
  }

  async refreshToken(
    options: RefreshTokenOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.refreshLock.run(async () => {
      const currentSession = await this.getSession();
      const refreshToken = await this.getStoredRefreshToken();

      if (!refreshToken) {
        throw new GuardhouseClientError(
          "No refresh token available. User interaction is required.",
          "MISSING_REFRESH_TOKEN",
        );
      }

      const body = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
        client_id: this.clientId,
      });

      const scope = trimToUndefined(options.scope);
      if (scope) {
        body.set("scope", scope);
      }

      const audience = this.resolveAudience(options.audience);
      if (audience) {
        body.set("audience", audience);
      }

      try {
        const tokenResponse = await this.executeTokenRequest(
          body,
          "Refresh token request",
        );
        return this.persistAuthResult(
          tokenResponse,
          currentSession ?? undefined,
        );
      } catch (error) {
        if (this.shouldClearSessionAfterRefreshFailure(error)) {
          await this.clearSession();
        }

        throw error;
      }
    });
  }

  async getSession(): Promise<GuardhouseSession | null> {
    const cachedSession = await this.loadSessionCache();
    if (!cachedSession) {
      return null;
    }

    const refreshToken = await this.getStoredRefreshToken();

    return {
      accessToken: cachedSession.accessToken,
      refreshToken: refreshToken ?? undefined,
      idToken: cachedSession.idToken,
      tokenType: cachedSession.tokenType,
      scope: cachedSession.scope,
      expiresAt: cachedSession.expiresAt,
      user: cachedSession.user,
    };
  }

  async restoreSession(
    options: RestoreSessionOptions = {},
  ): Promise<GuardhouseAuthResult | null> {
    const minValiditySeconds =
      options.minValiditySeconds !== undefined
        ? Math.max(0, options.minValiditySeconds)
        : 60;

    const cachedSession = await this.getSession();
    if (
      cachedSession &&
      !this.isExpired(cachedSession.expiresAt, minValiditySeconds)
    ) {
      return this.buildAuthResultFromSession(cachedSession);
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

  async logout(options: GuardhouseLogoutOptions = {}): Promise<void> {
    const currentSession = await this.getSession();
    const refreshToken = await this.getStoredRefreshToken();
    const revoke = options.revoke ?? false;

    let revokeError: GuardhouseClientError | null = null;

    if (revoke && currentSession) {
      const revokeAccessToken = options.revokeAccessToken ?? true;
      const revokeRefreshToken = options.revokeRefreshToken ?? true;

      if (revokeAccessToken && currentSession.accessToken) {
        try {
          await this.revokeToken(currentSession.accessToken, "access_token");
        } catch (error) {
          revokeError = this.toRevokeError(error);
        }
      }

      if (revokeRefreshToken && refreshToken) {
        try {
          await this.revokeToken(refreshToken, "refresh_token");
        } catch (error) {
          if (!revokeError) {
            revokeError = this.toRevokeError(error);
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
    authorizationEndpoint: string,
    options: BrowserLoginOptions,
  ): Promise<GuardhouseAuthResult> {
    const browser = this.requireBrowserAdapter();
    const scope = trimToUndefined(options.scope) ?? this.defaultScope;
    const audience = this.resolveAudience(options.audience);

    const { codeVerifier, codeChallenge } = await generatePKCE(
      {
        debug: this.debug,
      },
      this.cryptoAdapter,
    );

    const state = await generateState(32, this.debug, this.cryptoAdapter);
    const nonce = await generateNonce(32, this.debug, this.cryptoAdapter);

    await this.persistPendingBrowserFlow(
      codeVerifier,
      state,
      nonce,
      options.appState,
    );

    try {
      const authorizationUrl = generateAuthUrl({
        authority: this.authority,
        authorizationEndpoint,
        clientId: this.clientId,
        redirectUri: this.redirectUri,
        responseType: "code",
        scope,
        state,
        nonce,
        prompt: trimToUndefined(options.prompt),
        audience,
        allowAuthorizationWithoutAudience: true,
        allowOfflineAccessScope: true,
        codeChallenge,
        codeChallengeMethod: "S256",
        extraParams: options.extraParams,
      });

      const browserResult = await browser.openAuthSession(
        authorizationUrl,
        this.redirectUri,
        {
          ephemeralSession:
            options.ephemeralSession ?? this.defaultEphemeralSession,
          timeoutMs: options.timeoutMs,
        },
      );

      const callback = this.parseAuthorizationCallback(browserResult.url);
      const pendingFlow = this.pendingBrowserFlow;
      const storedState = pendingFlow?.state;

      if (!storedState || storedState !== callback.state) {
        throw new GuardhouseClientError(
          "OAuth state mismatch detected",
          "STATE_MISMATCH",
        );
      }

      const storedCodeVerifier = pendingFlow?.codeVerifier;

      if (!storedCodeVerifier) {
        throw new GuardhouseClientError(
          "PKCE code_verifier was not found in storage",
          "INVALID_CALLBACK",
        );
      }

      const tokenResponse = await this.exchangeAuthorizationCode(
        callback.code,
        storedCodeVerifier,
      );
      const currentSession = await this.getSession();
      const appState = this.readStoredAppState();

      return this.persistAuthResult(
        tokenResponse,
        currentSession ?? undefined,
        appState,
      );
    } finally {
      await this.clearPendingBrowserFlow();
    }
  }

  private async exchangeAuthorizationCode(
    code: string,
    codeVerifier: string,
  ): Promise<GuardhouseTokenResponse> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.redirectUri,
      client_id: this.clientId,
      code_verifier: codeVerifier,
    });

    return this.executeTokenRequest(body, "Authorization code exchange");
  }

  private async executeTokenRequest(
    body: URLSearchParams,
    operationLabel: string,
  ): Promise<GuardhouseTokenResponse> {
    let response: Response;

    try {
      response = await this.fetchFn(this.endpoints.token, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: body.toString(),
      });
    } catch (error) {
      throw new GuardhouseClientError(
        `${operationLabel} failed due to a network error`,
        "NETWORK_ERROR",
        undefined,
        error,
      );
    }

    const payload = await this.readResponsePayload(response);

    if (!response.ok) {
      throw new GuardhouseClientError(
        `${operationLabel} failed`,
        "TOKEN_REQUEST_FAILED",
        response.status,
        payload,
      );
    }

    return this.parseTokenResponse(payload);
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

    const resolvedTokenResponse: GuardhouseTokenResponse = {
      ...tokenResponse,
      refresh_token: session.refreshToken,
      id_token: session.idToken,
      scope: session.scope,
      token_type: session.tokenType,
    };

    return {
      session,
      tokenResponse: resolvedTokenResponse,
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

    let response: Response;

    try {
      response = await this.fetchFn(this.endpoints.userInfo, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
    } catch (error) {
      this.logger.warn("Failed to fetch user profile", {
        error: toErrorMessage(error),
      });
      return fallbackUser;
    }

    if (!response.ok) {
      return fallbackUser;
    }

    const payload = await this.readResponsePayload(response);
    if (!isRecord(payload)) {
      return fallbackUser;
    }

    const subject = trimToUndefined(
      typeof payload.sub === "string" ? payload.sub : undefined,
    );

    if (!subject) {
      return fallbackUser;
    }

    return {
      ...(payload as CoreUser),
      sub: subject,
    };
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
    this.sessionCache = null;
    this.pendingBrowserFlow = null;

    await Promise.all([
      this.persistRefreshToken(undefined),
      this.clearPersistedSessionCache(),
    ]);
  }

  private async revokeToken(
    token: string,
    tokenTypeHint: "access_token" | "refresh_token",
  ): Promise<void> {
    const body = new URLSearchParams({
      token,
      token_type_hint: tokenTypeHint,
      client_id: this.clientId,
    });

    let response: Response;

    try {
      response = await this.fetchFn(this.endpoints.revocation, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "application/json",
        },
        body: body.toString(),
      });
    } catch (error) {
      throw new GuardhouseClientError(
        "Token revocation request failed",
        "REVOCATION_FAILED",
        undefined,
        error,
      );
    }

    if (!response.ok) {
      const payload = await this.readResponsePayload(response);
      throw new GuardhouseClientError(
        "Token revocation request was rejected",
        "REVOCATION_FAILED",
        response.status,
        payload,
      );
    }
  }

  private parseAuthorizationCallback(callbackUrl: string): {
    code: string;
    state: string;
  } {
    if (!matchesRedirectUri(callbackUrl, this.redirectUriDescriptor)) {
      throw new GuardhouseClientError(
        "Callback URL does not match configured redirect URI",
        "INVALID_CALLBACK",
      );
    }

    const callback = parseOAuthCallbackUrl(callbackUrl);

    if (callback.error) {
      const description = callback.errorDescription ?? callback.error;
      throw new GuardhouseClientError(
        `OAuth callback returned an error: ${description}`,
        "INVALID_CALLBACK",
        undefined,
        callback,
      );
    }

    if (!callback.code || !callback.state) {
      throw new GuardhouseClientError(
        "OAuth callback is missing required code/state parameters",
        "INVALID_CALLBACK",
        undefined,
        callback,
      );
    }

    return {
      code: callback.code,
      state: callback.state,
    };
  }

  private parseTokenResponse(payload: unknown): GuardhouseTokenResponse {
    const container = this.extractTokenContainer(payload);

    const accessToken = trimToUndefined(
      typeof container.access_token === "string"
        ? container.access_token
        : undefined,
    );

    if (!accessToken) {
      throw new GuardhouseClientError(
        "Token response did not include access_token",
        "TOKEN_RESPONSE_ERROR",
        undefined,
        payload,
      );
    }

    const expiresIn = parsePositiveInteger(container.expires_in);
    if (!expiresIn) {
      throw new GuardhouseClientError(
        "Token response did not include a valid expires_in value",
        "TOKEN_RESPONSE_ERROR",
        undefined,
        payload,
      );
    }

    const tokenType =
      trimToUndefined(
        typeof container.token_type === "string"
          ? container.token_type
          : undefined,
      ) ?? "Bearer";

    const refreshToken = trimToUndefined(
      typeof container.refresh_token === "string"
        ? container.refresh_token
        : undefined,
    );
    const idToken = trimToUndefined(
      typeof container.id_token === "string" ? container.id_token : undefined,
    );
    const scope = trimToUndefined(
      typeof container.scope === "string" ? container.scope : undefined,
    );

    return {
      access_token: accessToken,
      token_type: tokenType,
      expires_in: expiresIn,
      refresh_token: refreshToken,
      id_token: idToken,
      scope,
    };
  }

  private extractTokenContainer(payload: unknown): Record<string, unknown> {
    if (!isRecord(payload)) {
      throw new GuardhouseClientError(
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

    throw new GuardhouseClientError(
      "Token response payload did not include access_token",
      "TOKEN_RESPONSE_ERROR",
      undefined,
      payload,
    );
  }

  private parsePasskeyChallenge(payload: unknown): ParsedPasskeyChallenge {
    if (!isRecord(payload)) {
      throw new GuardhouseClientError(
        "Passkey challenge response is not a JSON object",
        "PASSKEY_ERROR",
        undefined,
        payload,
      );
    }

    const requestOptionsCandidate = [
      payload.publicKey,
      payload.public_key,
      payload.publicKeyCredentialRequestOptions,
      payload.requestOptions,
      payload.options,
    ].find((entry) => isRecord(entry));

    const requestOptionsRecord = isRecord(requestOptionsCandidate)
      ? requestOptionsCandidate
      : typeof payload.challenge === "string"
        ? payload
        : null;

    if (!requestOptionsRecord) {
      throw new GuardhouseClientError(
        "Passkey challenge response is missing request options",
        "PASSKEY_ERROR",
        undefined,
        payload,
      );
    }

    const challenge = trimToUndefined(
      typeof requestOptionsRecord.challenge === "string"
        ? requestOptionsRecord.challenge
        : undefined,
    );

    if (!challenge) {
      throw new GuardhouseClientError(
        "Passkey request options are missing a challenge",
        "PASSKEY_ERROR",
        undefined,
        payload,
      );
    }

    const challengeId = this.readStringFromCandidates(payload, [
      "challenge_id",
      "challengeId",
      "request_id",
      "requestId",
      "id",
    ]);

    const requestOptions: PasskeyCredentialRequestOptions = {
      ...(requestOptionsRecord as PasskeyCredentialRequestOptions),
      challenge,
    };

    return {
      challengeId,
      requestOptions,
    };
  }

  private validatePasskeyAssertion(assertion: PasskeyAssertionResult): void {
    if (!isRecord(assertion)) {
      throw new GuardhouseClientError(
        "Passkey assertion result is invalid",
        "PASSKEY_ERROR",
      );
    }

    const assertionId = trimToUndefined(
      typeof assertion.id === "string" ? assertion.id : undefined,
    );

    if (!assertionId) {
      throw new GuardhouseClientError(
        "Passkey assertion result is missing credential id",
        "PASSKEY_ERROR",
      );
    }

    const response = assertion.response;
    if (!isRecord(response)) {
      throw new GuardhouseClientError(
        "Passkey assertion result is missing response payload",
        "PASSKEY_ERROR",
      );
    }

    const clientDataJSON = trimToUndefined(
      typeof response.clientDataJSON === "string"
        ? response.clientDataJSON
        : undefined,
    );
    const authenticatorData = trimToUndefined(
      typeof response.authenticatorData === "string"
        ? response.authenticatorData
        : undefined,
    );
    const signature = trimToUndefined(
      typeof response.signature === "string" ? response.signature : undefined,
    );

    if (!clientDataJSON || !authenticatorData || !signature) {
      throw new GuardhouseClientError(
        "Passkey assertion result is missing required WebAuthn fields",
        "PASSKEY_ERROR",
      );
    }
  }

  private async persistPendingBrowserFlow(
    codeVerifier: string,
    state: string,
    nonce: string,
    appState?: Record<string, unknown>,
  ): Promise<void> {
    this.pendingBrowserFlow = {
      codeVerifier,
      state,
      nonce,
      appState,
    };
  }

  private async clearPendingBrowserFlow(): Promise<void> {
    this.pendingBrowserFlow = null;
  }

  private readStoredAppState(): Record<string, unknown> | undefined {
    return this.pendingBrowserFlow?.appState;
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

  private async getStoredRefreshToken(): Promise<string | null> {
    if (this.refreshTokenCache) {
      return this.refreshTokenCache;
    }

    const persistedRefreshToken = trimToUndefined(
      await this.refreshTokenStorage.getItem(STORAGE_KEYS.REFRESH_TOKEN),
    );

    this.refreshTokenCache = persistedRefreshToken ?? null;
    return this.refreshTokenCache;
  }

  private async persistRefreshToken(
    refreshToken: string | undefined,
  ): Promise<void> {
    const normalizedRefreshToken = trimToUndefined(refreshToken);
    this.refreshTokenCache = normalizedRefreshToken ?? null;

    if (!normalizedRefreshToken) {
      await this.refreshTokenStorage.removeItem(STORAGE_KEYS.REFRESH_TOKEN);
      return;
    }

    await this.refreshTokenStorage.setItem(
      STORAGE_KEYS.REFRESH_TOKEN,
      normalizedRefreshToken,
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

    const parsedUser = this.parseStoredUser(userRaw);

    this.sessionCache = {
      accessToken,
      idToken: trimToUndefined(idTokenRaw),
      tokenType: trimToUndefined(tokenTypeRaw) ?? "Bearer",
      scope: trimToUndefined(scopeRaw),
      expiresAt,
      user: parsedUser,
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

  private parseStoredUser(serialized: string | null): CoreUser | null {
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

  private shouldClearSessionAfterRefreshFailure(error: unknown): boolean {
    if (!(error instanceof GuardhouseClientError)) {
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

  private toRevokeError(error: unknown): GuardhouseClientError {
    if (error instanceof GuardhouseClientError) {
      return error;
    }

    return new GuardhouseClientError(
      `Token revocation failed: ${toErrorMessage(error)}`,
      "REVOCATION_FAILED",
      undefined,
      error,
    );
  }

  private async postJson(
    url: string,
    body: Record<string, unknown>,
    operationLabel: string,
    errorCode: GuardhouseClientErrorCode,
  ): Promise<unknown> {
    let response: Response;

    try {
      response = await this.fetchFn(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify(body),
      });
    } catch (error) {
      throw new GuardhouseClientError(
        `${operationLabel} failed due to a network error`,
        "NETWORK_ERROR",
        undefined,
        error,
      );
    }

    const payload = await this.readResponsePayload(response);

    if (!response.ok) {
      throw new GuardhouseClientError(
        `${operationLabel} failed`,
        errorCode,
        response.status,
        payload,
      );
    }

    return payload;
  }

  private async readResponsePayload(response: Response): Promise<unknown> {
    const responseText = await response.text();
    if (!responseText) {
      return undefined;
    }

    try {
      return JSON.parse(responseText) as unknown;
    } catch {
      return responseText;
    }
  }

  private resolveEndpoint(endpoint: string): string {
    const normalizedEndpoint = this.requireString(endpoint, "endpoint");

    try {
      return new URL(normalizedEndpoint, this.authority).toString();
    } catch (error) {
      throw new GuardhouseClientError(
        `Invalid endpoint URL: ${toErrorMessage(error)}`,
        "CONFIG_ERROR",
      );
    }
  }

  private resolveAudience(audience: string | undefined): string | undefined {
    return trimToUndefined(audience) ?? this.defaultAudience;
  }

  private requireBrowserAdapter(): GuardhouseBrowserAdapter {
    if (!this.browser) {
      throw new GuardhouseClientError(
        "No browser adapter configured",
        "BROWSER_ADAPTER_MISSING",
      );
    }

    return this.browser;
  }

  private requirePasskeyAdapter(): GuardhousePasskeyAdapter {
    if (!this.passkey) {
      throw new GuardhouseClientError(
        "No passkey adapter configured",
        "PASSKEY_ADAPTER_MISSING",
      );
    }

    return this.passkey;
  }

  private isExpired(expiresAt: number, minValiditySeconds: number): boolean {
    const now = Math.floor(Date.now() / 1000);
    return expiresAt <= now + minValiditySeconds;
  }

  private readStringFromCandidates(
    source: Record<string, unknown>,
    keys: string[],
  ): string | undefined {
    for (const key of keys) {
      const candidate = source[key];
      if (typeof candidate !== "string") {
        continue;
      }

      const normalized = trimToUndefined(candidate);
      if (normalized) {
        return normalized;
      }
    }

    return undefined;
  }

  private requireString(value: string, fieldName: string): string {
    const normalized = trimToUndefined(value);

    if (!normalized) {
      throw new GuardhouseClientError(
        `${fieldName} is required`,
        "CONFIG_ERROR",
      );
    }

    return normalized;
  }
}
