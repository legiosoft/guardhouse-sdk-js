import type {
  BrowserLoginOptions,
  ExchangeCodeForTokensOptions,
  GetAccessTokenOptions,
  GuardhouseAuthResult,
  GuardhouseClientConfig,
  GuardhouseClientEndpoints,
  GuardhouseLogoutOptions,
  GuardhouseSession,
  LoginWithPasskeyOptions,
  RedirectTokenPayload,
  RefreshTokenOptions,
  RestoreSessionOptions,
} from "../types/index";
import { GuardhouseConfigurationError } from "../types/errors";
import {
  GuardhouseClient as CoreGuardhouseClient,
  setCryptoAdapter,
} from "@guardhouse/core";
import {
  ChunkedSecureStore,
  KeychainStorageAdapter,
  type GuardhouseStorageAdapter,
} from "../adapters/StorageAdapter";
import {
  InAppBrowserAuthAdapter,
  type GuardhouseBrowserAdapter,
} from "../adapters/BrowserAdapter";
import { resolveReactNativeCryptoAdapter } from "../crypto";
import { createLogger } from "../utils/logger";
import {
  resolveEndpoint,
  sanitizeAuthority,
  trimToUndefined,
} from "../utils/url";
import { AuthManager } from "./AuthManager";
import { PasskeyManager } from "./PasskeyManager";

const DEFAULT_SCOPE = "openid profile offline_access";

const DEFAULT_ENDPOINTS = {
  authorization: "/connect/authorize",
  registration: "/account/signup",
  token: "/connect/token",
  userInfo: "/connect/userinfo",
  revocation: "/connect/revocation",
  passkeyChallenge: "/connect/webauthn/challenge",
  passkeyAssertion: "/connect/webauthn/verify",
} as const;

function ensureChunkedStorage(
  storage: GuardhouseStorageAdapter,
  chunkSize: number,
): GuardhouseStorageAdapter {
  if (storage instanceof ChunkedSecureStore) {
    return storage;
  }

  return new ChunkedSecureStore(storage, chunkSize);
}

/**
 * Main SDK facade. Delegates auth and passkey responsibilities to dedicated managers.
 */
export class GuardhouseClient {
  private readonly authManager: AuthManager;
  private readonly passkeyManager: PasskeyManager;

  constructor(config: GuardhouseClientConfig) {
    if (!config || typeof config !== "object") {
      throw new GuardhouseConfigurationError(
        "GuardhouseClient configuration is required",
      );
    }

    const authority = sanitizeAuthority(
      this.requireString(config.authority, "authority"),
    );
    const clientId = this.requireString(config.clientId, "clientId");
    const redirectUri = this.requireString(config.redirectUri, "redirectUri");
    const defaultScope = trimToUndefined(config.scope) ?? DEFAULT_SCOPE;
    const defaultAudience = trimToUndefined(config.audience);
    const defaultEphemeralSession = config.defaultEphemeralSession ?? false;
    const userInfoOnLogin = config.userInfoOnLogin ?? true;
    const debug = config.debug ?? false;
    const logger = createLogger("GuardhouseClient", debug);

    const fetchImpl = config.fetch ?? globalThis.fetch;

    if (typeof fetchImpl !== "function") {
      throw new GuardhouseConfigurationError(
        "No fetch implementation available. Pass fetch in GuardhouseClientConfig.",
      );
    }

    const cryptoAdapter = resolveReactNativeCryptoAdapter(
      config.cryptoAdapter,
      debug,
    );

    setCryptoAdapter(cryptoAdapter);

    const endpoints = this.resolveEndpoints(authority, config.endpoints);
    const chunkSize =
      config.chunkSize && config.chunkSize > 0 ? config.chunkSize : 2000;

    const coreClient = new CoreGuardhouseClient({
      authority,
      clientId,
      redirectUri,
      scope: defaultScope,
      tokenEndpoint: endpoints.token,
      userInfoEndpoint: endpoints.userInfo,
      revocationEndpoint: endpoints.revocation,
      debug,
    });

    const refreshStorageBase =
      config.refreshTokenStorage ??
      config.storage ??
      new KeychainStorageAdapter(config.requireBiometrics ?? false, debug);
    const refreshTokenStorage = ensureChunkedStorage(
      refreshStorageBase,
      chunkSize,
    );

    const sessionStorage = config.sessionStorage
      ? ensureChunkedStorage(config.sessionStorage, chunkSize)
      : undefined;

    const browser: GuardhouseBrowserAdapter =
      config.browser ?? new InAppBrowserAuthAdapter(debug);

    this.authManager = new AuthManager({
      authority,
      clientId,
      redirectUri,
      defaultScope,
      defaultAudience,
      defaultEphemeralSession,
      userInfoOnLogin,
      authorizationEndpoint: endpoints.authorization,
      registrationEndpoint: endpoints.registration,
      tokenEndpoint: endpoints.token,
      coreClient,
      browser,
      cryptoAdapter,
      refreshTokenStorage,
      sessionStorage,
      logger,
    });

    this.passkeyManager = new PasskeyManager({
      clientId,
      defaultScope,
      defaultAudience,
      passkeyChallengeEndpoint: endpoints.passkeyChallenge,
      passkeyAssertionEndpoint: endpoints.passkeyAssertion,
      fetch: fetchImpl,
      passkey: config.passkey,
      logger,
      persistTokenResponse: (tokenResponse) =>
        this.authManager.persistTokenResponse(tokenResponse),
    });
  }

  /**
   * Starts browser-based login (Authorization Code + PKCE) through `AuthManager`.
   */
  loginWithBrowser(
    options: BrowserLoginOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.authManager.loginWithBrowser(options);
  }

  /**
   * Starts browser-based registration through `AuthManager`.
   */
  registerWithBrowser(
    options: BrowserLoginOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.authManager.registerWithBrowser(options);
  }

  /**
   * Exchanges an OAuth authorization code for tokens via `@guardhouse/core`.
   */
  exchangeCodeForTokens(
    code: string,
    options: ExchangeCodeForTokensOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.authManager.exchangeCodeForTokens(code, options);
  }

  /**
   * Persists tokens provided directly by deep link callback payloads.
   */
  applyRedirectTokens(
    payload: RedirectTokenPayload,
  ): Promise<GuardhouseAuthResult> {
    return this.authManager.applyRedirectTokens(payload);
  }

  /**
   * Executes headless passkey authentication flow.
   */
  loginWithPasskey(
    options: LoginWithPasskeyOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.passkeyManager.loginWithPasskey(options);
  }

  /**
   * Refreshes tokens using stored refresh token.
   */
  refreshToken(
    options: RefreshTokenOptions = {},
  ): Promise<GuardhouseAuthResult> {
    return this.authManager.refreshToken(options);
  }

  /**
   * Restores a valid session from cache/storage and refreshes if needed.
   */
  restoreSession(
    options: RestoreSessionOptions = {},
  ): Promise<GuardhouseAuthResult | null> {
    return this.authManager.restoreSession(options);
  }

  /**
   * Returns current normalized session if available.
   */
  getSession(): Promise<GuardhouseSession | null> {
    return this.authManager.getSession();
  }

  /**
   * Returns a valid access token and optionally auto-refreshes.
   */
  getAccessToken(options: GetAccessTokenOptions = {}): Promise<string | null> {
    return this.authManager.getAccessToken(options);
  }

  /**
   * Logs out locally and optionally revokes tokens on server.
   */
  logout(options: GuardhouseLogoutOptions = {}): Promise<void> {
    return this.authManager.logout(options);
  }

  private resolveEndpoints(
    authority: string,
    overrides?: Partial<GuardhouseClientEndpoints>,
  ): GuardhouseClientEndpoints {
    const configured = overrides ?? {};

    return {
      authorization: resolveEndpoint(
        authority,
        configured.authorization ?? DEFAULT_ENDPOINTS.authorization,
      ),
      registration: resolveEndpoint(
        authority,
        configured.registration ?? DEFAULT_ENDPOINTS.registration,
      ),
      token: resolveEndpoint(
        authority,
        configured.token ?? DEFAULT_ENDPOINTS.token,
      ),
      userInfo: resolveEndpoint(
        authority,
        configured.userInfo ?? DEFAULT_ENDPOINTS.userInfo,
      ),
      revocation: resolveEndpoint(
        authority,
        configured.revocation ?? DEFAULT_ENDPOINTS.revocation,
      ),
      passkeyChallenge: resolveEndpoint(
        authority,
        configured.passkeyChallenge ?? DEFAULT_ENDPOINTS.passkeyChallenge,
      ),
      passkeyAssertion: resolveEndpoint(
        authority,
        configured.passkeyAssertion ?? DEFAULT_ENDPOINTS.passkeyAssertion,
      ),
    };
  }

  private requireString(value: string, fieldName: string): string {
    const normalized = trimToUndefined(value);

    if (normalized) {
      return normalized;
    }

    throw new GuardhouseConfigurationError(`${fieldName} is required`);
  }
}
