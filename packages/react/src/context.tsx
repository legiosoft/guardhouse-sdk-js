import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  GuardhouseClient,
  generateAuthUrl,
  generateNonce,
  generatePKCE,
  generateState,
  setGuardhouseDebug,
} from "@guardhouse/core";
import type {
  GuardhouseConfig as CoreGuardhouseConfig,
  User as CoreUser,
} from "@guardhouse/core";
import type {
  AppState,
  AuthState,
  GuardhouseConfig,
  LoginOptions,
  LogoutOptions,
  OidcSessionData,
  StorageAdapter,
  TokenData,
} from "./types";
import {
  SessionStorageAdapter,
  StorageKeys,
  parseQueryParams,
  removeQueryParams,
  validateIdToken,
} from "./utils";
import { createReactLogger } from "./debug";

const DEFAULT_SCOPE = "openid profile email";
const ACCESS_TOKEN_REFRESH_LEEWAY_SECONDS = 60;

interface AuthContextValue extends AuthState {
  loginWithRedirect: (options?: LoginOptions) => Promise<void>;
  logout: (options?: LogoutOptions) => Promise<void>;
  getAccessToken: () => Promise<string | null>;
  getAccessTokenSilently: () => Promise<string | null>;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  user: CoreUser | null;
}

const AuthContext = createContext<AuthContextValue | null>(null);

interface GuardhouseProviderProps {
  config: GuardhouseConfig;
  children: ReactNode;
}

function scopeContains(scope: string | undefined, value: string): boolean {
  if (!scope) {
    return false;
  }

  return scope
    .trim()
    .split(/\s+/)
    .some((entry) => entry.toLowerCase() === value.toLowerCase());
}

function parseStoredOidcSession(
  serializedSession: string | null,
): OidcSessionData | null {
  if (!serializedSession) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(serializedSession);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const candidate = parsed as Record<string, unknown>;
  const user = candidate["user"];
  const oidc = candidate["oidc"];

  if (
    typeof candidate["accessToken"] !== "string" ||
    candidate["accessToken"].trim() === "" ||
    typeof candidate["tokenType"] !== "string" ||
    candidate["tokenType"].trim() === "" ||
    typeof candidate["expiresAt"] !== "number" ||
    !Number.isFinite(candidate["expiresAt"]) ||
    !user ||
    typeof user !== "object" ||
    typeof (user as Record<string, unknown>)["sub"] !== "string" ||
    !oidc ||
    typeof oidc !== "object" ||
    typeof (oidc as Record<string, unknown>)["issuer"] !== "string"
  ) {
    return null;
  }

  const refreshToken = candidate["refreshToken"];
  const idToken = candidate["idToken"];
  const scope = candidate["scope"];
  const audience = (oidc as Record<string, unknown>)["audience"];
  const sessionState = (oidc as Record<string, unknown>)["sessionState"];

  return {
    accessToken: candidate["accessToken"],
    tokenType: candidate["tokenType"],
    expiresAt: candidate["expiresAt"],
    refreshToken:
      typeof refreshToken === "string" && refreshToken.trim() !== ""
        ? refreshToken
        : undefined,
    idToken:
      typeof idToken === "string" && idToken.trim() !== ""
        ? idToken
        : undefined,
    scope: typeof scope === "string" && scope.trim() !== "" ? scope : undefined,
    user: user as CoreUser,
    oidc: {
      issuer: (oidc as Record<string, unknown>)["issuer"] as string,
      audience:
        typeof audience === "string" && audience.trim() !== ""
          ? audience
          : undefined,
      sessionState:
        typeof sessionState === "string" && sessionState.trim() !== ""
          ? sessionState
          : undefined,
    },
  };
}

export function GuardhouseProvider({
  config,
  children,
}: GuardhouseProviderProps) {
  const [state, setState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
    error: null,
    user: null,
  });

  const storage: StorageAdapter = useMemo(
    () => new SessionStorageAdapter(),
    [],
  );
  const logger = useMemo(
    () => createReactLogger("Provider", config.debug),
    [config.debug],
  );

  const clientConfig = useMemo<CoreGuardhouseConfig>(
    () => ({
      authority: config.authority,
      clientId: config.clientId,
      scope: config.scope,
      tokenEndpoint: config.tokenEndpoint,
      userInfoEndpoint: config.userInfoEndpoint,
      introspectionEndpoint: config.introspectionEndpoint,
      revocationEndpoint: config.revocationEndpoint,
      requestTimeoutMs: config.requestTimeoutMs,
      discoveryCacheTtlMs: config.discoveryCacheTtlMs,
      allowScopeNarrowing: config.allowScopeNarrowing,
      maxAuthorizationHeaderBytes: config.maxAuthorizationHeaderBytes,
      maxSilentAuthAttempts: config.maxSilentAuthAttempts,
      requireUserInteractionForSensitiveOperations:
        config.requireUserInteractionForSensitiveOperations,
      allowedPostLogoutRedirectUris: config.allowedPostLogoutRedirectUris,
      allowUnsafeHttpMethods: config.allowUnsafeHttpMethods,
      requireDpopForAccessTokenRequests:
        config.requireDpopForAccessTokenRequests,
      dpopProofFactory: config.dpopProofFactory,
      debug: config.debug,
    }),
    [
      config.allowScopeNarrowing,
      config.allowUnsafeHttpMethods,
      config.allowedPostLogoutRedirectUris,
      config.authority,
      config.clientId,
      config.debug,
      config.discoveryCacheTtlMs,
      config.dpopProofFactory,
      config.introspectionEndpoint,
      config.maxAuthorizationHeaderBytes,
      config.maxSilentAuthAttempts,
      config.requestTimeoutMs,
      config.requireDpopForAccessTokenRequests,
      config.requireUserInteractionForSensitiveOperations,
      config.revocationEndpoint,
      config.scope,
      config.tokenEndpoint,
      config.userInfoEndpoint,
    ],
  );

  const client = useMemo(
    () => new GuardhouseClient(clientConfig),
    [clientConfig],
  );

  useEffect(() => {
    setGuardhouseDebug(Boolean(config.debug));
    logger.info("Debug mode updated", { enabled: Boolean(config.debug) });
  }, [config.debug, logger]);

  const handleError = useCallback(
    (error: string) => {
      logger.error("Authentication flow failed", { error });

      setState((prev) => ({
        ...prev,
        isLoading: false,
        error,
        isAuthenticated: false,
        user: null,
      }));
    },
    [logger],
  );

  const handleSuccess = useCallback(
    (user: CoreUser, tokenData?: TokenData) => {
      logger.debug("Updating auth state to authenticated", {
        subject: user.sub,
        hasTokenData: Boolean(tokenData),
      });

      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: null,
        isAuthenticated: true,
        user,
      }));

      logger.info("Authentication flow completed", {
        subject: user.sub,
      });
    },
    [logger],
  );

  const handleLoading = useCallback(() => {
    logger.debug("Authentication flow loading state enabled");
    setState((prev) => ({ ...prev, isLoading: true }));
  }, [logger]);

  const clearTransientLoginState = useCallback(async () => {
    await storage.removeItem(StorageKeys.CODE_VERIFIER);
    await storage.removeItem(StorageKeys.STATE);
    await storage.removeItem(StorageKeys.NONCE);
    await storage.removeItem(StorageKeys.REQUESTED_SCOPE);
    await storage.removeItem(StorageKeys.REQUESTED_AUDIENCE);
    await storage.removeItem(StorageKeys.PROMPT);
    await storage.removeItem(StorageKeys.APP_STATE);
  }, [storage]);

  const clearAuthState = useCallback(async () => {
    logger.debug("Clearing stored auth state from session storage");

    await storage.removeItem(StorageKeys.OIDC_SESSION);

    await storage.removeItem(StorageKeys.ACCESS_TOKEN);
    await storage.removeItem(StorageKeys.REFRESH_TOKEN);
    await storage.removeItem(StorageKeys.ID_TOKEN);
    await storage.removeItem(StorageKeys.EXPIRES_AT);
    await storage.removeItem(StorageKeys.USER);

    await clearTransientLoginState();
    await client.clearSessionState();
  }, [clearTransientLoginState, client, logger, storage]);

  const readStoredOidcSession =
    useCallback(async (): Promise<OidcSessionData | null> => {
      const serializedSession = await storage.getItem(StorageKeys.OIDC_SESSION);
      return parseStoredOidcSession(serializedSession);
    }, [storage]);

  const persistOidcSession = useCallback(
    async (sessionData: OidcSessionData): Promise<void> => {
      await storage.setItem(
        StorageKeys.OIDC_SESSION,
        JSON.stringify(sessionData),
      );
    },
    [storage],
  );

  const refreshSession = useCallback(
    async (sessionData: OidcSessionData): Promise<OidcSessionData | null> => {
      if (!sessionData.refreshToken) {
        await clearAuthState();
        return null;
      }

      try {
        const tokenResponse = await client.refreshToken(
          sessionData.refreshToken,
        );

        const refreshedSession: OidcSessionData = {
          ...sessionData,
          accessToken: tokenResponse.access_token,
          refreshToken: tokenResponse.refresh_token || sessionData.refreshToken,
          idToken: tokenResponse.id_token || sessionData.idToken,
          tokenType: tokenResponse.token_type,
          scope: tokenResponse.scope || sessionData.scope,
          expiresAt: Math.floor(Date.now() / 1000) + tokenResponse.expires_in,
        };

        await persistOidcSession(refreshedSession);

        logger.info("Silent token refresh succeeded", {
          expiresAt: refreshedSession.expiresAt,
        });

        return refreshedSession;
      } catch (error) {
        logger.error("Token refresh failed", {
          error: String(error),
        });
        await clearAuthState();
        return null;
      }
    },
    [clearAuthState, client, logger, persistOidcSession],
  );

  const handleCallback = useCallback(async () => {
    const searchParams = parseQueryParams(window.location.search);
    const hashParams = parseQueryParams(
      window.location.hash.startsWith("#")
        ? `?${window.location.hash.slice(1)}`
        : window.location.hash,
    );

    const hasAuthResponse = Boolean(
      searchParams["code"] ||
      searchParams["error"] ||
      hashParams["code"] ||
      hashParams["error"],
    );

    if (!hasAuthResponse) {
      logger.debug("No authorization callback parameters found");
      setState((prev) => ({ ...prev, isLoading: false }));
      return;
    }

    try {
      handleLoading();

      const storedState = await storage.getItem(StorageKeys.STATE);
      if (!storedState) {
        throw new Error("State parameter missing in session storage");
      }

      const codeVerifier = await storage.getItem(StorageKeys.CODE_VERIFIER);
      if (!codeVerifier) {
        throw new Error("Code verifier not found in session storage");
      }

      const nonce = await storage.getItem(StorageKeys.NONCE);
      const requestedScope = await storage.getItem(StorageKeys.REQUESTED_SCOPE);
      const requestedAudience = await storage.getItem(
        StorageKeys.REQUESTED_AUDIENCE,
      );
      const prompt = await storage.getItem(StorageKeys.PROMPT);

      const callback = await client.validateOAuthCallback(
        window.location.href,
        storedState,
        prompt || undefined,
      );

      if (!callback.code) {
        throw new Error("OAuth callback did not include an authorization code");
      }

      const tokenData = await client.exchangeCodeForTokens(
        callback.code,
        codeVerifier,
        config.redirectUri,
      );

      logger.debug("Token exchange succeeded", {
        expiresIn: tokenData.expires_in,
        hasRefreshToken: Boolean(tokenData.refresh_token),
        hasIdToken: Boolean(tokenData.id_token),
      });

      let fallbackUserFromIdToken: CoreUser | null = null;

      if (tokenData.id_token && nonce) {
        try {
          const idTokenPayload = validateIdToken(
            tokenData.id_token,
            nonce,
            config.authority,
            config.clientId,
          );
          fallbackUserFromIdToken = idTokenPayload as CoreUser;
        } catch (idTokenError) {
          logger.warn("ID token validation failed", {
            error: String(idTokenError),
          });
        }
      }

      let authenticatedUser: CoreUser | null = null;

      try {
        authenticatedUser = await client.getUserInfo(tokenData.access_token);
      } catch (userInfoError) {
        logger.warn("Failed to fetch user info", {
          error: String(userInfoError),
        });

        if (fallbackUserFromIdToken) {
          authenticatedUser = fallbackUserFromIdToken;
        }
      }

      if (!authenticatedUser) {
        throw new Error(
          "Failed to load user profile. Ensure the client allows openid/profile scopes and /connect/userinfo.",
        );
      }

      const oidcSession: OidcSessionData = {
        accessToken: tokenData.access_token,
        tokenType: tokenData.token_type,
        expiresAt: Math.floor(Date.now() / 1000) + tokenData.expires_in,
        refreshToken: tokenData.refresh_token,
        idToken: tokenData.id_token,
        scope: tokenData.scope || requestedScope || config.scope,
        user: authenticatedUser,
        oidc: {
          issuer: config.authority,
          audience: requestedAudience || config.audience,
          sessionState:
            typeof callback.params["session_state"] === "string"
              ? callback.params["session_state"]
              : undefined,
        },
      };

      await persistOidcSession(oidcSession);
      handleSuccess(authenticatedUser, tokenData);

      if (config.onRedirectCallback) {
        const appStateRaw = await storage.getItem(StorageKeys.APP_STATE);

        if (appStateRaw) {
          try {
            const appState = JSON.parse(appStateRaw) as AppState;
            config.onRedirectCallback(appState);
          } catch {
            config.onRedirectCallback();
          }
        } else {
          config.onRedirectCallback();
        }
      }

      logger.info("OAuth callback handled successfully", {
        subject: authenticatedUser.sub,
      });

      removeQueryParams();
    } catch (error) {
      handleError(
        error instanceof Error ? error.message : "Unknown error occurred",
      );
      await clearAuthState();
      removeQueryParams();
    } finally {
      await clearTransientLoginState();
    }
  }, [
    clearAuthState,
    clearTransientLoginState,
    client,
    config.audience,
    config.authority,
    config.clientId,
    config.onRedirectCallback,
    config.redirectUri,
    config.scope,
    handleError,
    handleLoading,
    handleSuccess,
    logger,
    persistOidcSession,
    storage,
  ]);

  const checkSession = useCallback(async () => {
    try {
      handleLoading();
      logger.debug("Checking existing session in session storage");

      const sessionData = await readStoredOidcSession();

      if (!sessionData) {
        logger.debug("No active OIDC session found");
        setState((prev) => ({ ...prev, isLoading: false }));
        return;
      }

      const now = Math.floor(Date.now() / 1000);

      if (sessionData.expiresAt <= now) {
        logger.info("Stored OIDC session has expired", {
          expiresAt: sessionData.expiresAt,
          now,
        });

        const refreshedSession = await refreshSession(sessionData);

        if (!refreshedSession) {
          setState((prev) => ({
            ...prev,
            isLoading: false,
            isAuthenticated: false,
            user: null,
          }));
          return;
        }

        handleSuccess(refreshedSession.user);
        return;
      }

      handleSuccess(sessionData.user);

      logger.info("Restored authenticated session", {
        subject: sessionData.user.sub,
      });
    } catch (error) {
      logger.error("Session check failed", {
        error: String(error),
      });
      await clearAuthState();
      setState((prev) => ({
        ...prev,
        isLoading: false,
        isAuthenticated: false,
        user: null,
      }));
    }
  }, [
    clearAuthState,
    handleLoading,
    handleSuccess,
    logger,
    readStoredOidcSession,
    refreshSession,
  ]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    logger.debug("Initializing Guardhouse React provider");

    const searchParams = parseQueryParams(window.location.search);
    const hashParams = parseQueryParams(
      window.location.hash.startsWith("#")
        ? `?${window.location.hash.slice(1)}`
        : window.location.hash,
    );

    const hasAuthResponse = Boolean(
      searchParams["code"] ||
      searchParams["error"] ||
      hashParams["code"] ||
      hashParams["error"],
    );

    if (hasAuthResponse) {
      void handleCallback();
      return;
    }

    void checkSession();
  }, [checkSession, handleCallback, logger]);

  const loginWithRedirect = useCallback(
    async (options?: LoginOptions) => {
      try {
        logger.info("Starting redirect login flow");

        const requestedScope =
          options?.scope?.trim() || config.scope || DEFAULT_SCOPE;
        const requestedAudience =
          options?.audience?.trim() || config.audience?.trim();
        const responseType = (config.responseType || "code").trim();
        const hasCodeResponseType = responseType
          .split(/\s+/)
          .some((entry) => entry === "code");

        if (
          hasCodeResponseType &&
          !requestedAudience &&
          !config.requestUri &&
          !config.allowAuthorizationWithoutAudience
        ) {
          throw new Error(
            "audience is required for authorization code flow unless requestUri is configured or allowAuthorizationWithoutAudience=true",
          );
        }

        if (
          scopeContains(requestedScope, "offline_access") &&
          !config.allowOfflineAccessScope
        ) {
          throw new Error(
            "offline_access scope requires allowOfflineAccessScope=true",
          );
        }

        const { codeVerifier, codeChallenge } = await generatePKCE({
          debug: config.debug,
        });
        const stateToken = await generateState(18, config.debug);
        const nonce = await generateNonce(18, config.debug);

        await storage.setItem(StorageKeys.CODE_VERIFIER, codeVerifier);
        await storage.setItem(StorageKeys.STATE, stateToken);
        await storage.setItem(StorageKeys.NONCE, nonce);
        await storage.setItem(StorageKeys.REQUESTED_SCOPE, requestedScope);

        if (requestedAudience) {
          await storage.setItem(
            StorageKeys.REQUESTED_AUDIENCE,
            requestedAudience,
          );
        } else {
          await storage.removeItem(StorageKeys.REQUESTED_AUDIENCE);
        }

        if (options?.prompt) {
          await storage.setItem(StorageKeys.PROMPT, options.prompt);
        } else {
          await storage.removeItem(StorageKeys.PROMPT);
        }

        if (options?.appState) {
          await storage.setItem(
            StorageKeys.APP_STATE,
            JSON.stringify(options.appState),
          );

          logger.debug("Stored app state for post-login redirect", {
            returnTo: options.appState.returnTo,
          });
        } else {
          await storage.removeItem(StorageKeys.APP_STATE);
        }

        const authUrl = generateAuthUrl({
          authority: config.authority,
          authorizationEndpoint: config.authorizationEndpoint,
          clientId: config.clientId,
          redirectUri: config.redirectUri,
          requestUri: config.requestUri,
          debug: config.debug,
          responseType,
          scope: requestedScope,
          allowOfflineAccessScope: Boolean(config.allowOfflineAccessScope),
          allowAuthorizationWithoutAudience: Boolean(
            config.allowAuthorizationWithoutAudience,
          ),
          state: stateToken,
          codeChallenge,
          codeChallengeMethod: "S256",
          nonce,
          prompt: options?.prompt,
          audience: requestedAudience,
        });

        logger.debug("Redirecting browser to authorization endpoint", {
          authority: config.authority,
        });

        window.location.href = authUrl;
      } catch (error) {
        await clearTransientLoginState();
        handleError(error instanceof Error ? error.message : "Login failed");
      }
    },
    [
      clearTransientLoginState,
      config.allowOfflineAccessScope,
      config.allowAuthorizationWithoutAudience,
      config.audience,
      config.authority,
      config.authorizationEndpoint,
      config.clientId,
      config.debug,
      config.redirectUri,
      config.requestUri,
      config.responseType,
      config.scope,
      handleError,
      logger,
      storage,
    ],
  );

  const logout = useCallback(
    async (options?: LogoutOptions) => {
      const returnTo =
        options?.returnTo ||
        config.logoutRedirectUri ||
        config.redirectUri ||
        window.location.origin;

      logger.info("Starting logout flow", {
        returnTo,
      });

      const currentSession = await readStoredOidcSession();

      const logoutState = await generateState(18, config.debug);
      const logoutUrl = client.buildLogoutUrl({
        postLogoutRedirectUri: returnTo,
        idTokenHint: currentSession?.idToken,
        state: logoutState,
        federated: options?.federated,
      });

      logger.debug("Clearing local auth state before redirecting to logout");
      await clearAuthState();

      logger.debug("Redirecting browser to logout endpoint", {
        authority: config.authority,
      });
      window.location.href = logoutUrl;
    },
    [
      clearAuthState,
      client,
      config.authority,
      config.debug,
      config.logoutRedirectUri,
      logger,
      readStoredOidcSession,
    ],
  );

  const getAccessTokenSilently = useCallback(async (): Promise<
    string | null
  > => {
    logger.debug("Attempting silent access token retrieval");

    const sessionData = await readStoredOidcSession();

    if (!sessionData) {
      logger.debug("No OIDC session available for silent retrieval");
      return null;
    }

    const now = Math.floor(Date.now() / 1000);

    if (sessionData.expiresAt > now + ACCESS_TOKEN_REFRESH_LEEWAY_SECONDS) {
      logger.debug("Using existing access token for silent retrieval", {
        expiresAt: sessionData.expiresAt,
      });
      return sessionData.accessToken;
    }

    if (!sessionData.refreshToken) {
      logger.warn("Silent token retrieval failed: missing refresh token");
      await clearAuthState();
      return null;
    }

    const refreshedSession = await refreshSession(sessionData);

    if (!refreshedSession) {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        isAuthenticated: false,
        user: null,
      }));
      return null;
    }

    setState((prev) => ({
      ...prev,
      isLoading: false,
      isAuthenticated: true,
      error: null,
      user: refreshedSession.user,
    }));

    return refreshedSession.accessToken;
  }, [clearAuthState, logger, readStoredOidcSession, refreshSession]);

  const getAccessToken = useCallback(async (): Promise<string | null> => {
    const sessionData = await readStoredOidcSession();

    if (!sessionData) {
      logger.debug("No access token available in session storage");
      return null;
    }

    const now = Math.floor(Date.now() / 1000);
    if (sessionData.expiresAt > now + ACCESS_TOKEN_REFRESH_LEEWAY_SECONDS) {
      return sessionData.accessToken;
    }

    return getAccessTokenSilently();
  }, [getAccessTokenSilently, logger, readStoredOidcSession]);

  const contextValue: AuthContextValue = {
    ...state,
    loginWithRedirect,
    logout,
    getAccessToken,
    getAccessTokenSilently,
  };

  return (
    <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used within a GuardhouseProvider");
  }

  return context;
}
