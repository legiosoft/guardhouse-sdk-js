import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useMemo,
  ReactNode,
} from "react";
import {
  generateAuthUrl,
  generatePKCE,
  setGuardhouseDebug,
} from "@guardhouse/core";
import type { User as CoreUser } from "@guardhouse/core";
import {
  GuardhouseConfig,
  AuthState,
  TokenData,
  LoginOptions,
  LogoutOptions,
  StorageAdapter,
} from "./types";
import {
  LocalStorageAdapter,
  SessionStorageAdapter,
  StorageKeys,
  generateBase64UrlEncodedString,
  parseQueryParams,
  removeQueryParams,
  validateIdToken,
} from "./utils";
import { createReactLogger } from "./debug";

interface AuthContextValue extends AuthState {
  loginWithRedirect: (options?: LoginOptions) => Promise<void>;
  logout: (options?: LogoutOptions) => void;
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
    () => config.storage || new LocalStorageAdapter(),
    [config.storage],
  );
  const sessionStorage = useMemo(() => new SessionStorageAdapter(), []);
  const logger = useMemo(
    () => createReactLogger("Provider", config.debug),
    [config.debug],
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

      if (tokenData && config.onRedirectCallback) {
        logger.debug("Running redirect callback");
        config.onRedirectCallback();
      }

      logger.info("Authentication flow completed", {
        subject: user.sub,
      });
    },
    [config.onRedirectCallback, logger],
  );

  const handleLoading = useCallback(() => {
    logger.debug("Authentication flow loading state enabled");
    setState((prev) => ({ ...prev, isLoading: true }));
  }, [logger]);

  const clearAuthState = useCallback(async () => {
    logger.debug("Clearing stored auth state");
    await storage.removeItem(StorageKeys.ACCESS_TOKEN);
    await storage.removeItem(StorageKeys.REFRESH_TOKEN);
    await storage.removeItem(StorageKeys.ID_TOKEN);
    await storage.removeItem(StorageKeys.EXPIRES_AT);
    await storage.removeItem(StorageKeys.USER);
  }, [storage, logger]);

  const handleCallback = useCallback(async () => {
    const params = parseQueryParams(window.location.search);

    logger.debug("Handling OAuth callback", {
      hasCode: Boolean(params["code"]),
      hasState: Boolean(params["state"]),
      hasError: Boolean(params["error"]),
    });

    const code = params["code"];
    const state = params["state"];
    const error = params["error"];

    if (error) {
      const errorDescription = params["error_description"] || error;
      handleError(errorDescription);
      removeQueryParams();
      return;
    }

    if (!code || !state) {
      logger.debug("No authorization callback parameters found");
      setState((prev) => ({ ...prev, isLoading: false }));
      return;
    }

    try {
      handleLoading();

      const storedState = await sessionStorage.getItem(StorageKeys.STATE);
      if (storedState !== state) {
        logger.warn("State mismatch detected during callback", {
          receivedState: state,
          hasStoredState: Boolean(storedState),
        });
        throw new Error("State parameter mismatch. Possible CSRF attack.");
      }

      const codeVerifier = await sessionStorage.getItem(
        StorageKeys.CODE_VERIFIER,
      );
      if (!codeVerifier) {
        throw new Error("Code verifier not found in session storage");
      }

      logger.debug("State and code verifier validated");

      const nonce = await sessionStorage.getItem(StorageKeys.NONCE);

      await sessionStorage.removeItem(StorageKeys.CODE_VERIFIER);
      await sessionStorage.removeItem(StorageKeys.STATE);
      await sessionStorage.removeItem(StorageKeys.NONCE);

      const tokenEndpoint = `${config.authority}/connect/token`;
      logger.debug("Exchanging authorization code for tokens", {
        tokenEndpoint,
      });

      const response = await fetch(tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: config.redirectUri,
          client_id: config.clientId,
          code_verifier: codeVerifier,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Token exchange failed: ${errorText}`);
      }

      const tokenData: TokenData = await response.json();

      logger.debug("Token exchange succeeded", {
        expiresIn: tokenData.expires_in,
        hasRefreshToken: Boolean(tokenData.refresh_token),
        hasIdToken: Boolean(tokenData.id_token),
      });

      const expiresAt = Math.floor(Date.now() / 1000) + tokenData.expires_in;

      await storage.setItem(StorageKeys.ACCESS_TOKEN, tokenData.access_token);
      await storage.setItem(
        StorageKeys.REFRESH_TOKEN,
        tokenData.refresh_token || "",
      );
      await storage.setItem(StorageKeys.ID_TOKEN, tokenData.id_token || "");
      await storage.setItem(StorageKeys.EXPIRES_AT, expiresAt.toString());

      logger.debug("Token data stored", {
        expiresAt,
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

      const userInfoEndpoint = `${config.authority}/connect/userinfo`;
      const userResponse = await fetch(userInfoEndpoint, {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
        },
      });

      let authenticatedUser: CoreUser | null = null;

      if (!userResponse.ok) {
        const errorText = await userResponse.text();
        logger.warn("Failed to fetch user info", {
          error: errorText,
        });

        if (fallbackUserFromIdToken) {
          authenticatedUser = fallbackUserFromIdToken;
          await storage.setItem(
            StorageKeys.USER,
            JSON.stringify(authenticatedUser),
          );
        }
      } else {
        const userData = await userResponse.json();
        authenticatedUser = userData;
        await storage.setItem(StorageKeys.USER, JSON.stringify(userData));

        logger.debug("User profile fetched", {
          subject: userData?.sub,
        });
      }

      if (!authenticatedUser) {
        throw new Error(
          "Failed to load user profile. Ensure the client allows openid/profile scopes and /connect/userinfo.",
        );
      }

      handleSuccess(authenticatedUser, tokenData);

      logger.info("OAuth callback handled successfully", {
        subject: authenticatedUser.sub,
      });

      removeQueryParams();
    } catch (error) {
      handleError(
        error instanceof Error ? error.message : "Unknown error occurred",
      );
      removeQueryParams();
      await clearAuthState();
    }
  }, [
    config.authority,
    config.clientId,
    config.redirectUri,
    storage,
    sessionStorage,
    handleLoading,
    handleError,
    handleSuccess,
    clearAuthState,
    logger,
  ]);

  const checkSession = useCallback(async () => {
    try {
      handleLoading();
      logger.debug("Checking existing session");

      const accessToken = await storage.getItem(StorageKeys.ACCESS_TOKEN);
      const expiresAt = await storage.getItem(StorageKeys.EXPIRES_AT);
      const userStr = await storage.getItem(StorageKeys.USER);

      if (!accessToken || !userStr) {
        logger.debug("No active session found in storage", {
          hasAccessToken: Boolean(accessToken),
          hasUser: Boolean(userStr),
        });
        setState((prev) => ({ ...prev, isLoading: false }));
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      if (expiresAt && parseInt(expiresAt) < now) {
        logger.info("Stored session has expired", {
          expiresAt,
          now,
        });
        await clearAuthState();
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: false,
          user: null,
        }));
        return;
      }

      const userData: CoreUser = JSON.parse(userStr);
      handleSuccess(userData);

      logger.info("Restored authenticated session", {
        subject: userData.sub,
      });
    } catch (error) {
      logger.error("Session check failed", {
        error: String(error),
      });
      setState((prev) => ({
        ...prev,
        isLoading: false,
        isAuthenticated: false,
        user: null,
      }));
    }
  }, [storage, clearAuthState, handleLoading, handleSuccess, logger]);

  useEffect(() => {
    if (typeof window === "undefined") return;

    logger.debug("Initializing Guardhouse React provider");

    const params = parseQueryParams(window.location.search);

    if (params["code"] && params["state"]) {
      handleCallback();
    } else {
      checkSession();
    }
  }, [handleCallback, checkSession, logger]);

  const loginWithRedirect = useCallback(
    async (options?: LoginOptions) => {
      try {
        logger.info("Starting redirect login flow");

        if (options?.scope) {
          logger.debug("Login scope override provided", {
            scope: options.scope,
          });
        }

        const { codeVerifier, codeChallenge } = await generatePKCE({
          debug: config.debug,
        } as any);
        const state = generateBase64UrlEncodedString(32);
        const nonce = generateBase64UrlEncodedString(32);

        await sessionStorage.setItem(StorageKeys.CODE_VERIFIER, codeVerifier);
        await sessionStorage.setItem(StorageKeys.STATE, state);
        await sessionStorage.setItem(StorageKeys.NONCE, nonce);

        const authUrl = await generateAuthUrl({
          authority: config.authority,
          clientId: config.clientId,
          redirectUri: config.redirectUri,
          debug: config.debug,
          responseType: config.responseType || "code",
          scope: options?.scope || config.scope || "openid profile email",
          state,
          codeChallenge,
          codeChallengeMethod: "S256",
        } as any);

        if (options?.appState?.returnTo) {
          await sessionStorage.setItem(
            "gh_app_state",
            JSON.stringify(options.appState),
          );

          logger.debug("Stored app state for post-login redirect", {
            returnTo: options.appState.returnTo,
          });
        }

        logger.debug("Redirecting browser to authorization endpoint", {
          authority: config.authority,
        });
        window.location.href = authUrl;
      } catch (error) {
        handleError(error instanceof Error ? error.message : "Login failed");
      }
    },
    [config, sessionStorage, handleError, logger],
  );

  const logout = useCallback(
    async (options?: LogoutOptions) => {
      const returnTo =
        options?.returnTo || config.logoutRedirectUri || window.location.origin;

      logger.info("Starting logout flow", {
        returnTo,
      });

      const logoutUrl = new URL(`${config.authority}/connect/endsession`);
      logoutUrl.searchParams.set("post_logout_redirect_uri", returnTo);

      const idToken = await storage.getItem(StorageKeys.ID_TOKEN);
      if (idToken) {
        logoutUrl.searchParams.set("id_token_hint", idToken);
      }

      logger.debug("Clearing local auth state before redirecting to logout");
      await clearAuthState();

      logger.debug("Redirecting browser to logout endpoint", {
        authority: config.authority,
      });
      window.location.href = logoutUrl.toString();
    },
    [config, storage, clearAuthState, logger],
  );

  const getAccessToken = useCallback(async (): Promise<string | null> => {
    const accessToken = await storage.getItem(StorageKeys.ACCESS_TOKEN);

    logger.debug("Retrieved access token from storage", {
      hasAccessToken: Boolean(accessToken),
    });

    return accessToken;
  }, [storage, logger]);

  const getAccessTokenSilently = useCallback(async (): Promise<
    string | null
  > => {
    logger.debug("Attempting silent access token retrieval");

    const accessToken = await storage.getItem(StorageKeys.ACCESS_TOKEN);
    const expiresAt = await storage.getItem(StorageKeys.EXPIRES_AT);
    const refreshToken = await storage.getItem(StorageKeys.REFRESH_TOKEN);

    if (!accessToken) {
      logger.debug("No access token available for silent retrieval");
      return null;
    }

    const now = Math.floor(Date.now() / 1000);
    if (expiresAt && parseInt(expiresAt) > now + 60) {
      logger.debug("Using existing access token for silent retrieval", {
        expiresAt,
      });
      return accessToken;
    }

    if (!refreshToken) {
      logger.warn("Silent token retrieval failed: missing refresh token");
      await clearAuthState();
      return null;
    }

    try {
      const tokenEndpoint = `${config.authority}/connect/token`;

      const response = await fetch(tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: config.clientId,
        }),
      });

      if (!response.ok) {
        logger.warn("Silent refresh returned non-success status", {
          status: response.status,
        });
        await clearAuthState();
        return null;
      }

      const tokenData: TokenData = await response.json();

      const newExpiresAt = Math.floor(Date.now() / 1000) + tokenData.expires_in;

      await storage.setItem(StorageKeys.ACCESS_TOKEN, tokenData.access_token);
      await storage.setItem(
        StorageKeys.REFRESH_TOKEN,
        tokenData.refresh_token || "",
      );
      await storage.setItem(StorageKeys.EXPIRES_AT, newExpiresAt.toString());

      logger.info("Silent token refresh succeeded", {
        expiresAt: newExpiresAt,
      });

      return tokenData.access_token;
    } catch (error) {
      logger.error("Token refresh failed", {
        error: String(error),
      });
      await clearAuthState();
      return null;
    }
  }, [config, storage, clearAuthState, logger]);

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
