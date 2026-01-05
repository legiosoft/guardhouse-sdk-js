import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  ReactNode,
} from "react";
import {
  GuardhouseClient,
  generateAuthUrl,
  generatePKCE,
  User as CoreUser,
  type AuthUrlOptions as CoreAuthUrlOptions,
} from "@guardhouse/core";
import {
  GuardhouseConfig,
  AuthState,
  TokenData,
  LoginOptions,
  LogoutOptions,
  AppState,
  StorageAdapter,
} from "./types";
import {
  LocalStorageAdapter,
  InMemoryStorageAdapter,
  SessionStorageAdapter,
  StorageKeys,
  generateBase64UrlEncodedString,
  parseQueryParams,
  removeQueryParams,
  validateIdToken,
} from "./utils";

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

  const storage: StorageAdapter = config.storage || new LocalStorageAdapter();
  const sessionStorage = new SessionStorageAdapter();

  const client = React.useMemo(
    () =>
      new GuardhouseClient({
        authority: config.authority,
        clientId: config.clientId,
      }),
    [config.authority, config.clientId],
  );

  const handleError = useCallback((error: string) => {
    setState((prev) => ({
      ...prev,
      isLoading: false,
      error,
      isAuthenticated: false,
      user: null,
    }));
  }, []);

  const handleSuccess = useCallback(
    (user: CoreUser, tokenData?: TokenData) => {
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: null,
        isAuthenticated: true,
        user,
      }));

      if (tokenData && config.onRedirectCallback) {
        config.onRedirectCallback();
      }
    },
    [config.onRedirectCallback],
  );

  const handleLoading = useCallback(() => {
    setState((prev) => ({ ...prev, isLoading: true }));
  }, []);

  const clearAuthState = useCallback(async () => {
    await storage.removeItem(StorageKeys.ACCESS_TOKEN);
    await storage.removeItem(StorageKeys.REFRESH_TOKEN);
    await storage.removeItem(StorageKeys.ID_TOKEN);
    await storage.removeItem(StorageKeys.EXPIRES_AT);
    await storage.removeItem(StorageKeys.USER);
  }, [storage]);

  const handleCallback = useCallback(async () => {
    const params = parseQueryParams(window.location.search);

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
      setState((prev) => ({ ...prev, isLoading: false }));
      return;
    }

    try {
      handleLoading();

      const storedState = await sessionStorage.getItem(StorageKeys.STATE);
      if (storedState !== state) {
        throw new Error("State parameter mismatch. Possible CSRF attack.");
      }

      const codeVerifier = await sessionStorage.getItem(
        StorageKeys.CODE_VERIFIER,
      );
      if (!codeVerifier) {
        throw new Error("Code verifier not found in session storage");
      }

      const nonce = await sessionStorage.getItem(StorageKeys.NONCE);

      await sessionStorage.removeItem(StorageKeys.CODE_VERIFIER);
      await sessionStorage.removeItem(StorageKeys.STATE);
      await sessionStorage.removeItem(StorageKeys.NONCE);

      const tokenEndpoint = `${config.authority}/connect/token`;

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

      const expiresAt = Math.floor(Date.now() / 1000) + tokenData.expires_in;

      await storage.setItem(StorageKeys.ACCESS_TOKEN, tokenData.access_token);
      await storage.setItem(
        StorageKeys.REFRESH_TOKEN,
        tokenData.refresh_token || "",
      );
      await storage.setItem(StorageKeys.ID_TOKEN, tokenData.id_token || "");
      await storage.setItem(StorageKeys.EXPIRES_AT, expiresAt.toString());

      if (tokenData.id_token && nonce) {
        try {
          validateIdToken(
            tokenData.id_token,
            nonce,
            config.authority,
            config.clientId,
          );
        } catch (idTokenError) {
          console.warn("ID token validation failed:", idTokenError);
        }
      }

      const userInfoEndpoint = `${config.authority}/connect/userinfo`;
      const userResponse = await fetch(userInfoEndpoint, {
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
        },
      });

      if (!userResponse.ok) {
        const errorText = await userResponse.text();
        console.warn("Failed to fetch user info:", errorText);
      } else {
        const userData = await userResponse.json();
        await storage.setItem(StorageKeys.USER, JSON.stringify(userData));
        handleSuccess(userData, tokenData);
      }

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
  ]);

  const checkSession = useCallback(async () => {
    try {
      handleLoading();

      const accessToken = await storage.getItem(StorageKeys.ACCESS_TOKEN);
      const expiresAt = await storage.getItem(StorageKeys.EXPIRES_AT);
      const userStr = await storage.getItem(StorageKeys.USER);

      if (!accessToken || !userStr) {
        setState((prev) => ({ ...prev, isLoading: false }));
        return;
      }

      const now = Math.floor(Date.now() / 1000);
      if (expiresAt && parseInt(expiresAt) < now) {
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
    } catch (error) {
      console.error("Session check failed:", error);
      setState((prev) => ({
        ...prev,
        isLoading: false,
        isAuthenticated: false,
        user: null,
      }));
    }
  }, [storage, clearAuthState, handleLoading, handleSuccess]);

  useEffect(() => {
    if (typeof window === "undefined") return;

    const params = parseQueryParams(window.location.search);

    if (params["code"] && params["state"]) {
      handleCallback();
    } else {
      checkSession();
    }
  }, [handleCallback, checkSession]);

  const loginWithRedirect = useCallback(
    async (options?: LoginOptions) => {
      try {
        const { codeVerifier, codeChallenge } = await generatePKCE();
        const state = generateBase64UrlEncodedString(32);
        const nonce = generateBase64UrlEncodedString(32);

        await sessionStorage.setItem(StorageKeys.CODE_VERIFIER, codeVerifier);
        await sessionStorage.setItem(StorageKeys.STATE, state);
        await sessionStorage.setItem(StorageKeys.NONCE, nonce);

        const authUrl = await generateAuthUrl({
          authority: config.authority,
          clientId: config.clientId,
          redirectUri: config.redirectUri,
          responseType: config.responseType || "code",
          scope: options?.scope || config.scope || "openid profile email",
          state,
          codeChallenge,
          codeChallengeMethod: "S256",
        });

        if (options?.appState?.returnTo) {
          await sessionStorage.setItem(
            "gh_app_state",
            JSON.stringify(options.appState),
          );
        }

        window.location.href = authUrl;
      } catch (error) {
        handleError(error instanceof Error ? error.message : "Login failed");
      }
    },
    [config, sessionStorage, handleError],
  );

  const logout = useCallback(
    async (options?: LogoutOptions) => {
      const returnTo =
        options?.returnTo || config.logoutRedirectUri || window.location.origin;

      const logoutUrl = new URL(`${config.authority}/connect/endsession`);
      logoutUrl.searchParams.set("post_logout_redirect_uri", returnTo);

      const idToken = await storage.getItem(StorageKeys.ID_TOKEN);
      if (idToken) {
        logoutUrl.searchParams.set("id_token_hint", idToken);
      }

      await clearAuthState();

      window.location.href = logoutUrl.toString();
    },
    [config, storage, clearAuthState],
  );

  const getAccessToken = useCallback(async (): Promise<string | null> => {
    const accessToken = await storage.getItem(StorageKeys.ACCESS_TOKEN);
    return accessToken;
  }, [storage]);

  const getAccessTokenSilently = useCallback(async (): Promise<
    string | null
  > => {
    const accessToken = await storage.getItem(StorageKeys.ACCESS_TOKEN);
    const expiresAt = await storage.getItem(StorageKeys.EXPIRES_AT);
    const refreshToken = await storage.getItem(StorageKeys.REFRESH_TOKEN);

    if (!accessToken) {
      return null;
    }

    const now = Math.floor(Date.now() / 1000);
    if (expiresAt && parseInt(expiresAt) > now + 60) {
      return accessToken;
    }

    if (!refreshToken) {
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

      return tokenData.access_token;
    } catch (error) {
      console.error("Token refresh failed:", error);
      await clearAuthState();
      return null;
    }
  }, [config, storage, clearAuthState]);

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
