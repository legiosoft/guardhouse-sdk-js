import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  ReactNode,
  useRef,
} from "react";
import { Linking } from "react-native";
import InAppBrowser from "react-native-inappbrowser-reborn";
import {
  generateAuthUrl,
  generatePKCE,
  User as CoreUser,
} from "@guardhouse/core";
import {
  AuthState,
  TokenData,
  LoginOptions,
  LogoutOptions,
  SecurityError,
  RefreshTokenError,
  BiometricAuthFailedError,
  SessionExpiredError,
} from "./types";
import {
  SecureStorageAdapter,
  StorageKeys,
  generateBase64UrlEncodedString,
  parseQueryParams,
  sanitizeUrl,
  validateIdToken,
  validateUrlProtocol,
  logSecurityEvent,
  isTokenExpired,
  PromiseLock,
} from "./utils";

interface AuthContextValue extends AuthState {
  login: (options?: LoginOptions) => Promise<void>;
  logout: (options?: LogoutOptions) => Promise<void>;
  getAccessToken: () => Promise<string | null>;
  user: CoreUser | null;
  accessToken: string | null;
}

const AuthContext = createContext<AuthContextValue | null>(null);

interface GuardhouseProviderProps {
  authority: string;
  clientId: string;
  redirectUri: string;
  scopes?: string[];
  requireBiometrics?: boolean;
  children: ReactNode;
}

export function GuardhouseProvider({
  authority,
  clientId,
  redirectUri,
  scopes = ["openid", "profile", "offline_access"],
  requireBiometrics = false,
  children,
}: GuardhouseProviderProps) {
  const [state, setState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
    error: null,
    user: null,
  });
  const [accessToken, setAccessToken] = useState<string | null>(null);

  const secureStorage = new SecureStorageAdapter(requireBiometrics);
  const authUrlRef = useRef<string | null>(null);
  const refreshLock = useRef(new PromiseLock());

  const handleError = useCallback((error: string) => {
    setState((prev) => ({
      ...prev,
      isLoading: false,
      error,
      isAuthenticated: false,
      user: null,
    }));
  }, []);

  const handleSuccess = useCallback((user: CoreUser, tokenData?: TokenData) => {
    setState((prev) => ({
      ...prev,
      isLoading: false,
      error: null,
      isAuthenticated: true,
      user,
    }));

    if (tokenData && tokenData.access_token) {
      setAccessToken(tokenData.access_token);
    }

    logSecurityEvent("Authentication successful", {
      userId: user.sub,
      hasAccessToken: !!tokenData?.access_token,
    });
  }, []);

  const handleLoading = useCallback(() => {
    setState((prev) => ({ ...prev, isLoading: true }));
  }, []);

  const clearAuthState = useCallback(async () => {
    logSecurityEvent("Clearing auth state");
    await secureStorage.removeItem(StorageKeys.ACCESS_TOKEN);
    await secureStorage.removeItem(StorageKeys.REFRESH_TOKEN);
    await secureStorage.removeItem(StorageKeys.ID_TOKEN);
    await secureStorage.removeItem(StorageKeys.EXPIRES_AT);
    await secureStorage.removeItem(StorageKeys.USER);
    await secureStorage.removeItem(StorageKeys.CODE_VERIFIER);
    await secureStorage.removeItem(StorageKeys.STATE);
    await secureStorage.removeItem(StorageKeys.NONCE);
    await secureStorage.removeItem(StorageKeys.APP_STATE);
    setAccessToken(null);
    setState((prev) => ({
      ...prev,
      isAuthenticated: false,
      user: null,
      error: null,
    }));
  }, [secureStorage]);

  const checkSession = useCallback(async () => {
    try {
      handleLoading();
      logSecurityEvent("Checking existing session");

      let accessTokenStored: string | null = null;
      let userStr: string | null = null;

      try {
        accessTokenStored = await secureStorage.getItem(
          StorageKeys.ACCESS_TOKEN,
        );
        userStr = await secureStorage.getItem(StorageKeys.USER);
      } catch (error: any) {
        if (requireBiometrics && error?.message?.includes("cancelled")) {
          console.log(
            "Biometric authentication cancelled during session check",
          );
          setState((prev) => ({
            ...prev,
            isLoading: false,
            isAuthenticated: false,
          }));
          return;
        }
        throw error;
      }

      if (!accessTokenStored || !userStr) {
        logSecurityEvent("No existing session found");
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: false,
        }));
        return;
      }

      if (isTokenExpired(accessTokenStored)) {
        logSecurityEvent("Session expired, will require biometrics on refresh");
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: false,
        }));
        return;
      }

      const userData: CoreUser = JSON.parse(userStr);
      setAccessToken(accessTokenStored);
      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: null,
        isAuthenticated: true,
        user: userData,
      }));

      logSecurityEvent("Session check successful");
    } catch (error) {
      console.error("Session check failed:", error);
      logSecurityEvent("Session check failed", { error: String(error) });
      setState((prev) => ({
        ...prev,
        isLoading: false,
        isAuthenticated: false,
        user: null,
      }));
    }
  }, [secureStorage, clearAuthState, handleLoading, requireBiometrics]);

  useEffect(() => {
    checkSession();
  }, [checkSession]);

  const openAuthSession = useCallback(
    async (url: string): Promise<{ url: string }> => {
      logSecurityEvent("Opening auth session", {
        url: url.substring(0, 50) + "...",
      });

      try {
        if (!(await InAppBrowser.isAvailable())) {
          throw new Error("InAppBrowser is not available on this device");
        }

        validateUrlProtocol(url);

        const result = await InAppBrowser.openAuth(url, redirectUri, {
          ephemeralWebSession: false,
          showTitle: false,
          enableDefaultShare: false,
          enableUrlBarHiding: true,
          showInRecents: true,
        });

        if (result.type === "cancel") {
          throw new Error("Authentication cancelled by user");
        }

        if (result.type === "dismiss") {
          throw new Error("Authentication session was dismissed");
        }

        if (result.type === "success" && result.url) {
          return { url: result.url };
        }

        throw new Error("Authentication failed with unknown error");
      } catch (error) {
        logSecurityEvent("Auth session error", { error: String(error) });
        throw error;
      }
    },
    [redirectUri],
  );

  const handleAuthCallback = useCallback(
    async (callbackUrl: string): Promise<void> => {
      try {
        handleLoading();

        const sanitizedUrl = sanitizeUrl(callbackUrl);
        const url = new URL(sanitizedUrl);
        const params = parseQueryParams(url.search);

        const code = params["code"];
        const stateParam = params["state"];
        const error = params["error"];

        if (error) {
          const errorDescription = params["error_description"] || error;
          throw new Error(`Authentication error: ${errorDescription}`);
        }

        if (!code || !stateParam) {
          throw new Error("Invalid callback URL: missing code or state");
        }

        const storedState = await secureStorage.getItem(StorageKeys.STATE);
        if (storedState !== stateParam) {
          const securityError: SecurityError = new Error(
            "State parameter mismatch. Possible CSRF attack.",
          ) as SecurityError;
          securityError.code = "STATE_MISMATCH";
          logSecurityEvent("SECURITY ALERT: State mismatch", {
            received: stateParam,
            expected: storedState,
          });
          throw securityError;
        }

        const codeVerifier = await secureStorage.getItem(
          StorageKeys.CODE_VERIFIER,
        );
        if (!codeVerifier) {
          throw new Error("Code verifier not found in secure storage");
        }

        const nonce = await secureStorage.getItem(StorageKeys.NONCE);

        await secureStorage.removeItem(StorageKeys.CODE_VERIFIER);
        await secureStorage.removeItem(StorageKeys.STATE);
        await secureStorage.removeItem(StorageKeys.NONCE);

        const tokenEndpoint = `${authority}/connect/token`;

        logSecurityEvent("Exchanging authorization code for tokens");

        const response = await fetch(tokenEndpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri,
            client_id: clientId,
            code_verifier: codeVerifier,
          }),
        });

        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`Token exchange failed: ${errorText}`);
        }

        const tokenData: TokenData = await response.json();

        const expiresAt = Math.floor(Date.now() / 1000) + tokenData.expires_in;

        await secureStorage.setItem(
          StorageKeys.ACCESS_TOKEN,
          tokenData.access_token,
        );
        if (tokenData.refresh_token) {
          await secureStorage.setItem(
            StorageKeys.REFRESH_TOKEN,
            tokenData.refresh_token,
          );
        }
        if (tokenData.id_token) {
          await secureStorage.setItem(StorageKeys.ID_TOKEN, tokenData.id_token);
        }
        await secureStorage.setItem(
          StorageKeys.EXPIRES_AT,
          expiresAt.toString(),
        );

        if (tokenData.id_token && nonce) {
          try {
            validateIdToken(tokenData.id_token, nonce, authority, clientId);
            logSecurityEvent("ID token validated successfully");
          } catch (idTokenError) {
            console.error("ID token validation failed:", idTokenError);
            logSecurityEvent("ID token validation failed", {
              error: String(idTokenError),
            });
          }
        }

        const userInfoEndpoint = `${authority}/connect/userinfo`;
        const userResponse = await fetch(userInfoEndpoint, {
          headers: {
            Authorization: `Bearer ${tokenData.access_token}`,
          },
        });

        if (!userResponse.ok) {
          const errorText = await userResponse.text();
          console.warn("Failed to fetch user info:", errorText);
          logSecurityEvent("User info fetch failed", { error: errorText });
        } else {
          const userData = await userResponse.json();
          await secureStorage.setItem(
            StorageKeys.USER,
            JSON.stringify(userData),
          );
          handleSuccess(userData, tokenData);
        }

        const appStateStr = await secureStorage.getItem(StorageKeys.APP_STATE);
        const appState = appStateStr ? JSON.parse(appStateStr) : undefined;
        await secureStorage.removeItem(StorageKeys.APP_STATE);

        if (appState?.returnTo) {
          logSecurityEvent("Redirecting to returnTo", {
            returnTo: appState.returnTo,
          });
          const returnUrl = new URL(appState.returnTo);
          if (await Linking.canOpenURL(returnUrl.toString())) {
            await Linking.openURL(returnUrl.toString());
          }
        }
      } catch (error) {
        console.error("Auth callback handling failed:", error);
        handleError(
          error instanceof Error ? error.message : "Unknown error occurred",
        );
        await clearAuthState();
      }
    },
    [
      authority,
      clientId,
      redirectUri,
      secureStorage,
      handleLoading,
      handleError,
      handleSuccess,
      clearAuthState,
    ],
  );

  const login = useCallback(
    async (options?: LoginOptions) => {
      try {
        handleLoading();
        logSecurityEvent("Starting login flow");

        const { codeVerifier, codeChallenge } = await generatePKCE();
        const state = generateBase64UrlEncodedString(32);
        const nonce = generateBase64UrlEncodedString(32);

        await secureStorage.setItem(StorageKeys.CODE_VERIFIER, codeVerifier);
        await secureStorage.setItem(StorageKeys.STATE, state);
        await secureStorage.setItem(StorageKeys.NONCE, nonce);

        if (options?.appState?.returnTo) {
          await secureStorage.setItem(
            StorageKeys.APP_STATE,
            JSON.stringify(options.appState),
          );
        }

        const scope = options?.scope || scopes.join(" ");
        const authUrl = await generateAuthUrl({
          authority,
          clientId,
          redirectUri,
          responseType: "code",
          scope,
          state,
          codeChallenge,
          codeChallengeMethod: "S256",
        });

        validateUrlProtocol(authUrl);
        authUrlRef.current = authUrl;

        const result = await openAuthSession(authUrl);
        await handleAuthCallback(result.url);
      } catch (error) {
        console.error("Login failed:", error);
        handleError(error instanceof Error ? error.message : "Login failed");
      }
    },
    [
      authority,
      clientId,
      redirectUri,
      scopes,
      secureStorage,
      handleLoading,
      handleError,
      openAuthSession,
      handleAuthCallback,
    ],
  );

  const logout = useCallback(
    async (options?: LogoutOptions) => {
      try {
        logSecurityEvent("Starting logout flow");

        const returnTo = options?.returnTo || redirectUri || "com.myapp://";

        const logoutUrl = new URL(`${authority}/connect/logout`);
        logoutUrl.searchParams.set("post_logout_redirect_uri", returnTo);

        const idToken = await secureStorage.getItem(StorageKeys.ID_TOKEN);
        if (idToken) {
          logoutUrl.searchParams.set("id_token_hint", idToken);
        }

        validateUrlProtocol(logoutUrl.toString());

        await clearAuthState();

        logSecurityEvent("Opening logout URL", {
          url: logoutUrl.toString().substring(0, 50) + "...",
        });

        if (await Linking.canOpenURL(logoutUrl.toString())) {
          await Linking.openURL(logoutUrl.toString());
        } else {
          console.warn("Cannot open logout URL");
        }
      } catch (error) {
        console.error("Logout failed:", error);
        logSecurityEvent("Logout failed", { error: String(error) });
      }
    },
    [authority, redirectUri, secureStorage, clearAuthState],
  );

  const getAccessToken = useCallback(async (): Promise<string | null> => {
    return refreshLock.current.run(async () => {
      try {
        logSecurityEvent("Getting access token (with lock)");

        let accessTokenStored: string | null = null;
        let refreshToken: string | null = null;

        try {
          accessTokenStored = await secureStorage.getItem(
            StorageKeys.ACCESS_TOKEN,
          );
          refreshToken = await secureStorage.getItem(StorageKeys.REFRESH_TOKEN);
        } catch (error: any) {
          if (requireBiometrics && error?.message?.includes("cancelled")) {
            throw new BiometricAuthFailedError(
              "Biometric authentication cancelled",
              true,
            );
          }
          throw error;
        }

        if (!accessTokenStored) {
          logSecurityEvent("No access token found");
          return null;
        }

        if (!isTokenExpired(accessTokenStored)) {
          logSecurityEvent("Access token is still valid");
          return accessTokenStored;
        }

        logSecurityEvent("Access token expired, attempting refresh");

        if (!refreshToken) {
          logSecurityEvent("No refresh token available");
          throw new SessionExpiredError(
            "Session expired and no refresh token available",
          );
        }

        const tokenEndpoint = `${authority}/connect/token`;

        const response = await fetch(tokenEndpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: clientId,
          }),
        });

        if (!response.ok) {
          const errorText = await response.text();
          logSecurityEvent("Token refresh failed", {
            error: errorText,
            status: response.status,
          });
          throw new RefreshTokenError(
            `Failed to refresh token: ${errorText}`,
            response.status,
          );
        }

        const tokenData: TokenData = await response.json();

        const newExpiresAt =
          Math.floor(Date.now() / 1000) + tokenData.expires_in;

        await secureStorage.setItem(
          StorageKeys.ACCESS_TOKEN,
          tokenData.access_token,
        );
        if (tokenData.refresh_token) {
          await secureStorage.setItem(
            StorageKeys.REFRESH_TOKEN,
            tokenData.refresh_token,
          );
        }
        if (tokenData.id_token) {
          await secureStorage.setItem(StorageKeys.ID_TOKEN, tokenData.id_token);
        }
        await secureStorage.setItem(
          StorageKeys.EXPIRES_AT,
          newExpiresAt.toString(),
        );

        setAccessToken(tokenData.access_token);

        logSecurityEvent("Token refreshed successfully");

        return tokenData.access_token;
      } catch (error) {
        if (error instanceof BiometricAuthFailedError) {
          console.log("Biometric authentication cancelled:", error.message);
          throw error;
        }

        if (
          error instanceof SessionExpiredError ||
          error instanceof RefreshTokenError
        ) {
          console.error("Token refresh failed:", error);
          await clearAuthState();
          setState((prev) => ({
            ...prev,
            isAuthenticated: false,
            user: null,
            error: error.message,
          }));
          throw error;
        }

        console.error("Get access token failed:", error);
        logSecurityEvent("Get access token failed", { error: String(error) });
        await clearAuthState();
        setState((prev) => ({
          ...prev,
          isAuthenticated: false,
          user: null,
        }));
        return null;
      }
    });
  }, [authority, clientId, secureStorage, clearAuthState, requireBiometrics]);

  const contextValue: AuthContextValue = {
    ...state,
    login,
    logout,
    getAccessToken,
    user: state.user,
    accessToken,
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
