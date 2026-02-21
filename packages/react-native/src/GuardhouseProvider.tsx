/**
 * Guardhouse Provider Component
 *
 * SECURITY DECISIONS:
 *
 * 1. Why ephemeralWebSession: false?
 *    - Enables SSO via shared cookies
 *    - Allows Passkeys/FaceID autofill in browser
 *    - Better UX (user doesn't re-authenticate every time)
 *    - Security: Cookies are still scoped to your app
 *
 * 2. Why validate state parameter?
 *    - Critical CSRF protection
 *    - Prevents man-in-the-middle attacks on OAuth flow
 *    - If state doesn't match, potential attack - throw security error
 *
 * 3. Why clear temporary PKCE values after use?
 *    - code_verifier, state, nonce are sensitive
 *    - Should not persist beyond auth flow
 *    - Minimizes attack surface if device is compromised
 *
 * 4. Why call /connect/endsession on logout?
 *    - Clears server-side session and cookies
 *    - Prevents session fixation attacks
 *    - Prevents other apps from using SSO cookies
 *
 * 5. Why set launchMode="singleTask" in AndroidManifest?
 *    - Critical: Prevents task hijacking attacks
 *    - Malicious app can't intercept redirect intent
 *    - OWASP M-STG-RES-008 requirement
 *    - Documented in README (user's responsibility)
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  ReactNode,
  useMemo,
  useRef,
} from "react";
import { Linking } from "react-native";
import InAppBrowser from "react-native-inappbrowser-reborn";
import {
  decodeJWT,
  generateAuthUrl,
  generateNonce,
  generatePKCE,
  generateState,
  validateToken,
} from "@guardhouse/core";
import type { User as CoreUser } from "@guardhouse/core";
import { AuthState, TokenData, LoginOptions, LogoutOptions } from "./types";
import {
  SecureStorage,
  SessionData,
  PromiseLock,
  isTokenExpired,
  STORAGE_KEYS,
} from "./utils/storage";

interface AuthContextValue extends AuthState {
  login: (options?: LoginOptions) => Promise<void>;
  logout: (options?: LogoutOptions) => Promise<void>;
  getAccessToken: () => Promise<string | null>;
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

  const storage = useMemo(
    () => new SecureStorage(requireBiometrics),
    [requireBiometrics],
  );
  const refreshLock = useRef(new PromiseLock());

  const handleError = useCallback((error: string) => {
    setState((prev) => ({
      ...prev,
      isLoading: false,
      error,
      isAuthenticated: false,
      user: null,
    }));
    setAccessToken(null);
  }, []);

  const handleSuccess = useCallback((user: CoreUser, tokenData: TokenData) => {
    setState((prev) => ({
      ...prev,
      isLoading: false,
      error: null,
      isAuthenticated: true,
      user,
    }));
    setAccessToken(tokenData.access_token);
  }, []);

  const handleLoading = useCallback(() => {
    setState((prev) => ({ ...prev, isLoading: true }));
  }, []);

  /**
   * Clear all authentication data from secure storage
   *
   * SECURITY: Important to call on logout to remove all sensitive data
   * Prevents unauthorized access if device is lost/stolen
   */
  const clearAuthState = useCallback(async () => {
    console.log("[Guardhouse] Clearing auth state");

    await Promise.all([
      storage.removeItem(STORAGE_KEYS.ACCESS_TOKEN),
      storage.removeItem(STORAGE_KEYS.REFRESH_TOKEN),
      storage.removeItem(STORAGE_KEYS.ID_TOKEN),
      storage.removeItem(STORAGE_KEYS.EXPIRES_AT),
      storage.removeItem(STORAGE_KEYS.USER),
      storage.removeItem(STORAGE_KEYS.CODE_VERIFIER),
      storage.removeItem(STORAGE_KEYS.STATE),
      storage.removeItem(STORAGE_KEYS.NONCE),
      storage.removeItem(STORAGE_KEYS.APP_STATE),
    ]);

    setState((prev) => ({
      ...prev,
      isAuthenticated: false,
      user: null,
      error: null,
    }));
    setAccessToken(null);
  }, [storage]);

  /**
   * Check for existing session on mount
   *
   * SECURITY: Validates token presence and expiration
   * If requireBiometrics=true, user will be prompted
   * If expired, user must re-login (we don't auto-refresh here)
   */
  const checkSession = useCallback(async () => {
    try {
      handleLoading();

      const session = await storage.getSession();

      if (!session) {
        console.log("[Guardhouse] No existing session found");
        setState((prev) => ({ ...prev, isLoading: false }));
        return;
      }

      // Check if token is expired
      if (isTokenExpired(session.accessToken)) {
        console.log("[Guardhouse] Session token is expired");
        await clearAuthState();
        setState((prev) => ({ ...prev, isLoading: false }));
        return;
      }

      // Session is valid, restore state
      setAccessToken(session.accessToken);
      handleSuccess(session.user, {
        access_token: session.accessToken,
        refresh_token: session.refreshToken,
        id_token: session.idToken,
        expires_in: session.expiresAt - Math.floor(Date.now() / 1000),
        token_type: "Bearer",
      });

      console.log("[Guardhouse] Session restored successfully");
    } catch (error) {
      console.error("[Guardhouse] Session check failed:", error);

      if (error instanceof Error && error.name === "BiometricAuthFailedError") {
        console.log("[Guardhouse] Biometric authentication cancelled");
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: false,
        }));
        return;
      }

      handleError("Failed to check session");
    }
  }, [storage, clearAuthState, handleLoading, handleError, handleSuccess]);

  // Check session on mount
  useEffect(() => {
    checkSession();
  }, [checkSession]);

  /**
   * Open InAppBrowser for OAuth authentication
   *
   * SECURITY DECISIONS:
   * - ephemeralWebSession: false (SSO, Passkeys support)
   * - showTitle: false (native feel)
   * - enableUrlBarHiding: true (prevents URL manipulation)
   * - enableDefaultShare: false (prevents data leakage)
   */
  const openAuthSession = useCallback(
    async (url: string): Promise<{ url: string }> => {
      console.log("[Guardhouse] Opening auth session");

      try {
        if (!(await InAppBrowser.isAvailable())) {
          throw new Error("InAppBrowser is not available on this device");
        }

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
        console.error("[Guardhouse] Auth session error:", error);
        throw error;
      }
    },
    [redirectUri],
  );

  /**
   * Handle OAuth callback URL
   *
   * SECURITY: Validates state parameter (CSRF protection)
   * SECURITY: Exchanges authorization code for tokens
   * SECURITY: Validates ID token (nonce, issuer, audience, algorithm)
   */
  const handleAuthCallback = useCallback(
    async (callbackUrl: string): Promise<void> => {
      try {
        handleLoading();

        const url = new URL(callbackUrl);
        const params = new URLSearchParams(url.search);

        const code = params.get("code");
        const stateParam = params.get("state");
        const error = params.get("error");

        if (error) {
          const errorDescription = params.get("error_description") || error;
          throw new Error(`Authentication error: ${errorDescription}`);
        }

        if (!code || !stateParam) {
          throw new Error("Invalid callback URL: missing code or state");
        }

        // CRITICAL: Validate state parameter (CSRF protection)
        const storedState = await storage.getItem(STORAGE_KEYS.STATE);
        if (storedState !== stateParam) {
          throw new Error("State parameter mismatch. Possible CSRF attack.");
        }

        const codeVerifier = await storage.getItem(STORAGE_KEYS.CODE_VERIFIER);
        if (!codeVerifier) {
          throw new Error("Code verifier not found in secure storage");
        }

        const nonce = await storage.getItem(STORAGE_KEYS.NONCE);

        // Clear temporary PKCE values (security: minimize attack surface)
        await Promise.all([
          storage.removeItem(STORAGE_KEYS.CODE_VERIFIER),
          storage.removeItem(STORAGE_KEYS.STATE),
          storage.removeItem(STORAGE_KEYS.NONCE),
        ]);

        const tokenEndpoint = `${authority}/connect/token`;

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

        if (tokenData.id_token && nonce) {
          const decodedIdToken = decodeJWT(tokenData.id_token);
          const validation = validateToken(decodedIdToken, {
            issuer: authority,
            audience: clientId,
            nonce,
          });

          if (!validation.valid) {
            throw new Error(
              `ID token validation failed: ${validation.errors.join(", ")}`,
            );
          }
        }

        const expiresAt = Math.floor(Date.now() / 1000) + tokenData.expires_in;

        // Save session data to secure storage
        const userResponse = await fetch(`${authority}/connect/userinfo`, {
          headers: {
            Authorization: `Bearer ${tokenData.access_token}`,
          },
        });

        if (!userResponse.ok) {
          console.warn("[Guardhouse] Failed to fetch user info");
        }

        const userData = await userResponse.json();

        const sessionData: SessionData = {
          accessToken: tokenData.access_token,
          refreshToken: tokenData.refresh_token,
          idToken: tokenData.id_token,
          expiresAt,
          user: userData,
        };

        await storage.saveSession(sessionData);

        handleSuccess(userData, tokenData);

        // Handle app state (returnTo after login)
        const appStateStr = await storage.getItem(STORAGE_KEYS.APP_STATE);
        if (appStateStr) {
          await storage.removeItem(STORAGE_KEYS.APP_STATE);

          const appState = JSON.parse(appStateStr);
          if (appState?.returnTo) {
            const returnUrl = new URL(appState.returnTo);
            if (await Linking.canOpenURL(returnUrl.toString())) {
              await Linking.openURL(returnUrl.toString());
            }
          }
        }
      } catch (error) {
        console.error("[Guardhouse] Auth callback handling failed:", error);
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
      storage,
      handleLoading,
      handleError,
      handleSuccess,
      clearAuthState,
    ],
  );

  /**
   * Login using OAuth 2.0 Authorization Code Flow with PKCE
   *
   * SECURITY: Generates cryptographically secure PKCE parameters
   * SECURITY: Stores temporary values (code_verifier, state, nonce)
   * SECURITY: Opens secure browser window
   */
  const login = useCallback(
    async (options?: LoginOptions) => {
      try {
        handleLoading();

        const { codeVerifier, codeChallenge } = await generatePKCE();

        const state = await generateState(32);
        const nonce = await generateNonce(32);

        // Store temporary PKCE values
        await Promise.all([
          storage.setItem(STORAGE_KEYS.CODE_VERIFIER, codeVerifier),
          storage.setItem(STORAGE_KEYS.STATE, state),
          storage.setItem(STORAGE_KEYS.NONCE, nonce),
        ]);

        if (options?.appState) {
          await storage.setItem(
            STORAGE_KEYS.APP_STATE,
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
          codeChallengeMethod: "S256", // Enforce S256 (no plain text)
        });

        const result = await openAuthSession(authUrl);
        await handleAuthCallback(result.url);
      } catch (error) {
        console.error("[Guardhouse] Login failed:", error);
        handleError(error instanceof Error ? error.message : "Login failed");
      }
    },
    [
      authority,
      clientId,
      redirectUri,
      scopes,
      storage,
      handleLoading,
      handleError,
      openAuthSession,
      handleAuthCallback,
    ],
  );

  /**
   * Logout user and clear session
   *
   * SECURITY: Calls /connect/endsession to clear server cookies
   * SECURITY: Clears all local sensitive data from Keychain
   * SECURITY: Prevents session fixation attacks
   */
  const logout = useCallback(
    async (options?: LogoutOptions) => {
      try {
        console.log("[Guardhouse] Starting logout flow");

        const returnTo = options?.returnTo || redirectUri || "com.myapp://";

        // Call end-session endpoint to clear server session and cookies
        const logoutUrl = new URL(`${authority}/connect/endsession`);
        logoutUrl.searchParams.set("post_logout_redirect_uri", returnTo);

        const idToken = await storage.getItem(STORAGE_KEYS.ID_TOKEN);
        if (idToken) {
          logoutUrl.searchParams.set("id_token_hint", idToken);
        }

        // Clear all local data first
        await clearAuthState();

        // Open logout URL to clear server cookies
        console.log("[Guardhouse] Opening logout URL");
        if (await Linking.canOpenURL(logoutUrl.toString())) {
          await Linking.openURL(logoutUrl.toString());
        } else {
          console.warn("[Guardhouse] Cannot open logout URL");
        }
      } catch (error) {
        console.error("[Guardhouse] Logout failed:", error);
        // Clear local data even if logout URL fails
        await clearAuthState();
      }
    },
    [authority, redirectUri, storage, clearAuthState],
  );

  /**
   * Get access token with automatic silent refresh
   *
   * SECURITY DECISIONS:
   * - Check JWT exp claim directly (no network call needed)
   * - Use mutex to prevent multiple concurrent refresh requests
   * - If refresh fails, clear session and require re-login
   * - If requireBiometrics=true, triggers biometric prompt
   *
   * Why mutex for refresh?
   * - Multiple API calls might trigger getAccessToken() simultaneously
   * - Without lock: Each makes separate refresh request (wasteful, race conditions)
   * - With lock: First call refreshes, others reuse result (efficient)
   */
  const getAccessToken = useCallback(async (): Promise<string | null> => {
    return refreshLock.current.run(async () => {
      try {
        console.log("[Guardhouse] Getting access token (with lock)");

        let session: SessionData | null = null;

        try {
          session = await storage.getSession();
        } catch (error: any) {
          if (
            error instanceof Error &&
            error.name === "BiometricAuthFailedError"
          ) {
            // User cancelled biometric prompt
            throw error;
          }
          throw new Error("Failed to access secure storage");
        }

        if (!session) {
          console.log("[Guardhouse] No session found");
          return null;
        }

        // Check if token is expired (using JWT exp claim)
        if (!isTokenExpired(session.accessToken)) {
          console.log("[Guardhouse] Access token is still valid");
          return session.accessToken;
        }

        console.log("[Guardhouse] Access token expired, attempting refresh");

        if (!session.refreshToken) {
          console.log("[Guardhouse] No refresh token available");
          // Clear session and force re-login
          await clearAuthState();
          setState((prev) => ({
            ...prev,
            isAuthenticated: false,
            user: null,
          }));
          return null;
        }

        // Perform silent token refresh
        const tokenEndpoint = `${authority}/connect/token`;

        const response = await fetch(tokenEndpoint, {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: session.refreshToken,
            client_id: clientId,
          }),
        });

        if (!response.ok) {
          const errorText = await response.text();
          console.error(
            "[Guardhouse] Token refresh failed:",
            response.status,
            errorText,
          );
          // Refresh failed - clear session
          await clearAuthState();
          setState((prev) => ({
            ...prev,
            isAuthenticated: false,
            user: null,
            error: "Session expired. Please login again.",
          }));
          return null;
        }

        const tokenData: TokenData = await response.json();

        const newExpiresAt =
          Math.floor(Date.now() / 1000) + tokenData.expires_in;

        // Save new tokens to secure storage
        await storage.saveSession({
          accessToken: tokenData.access_token,
          refreshToken: tokenData.refresh_token,
          idToken: tokenData.id_token,
          expiresAt: newExpiresAt,
          user: session.user,
        });

        setAccessToken(tokenData.access_token);

        console.log("[Guardhouse] Token refreshed successfully");

        return tokenData.access_token;
      } catch (error) {
        console.error("[Guardhouse] Get access token failed:", error);

        // If biometric was cancelled, don't clear session
        if (
          error instanceof Error &&
          error.name === "BiometricAuthFailedError"
        ) {
          throw error;
        }

        // For other errors, clear session
        await clearAuthState();
        return null;
      }
    });
  }, [authority, clientId, storage, clearAuthState]);

  const contextValue: AuthContextValue = {
    ...state,
    login,
    logout,
    getAccessToken,
    accessToken,
  };

  return (
    <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
  );
}

/**
 * useAuth Hook
 *
 * Provides access to authentication state and actions
 *
 * SECURITY NOTES:
 * - isAuthenticated is derived from valid token presence
 * - user is parsed ID token payload (strictly typed)
 * - getAccessToken() includes biometric prompt if enabled
 * - All token operations go through secure storage
 */
export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used within a GuardhouseProvider");
  }

  return context;
}

export { AuthContext };
