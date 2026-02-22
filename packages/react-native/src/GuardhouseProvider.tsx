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
import * as GuardhouseCore from "@guardhouse/core";
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
import { createReactNativeLogger } from "./debug";

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
  debug?: boolean;
  children: ReactNode;
}

export function GuardhouseProvider({
  authority,
  clientId,
  redirectUri,
  scopes = ["openid", "profile", "offline_access"],
  requireBiometrics = false,
  debug = false,
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
    () => new SecureStorage(requireBiometrics, debug),
    [requireBiometrics, debug],
  );
  const logger = useMemo(
    () => createReactNativeLogger("Provider", debug),
    [debug],
  );
  const refreshLock = useRef(new PromiseLock(debug));

  useEffect(() => {
    (GuardhouseCore as any).setGuardhouseDebug?.(debug);
    logger.info("Debug mode updated", { enabled: debug });
  }, [debug, logger]);

  const handleError = useCallback(
    (error: string) => {
      logger.error("Authentication state updated to error", { error });

      setState((prev) => ({
        ...prev,
        isLoading: false,
        error,
        isAuthenticated: false,
        user: null,
      }));
      setAccessToken(null);
    },
    [logger],
  );

  const handleSuccess = useCallback(
    (user: CoreUser, tokenData: TokenData) => {
      logger.info("Authentication state updated to success", {
        subject: user.sub,
        hasRefreshToken: Boolean(tokenData.refresh_token),
      });

      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: null,
        isAuthenticated: true,
        user,
      }));
      setAccessToken(tokenData.access_token);
    },
    [logger],
  );

  const handleLoading = useCallback(() => {
    logger.debug("Authentication state set to loading");
    setState((prev) => ({ ...prev, isLoading: true }));
  }, [logger]);

  /**
   * Clear all authentication data from secure storage
   *
   * SECURITY: Important to call on logout to remove all sensitive data
   * Prevents unauthorized access if device is lost/stolen
   */
  const clearAuthState = useCallback(async () => {
    logger.debug("Clearing auth state");

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
  }, [storage, logger]);

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
        logger.info("No existing session found");
        setState((prev) => ({ ...prev, isLoading: false }));
        return;
      }

      // Check if token is expired
      if (isTokenExpired(session.accessToken, 60, debug)) {
        logger.info("Session token is expired");
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

      logger.info("Session restored successfully");
    } catch (error) {
      logger.error("Session check failed", { error: String(error) });

      if (error instanceof Error && error.name === "BiometricAuthFailedError") {
        logger.warn("Biometric authentication cancelled");
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: false,
        }));
        return;
      }

      handleError("Failed to check session");
    }
  }, [
    storage,
    clearAuthState,
    handleLoading,
    handleError,
    handleSuccess,
    debug,
    logger,
  ]);

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
  const openExternalAuthSession = useCallback(
    async (url: string): Promise<{ url: string }> => {
      logger.warn(
        "InAppBrowser unavailable; falling back to external browser deep link flow",
      );

      const redirectPrefix = redirectUri;

      return new Promise((resolve, reject) => {
        let settled = false;

        const cleanup = (subscription?: { remove: () => void }) => {
          if (subscription) {
            subscription.remove();
          }
          clearTimeout(timeout);
        };

        const fail = (
          error: unknown,
          subscription?: { remove: () => void },
        ) => {
          if (settled) {
            return;
          }

          settled = true;
          cleanup(subscription);

          reject(
            error instanceof Error
              ? error
              : new Error(typeof error === "string" ? error : String(error)),
          );
        };

        const success = (
          callbackUrl: string,
          subscription?: { remove: () => void },
        ) => {
          if (settled) {
            return;
          }

          settled = true;
          cleanup(subscription);
          resolve({ url: callbackUrl });
        };

        const subscription = Linking.addEventListener("url", ({ url }) => {
          if (!url.startsWith(redirectPrefix)) {
            logger.debug(
              "Ignoring unrelated deep link while waiting for auth",
              {
                redirectPrefix,
              },
            );
            return;
          }

          success(url, subscription);
        });

        const timeout = setTimeout(() => {
          fail(
            new Error(
              "Authentication redirect timed out. Check redirect URI scheme configuration.",
            ),
            subscription,
          );
        }, 180000);

        Linking.openURL(url).catch((error) => {
          fail(error, subscription);
        });
      });
    },
    [redirectUri, logger],
  );

  const openAuthSession = useCallback(
    async (url: string): Promise<{ url: string }> => {
      logger.info("Opening auth session");

      try {
        const inAppBrowserAvailable = await InAppBrowser.isAvailable();

        if (!inAppBrowserAvailable) {
          return openExternalAuthSession(url);
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
        logger.error("Auth session error", { error: String(error) });
        throw error;
      }
    },
    [redirectUri, logger, openExternalAuthSession],
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

        logger.debug("Handling OAuth callback", {
          callbackOrigin: new URL(callbackUrl).origin,
        });

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
          logger.warn("State mismatch detected", {
            hasStoredState: Boolean(storedState),
            receivedState: stateParam,
          });
          throw new Error("State parameter mismatch. Possible CSRF attack.");
        }

        const codeVerifier = await storage.getItem(STORAGE_KEYS.CODE_VERIFIER);
        if (!codeVerifier) {
          throw new Error("Code verifier not found in secure storage");
        }

        logger.debug("State and code verifier validated");

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

        logger.debug("Token exchange succeeded", {
          expiresIn: tokenData.expires_in,
          hasRefreshToken: Boolean(tokenData.refresh_token),
          hasIdToken: Boolean(tokenData.id_token),
        });

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
          logger.warn("Failed to fetch user info");
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

        logger.debug("Session stored in secure storage", {
          expiresAt,
        });

        handleSuccess(userData, tokenData);

        // Handle app state (returnTo after login)
        const appStateStr = await storage.getItem(STORAGE_KEYS.APP_STATE);
        if (appStateStr) {
          await storage.removeItem(STORAGE_KEYS.APP_STATE);

          const appState = JSON.parse(appStateStr);
          if (appState?.returnTo) {
            logger.debug("Handling post-login app state redirect", {
              returnTo: appState.returnTo,
            });
            const returnUrl = new URL(appState.returnTo);
            if (await Linking.canOpenURL(returnUrl.toString())) {
              await Linking.openURL(returnUrl.toString());
            }
          }
        }
      } catch (error) {
        logger.error("Auth callback handling failed", {
          error: String(error),
        });
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
      logger,
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

        logger.info("Starting login flow", {
          hasAppState: Boolean(options?.appState),
          scope: options?.scope || scopes.join(" "),
        });

        const { codeVerifier, codeChallenge } = await generatePKCE({
          debug,
        } as any);

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

          logger.debug("Stored app state before auth redirect", {
            hasReturnTo: Boolean(options.appState.returnTo),
          });
        }

        const scope = options?.scope || scopes.join(" ");
        const authUrl = await generateAuthUrl({
          authority,
          clientId,
          redirectUri,
          debug,
          responseType: "code",
          scope,
          state,
          codeChallenge,
          codeChallengeMethod: "S256", // Enforce S256 (no plain text)
        } as any);

        const result = await openAuthSession(authUrl);
        await handleAuthCallback(result.url);
      } catch (error) {
        logger.error("Login failed", { error: String(error) });
        handleError(error instanceof Error ? error.message : "Login failed");
      }
    },
    [
      authority,
      clientId,
      debug,
      redirectUri,
      scopes,
      storage,
      handleLoading,
      handleError,
      openAuthSession,
      handleAuthCallback,
      logger,
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
        logger.info("Starting logout flow");

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
        logger.debug("Opening logout URL");
        if (await Linking.canOpenURL(logoutUrl.toString())) {
          await Linking.openURL(logoutUrl.toString());
        } else {
          logger.warn("Cannot open logout URL");
        }
      } catch (error) {
        logger.error("Logout failed", { error: String(error) });
        // Clear local data even if logout URL fails
        await clearAuthState();
      }
    },
    [authority, redirectUri, storage, clearAuthState, logger],
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
        logger.debug("Getting access token with lock");

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
          logger.info("No session found");
          return null;
        }

        // Check if token is expired (using JWT exp claim)
        if (!isTokenExpired(session.accessToken, 60, debug)) {
          logger.debug("Access token is still valid");
          return session.accessToken;
        }

        logger.info("Access token expired, attempting refresh");

        if (!session.refreshToken) {
          logger.warn("No refresh token available");
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
          logger.error("Token refresh failed", {
            status: response.status,
            error: errorText,
          });
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

        logger.info("Token refreshed successfully");

        return tokenData.access_token;
      } catch (error) {
        logger.error("Get access token failed", {
          error: String(error),
        });

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
  }, [authority, clientId, storage, clearAuthState, debug, logger]);

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
