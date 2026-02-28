import React, { useCallback, useEffect, useMemo, useState } from "react";
import { ActivityIndicator, StyleSheet, Text, View } from "react-native";
import { parseOAuthCallbackUrl } from "@guardhouse/core";
import {
  GuardhouseClient,
  type GuardhouseSession,
} from "@guardhouse/react-native";
import * as Linking from "expo-linking";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { appConfig } from "./src/config";
import { expoCryptoAdapter } from "./src/cryptoAdapter";
import { asyncSessionStorageAdapter } from "./src/asyncSessionStorageAdapter";
import { expoPasskeyAdapter } from "./src/expoPasskeyAdapter";
import { expoRefreshTokenStorageAdapter } from "./src/expoGoStorageAdapter";
import {
  expoWebBrowserAdapter,
  resolveExpoRedirectUri,
} from "./src/expoWebBrowserAdapter";
import AuthScreen from "./src/screens/AuthScreen";
import ProtectedScreen from "./src/screens/ProtectedScreen";

type BusyAction =
  | "login"
  | "register"
  | "passkey"
  | "refresh"
  | "logout"
  | "deepLink";

function isAuthCallbackUrl(url: string): boolean {
  return /(code|access_token|id_token|refresh_token|error)=/.test(url);
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

export default function App(): React.JSX.Element {
  const redirectUri = useMemo(() => {
    const configuredRedirectUri = appConfig.redirectUri.trim();

    if (configuredRedirectUri === "" || configuredRedirectUri === "auto") {
      return Linking.createURL("callback");
    }

    return resolveExpoRedirectUri(configuredRedirectUri);
  }, []);

  const client = useMemo(
    () =>
      new GuardhouseClient({
        authority: appConfig.authority,
        clientId: appConfig.clientId,
        redirectUri,
        scope: appConfig.scope,
        audience: appConfig.audience,
        cryptoAdapter: expoCryptoAdapter,
        refreshTokenStorage: expoRefreshTokenStorageAdapter,
        sessionStorage: asyncSessionStorageAdapter,
        browser: expoWebBrowserAdapter,
        passkey: expoPasskeyAdapter,
        defaultEphemeralSession: true,
        userInfoOnLogin: true,
        endpoints: {
          authorization: appConfig.authorizationEndpoint,
          registration: appConfig.registrationEndpoint,
          token: appConfig.tokenEndpoint,
          revocation: appConfig.revocationEndpoint,
          passkeyChallenge: appConfig.passkeyChallengeEndpoint,
          passkeyAssertion: appConfig.passkeyAssertionEndpoint,
        },
      }),
    [redirectUri],
  );

  const [session, setSession] = useState<GuardhouseSession | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isBootstrapping, setIsBootstrapping] = useState(true);
  const [busyAction, setBusyAction] = useState<BusyAction | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    const restore = async () => {
      try {
        const restored = await client.restoreSession();

        if (!isMounted) {
          return;
        }

        if (restored?.session) {
          setSession(restored.session);
          setIsAuthenticated(true);
          return;
        }

        setSession(null);
        setIsAuthenticated(false);
      } catch (restoreError) {
        if (!isMounted) {
          return;
        }

        setSession(null);
        setIsAuthenticated(false);
        setError(toErrorMessage(restoreError));
      } finally {
        if (isMounted) {
          setIsBootstrapping(false);
        }
      }
    };

    void restore();

    return () => {
      isMounted = false;
    };
  }, [client]);

  const runAction = useCallback(
    async (action: BusyAction, fn: () => Promise<void>) => {
      setBusyAction(action);
      setError(null);

      try {
        await fn();
      } catch (actionError) {
        setError(toErrorMessage(actionError));
      } finally {
        setBusyAction(null);
      }
    },
    [],
  );

  const handleDeepLink = useCallback(
    async (incomingUrl: string) => {
      const parsedIncomingUrl = Linking.parse(incomingUrl);

      if (
        !incomingUrl ||
        parsedIncomingUrl.path !== "callback" ||
        !isAuthCallbackUrl(incomingUrl)
      ) {
        return;
      }

      setBusyAction("deepLink");

      try {
        const callback = parseOAuthCallbackUrl(incomingUrl);

        if (callback.error) {
          throw new Error(callback.errorDescription ?? callback.error);
        }

        if (callback.code) {
          const authResult = await client.exchangeCodeForTokens(callback.code);
          setSession(authResult.session);
          setIsAuthenticated(true);
          setError(null);
          return;
        }

        if (callback.accessToken) {
          const authResult = await client.applyRedirectTokens({
            accessToken: callback.accessToken,
            refreshToken: callback.refreshToken,
            idToken: callback.idToken,
            tokenType: callback.tokenType,
            expiresIn: callback.expiresIn,
            scope: callback.scope,
          });

          setSession(authResult.session);
          setIsAuthenticated(true);
          setError(null);
          return;
        }

        throw new Error(
          "Deep link callback did not include an authorization code or tokens.",
        );
      } catch (deepLinkError) {
        setError(toErrorMessage(deepLinkError));
      } finally {
        setBusyAction((currentAction) =>
          currentAction === "deepLink" ? null : currentAction,
        );
      }
    },
    [client],
  );

  useEffect(() => {
    const subscription = Linking.addEventListener("url", ({ url }) => {
      void handleDeepLink(url);
    });

    void Linking.getInitialURL().then((initialUrl) => {
      if (!initialUrl) {
        return;
      }

      void handleDeepLink(initialUrl);
    });

    return () => {
      subscription.remove();
    };
  }, [handleDeepLink]);

  const handleLogin = useCallback(() => {
    void runAction("login", async () => {
      const result = await client.loginWithBrowser({
        ephemeralSession: true,
      });

      setSession(result.session);
      setIsAuthenticated(true);
    });
  }, [client, runAction]);

  const handleRegister = useCallback(() => {
    void runAction("register", async () => {
      const result = await client.registerWithBrowser({
        ephemeralSession: true,
      });

      setSession(result.session);
      setIsAuthenticated(true);
    });
  }, [client, runAction]);

  const handlePasskeyLogin = useCallback(() => {
    void runAction("passkey", async () => {
      const result = await client.loginWithPasskey();

      setSession(result.session);
      setIsAuthenticated(true);
    });
  }, [client, runAction]);

  const handleRefresh = useCallback(() => {
    void runAction("refresh", async () => {
      const result = await client.refreshToken();

      setSession(result.session);
      setIsAuthenticated(true);
    });
  }, [client, runAction]);

  const handleLogout = useCallback(() => {
    void runAction("logout", async () => {
      await client.logout({
        revoke: true,
        revokeAccessToken: false,
        revokeRefreshToken: true,
      });

      setSession(null);
      setIsAuthenticated(false);
    });
  }, [client, runAction]);

  return (
    <SafeAreaProvider>
      {isBootstrapping ? (
        <View style={styles.loadingContainer}>
          <ActivityIndicator size="large" color="#1d4ed8" />
          <Text style={styles.loadingText}>Restoring session...</Text>
        </View>
      ) : isAuthenticated && session ? (
        <ProtectedScreen
          session={session}
          isBusy={busyAction !== null}
          busyAction={busyAction === "deepLink" ? null : busyAction}
          error={error}
          onRefresh={handleRefresh}
          onLogout={handleLogout}
        />
      ) : (
        <AuthScreen
          isBusy={busyAction !== null}
          busyAction={busyAction === "deepLink" ? null : busyAction}
          error={error}
          redirectUri={redirectUri}
          onLogin={handleLogin}
          onRegister={handleRegister}
          onPasskeyLogin={handlePasskeyLogin}
        />
      )}
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  loadingContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    backgroundColor: "#f2f4f8",
    gap: 12,
  },
  loadingText: {
    fontSize: 14,
    color: "#334155",
  },
});
