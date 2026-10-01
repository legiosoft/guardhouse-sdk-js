import React, { useCallback, useEffect, useMemo, useState } from "react";
import { Button, Text, View } from "react-native";

import {
  GuardhouseClient,
  type GuardhouseSession,
} from "@guardhouse/react-native";

/**
 * Minimal biometric-storage example for the v2 transaction-bound API.
 *
 * `requireBiometrics` protects the namespaced v3 session and refresh token in
 * the platform keychain. Browser login itself remains Authorization Code +
 * PKCE and is completed only through Core's active authorization transaction.
 */
export function BiometricAuthenticationExample() {
  const client = useMemo(
    () =>
      new GuardhouseClient({
        authority: "https://auth.example.com",
        clientId: "native-client",
        redirectUri: "com.example.app://callback",
        scope: "openid profile offline_access",
        requireBiometrics: true,
      }),
    [],
  );
  const [session, setSession] = useState<GuardhouseSession | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let active = true;

    void client
      .restoreSession()
      .then((result) => {
        if (active) setSession(result?.session ?? null);
      })
      .catch((reason: unknown) => {
        if (active) {
          setError(
            reason instanceof Error ? reason : new Error(String(reason)),
          );
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, [client]);

  const login = useCallback(async () => {
    setError(null);
    setLoading(true);
    try {
      const result = await client.loginWithBrowser({
        ephemeralSession: false,
      });
      setSession(result.session);
    } catch (reason) {
      setError(reason instanceof Error ? reason : new Error(String(reason)));
    } finally {
      setLoading(false);
    }
  }, [client]);

  const logout = useCallback(async () => {
    setError(null);
    try {
      await client.logout({ revoke: true });
      setSession(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason : new Error(String(reason)));
    }
  }, [client]);

  return (
    <View>
      <Text>
        {loading
          ? "Checking secure session…"
          : session
            ? `Signed in as ${session.user?.name ?? session.user?.sub ?? "user"}`
            : "Signed out"}
      </Text>
      {error ? <Text accessibilityRole="alert">{error.message}</Text> : null}
      {session ? (
        <Button title="Sign out" onPress={() => void logout()} />
      ) : (
        <Button
          title="Sign in"
          onPress={() => void login()}
          disabled={loading}
        />
      )}
    </View>
  );
}
