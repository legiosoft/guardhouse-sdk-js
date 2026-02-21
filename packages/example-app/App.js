import React, { useMemo, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  Platform,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
} from "react-native";
import { GuardhouseProvider, useAuth } from "@guardhouse/react-native";
import {
  GH_API_BASE_URL_ANDROID,
  GH_API_BASE_URL_IOS,
  GH_AUTHORITY,
  GH_CLIENT_ID,
  GH_REDIRECT_URI,
  GH_SCOPE,
} from "@env";

function parseScopes(scopeValue) {
  return (scopeValue || "openid profile email offline_access")
    .split(/\s+/)
    .map((scope) => scope.trim())
    .filter(Boolean);
}

const appConfig = {
  authority: GH_AUTHORITY?.trim() || "https://auth.example.com",
  clientId: GH_CLIENT_ID?.trim() || "your-client-id",
  redirectUri: GH_REDIRECT_URI?.trim() || "com.example.guardhouse://callback",
  scopes: parseScopes(GH_SCOPE),
  apiBaseUrl:
    (Platform.OS === "android" ? GH_API_BASE_URL_ANDROID : GH_API_BASE_URL_IOS)
      ?.trim()
      .replace(/\/+$/, "") ||
    (Platform.OS === "android"
      ? "http://10.0.2.2:3001"
      : "http://localhost:3001"),
};

function ExampleContent() {
  const {
    isAuthenticated,
    isLoading,
    error,
    user,
    login,
    logout,
    getAccessToken,
  } = useAuth();
  const [apiResult, setApiResult] = useState(null);
  const [apiError, setApiError] = useState(null);
  const [apiLoading, setApiLoading] = useState(false);

  const handleLogin = async () => {
    try {
      await login();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Login failed";
      Alert.alert("Login Failed", message);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
      setApiResult(null);
      setApiError(null);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Logout failed";
      Alert.alert("Logout Failed", message);
    }
  };

  const handleProtectedCall = async () => {
    try {
      setApiLoading(true);
      setApiResult(null);
      setApiError(null);

      const token = await getAccessToken();
      if (!token) {
        throw new Error("No access token available");
      }

      const response = await fetch(`${appConfig.apiBaseUrl}/protected`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const result = await response.json();
      setApiResult(result);
    } catch (err) {
      const message = err instanceof Error ? err.message : "Request failed";
      setApiError(message);
    } finally {
      setApiLoading(false);
    }
  };

  if (isLoading) {
    return (
      <SafeAreaView style={styles.centerContainer}>
        <StatusBar barStyle="dark-content" />
        <ActivityIndicator size="large" color="#1b6ef3" />
        <Text style={styles.loadingText}>Checking session...</Text>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="dark-content" backgroundColor="#f5f7fb" />
      <ScrollView contentContainerStyle={styles.content}>
        <Text style={styles.title}>Guardhouse Example App</Text>
        <Text style={styles.subtitle}>{appConfig.authority}</Text>

        {error ? <Text style={styles.errorText}>Error: {error}</Text> : null}

        {isAuthenticated && user ? (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Authenticated User</Text>
            <Text style={styles.row}>sub: {user.sub}</Text>
            <Text style={styles.row}>name: {user.name || "N/A"}</Text>
            <Text style={styles.row}>email: {user.email || "N/A"}</Text>
            <Text style={styles.row}>
              roles: {user.roles?.join(", ") || "N/A"}
            </Text>

            <TouchableOpacity
              style={styles.primaryButton}
              onPress={handleProtectedCall}
            >
              <Text style={styles.primaryButtonText}>
                {apiLoading ? "Calling API..." : "Call Protected API"}
              </Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.dangerButton}
              onPress={handleLogout}
            >
              <Text style={styles.primaryButtonText}>Logout</Text>
            </TouchableOpacity>
          </View>
        ) : (
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Authentication Required</Text>
            <Text style={styles.row}>Client ID: {appConfig.clientId}</Text>
            <Text style={styles.row}>
              Redirect URI: {appConfig.redirectUri}
            </Text>
            <TouchableOpacity
              style={styles.primaryButton}
              onPress={handleLogin}
            >
              <Text style={styles.primaryButtonText}>Login</Text>
            </TouchableOpacity>
          </View>
        )}

        <View style={styles.card}>
          <Text style={styles.cardTitle}>API Result</Text>
          <Text style={styles.row}>Base URL: {appConfig.apiBaseUrl}</Text>
          {apiError ? <Text style={styles.errorText}>{apiError}</Text> : null}
          {apiResult ? (
            <Text style={styles.resultText}>
              {JSON.stringify(apiResult, null, 2)}
            </Text>
          ) : (
            <Text style={styles.row}>No API response yet.</Text>
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

export default function App() {
  const providerProps = useMemo(
    () => ({
      authority: appConfig.authority,
      clientId: appConfig.clientId,
      redirectUri: appConfig.redirectUri,
      scopes: appConfig.scopes,
    }),
    [],
  );

  return (
    <GuardhouseProvider {...providerProps}>
      <ExampleContent />
    </GuardhouseProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#f5f7fb",
  },
  centerContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    backgroundColor: "#f5f7fb",
  },
  content: {
    padding: 20,
    gap: 16,
  },
  title: {
    fontSize: 28,
    fontWeight: "700",
    color: "#172033",
  },
  subtitle: {
    color: "#4d5b78",
  },
  loadingText: {
    marginTop: 10,
    color: "#4d5b78",
  },
  card: {
    backgroundColor: "#ffffff",
    borderRadius: 12,
    padding: 16,
    shadowColor: "#000000",
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.08,
    shadowRadius: 6,
    elevation: 2,
    gap: 8,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: "600",
    color: "#172033",
    marginBottom: 4,
  },
  row: {
    color: "#33415c",
    fontSize: 14,
  },
  primaryButton: {
    marginTop: 8,
    backgroundColor: "#1b6ef3",
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: "center",
  },
  dangerButton: {
    marginTop: 8,
    backgroundColor: "#c43030",
    paddingVertical: 12,
    borderRadius: 8,
    alignItems: "center",
  },
  primaryButtonText: {
    color: "#ffffff",
    fontWeight: "600",
  },
  errorText: {
    color: "#bf1f1f",
    fontSize: 13,
  },
  resultText: {
    color: "#1a2b49",
    fontFamily: "monospace",
    fontSize: 12,
  },
});
