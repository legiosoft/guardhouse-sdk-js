import React, { useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
  Platform,
  TextInput,
} from "react-native";
import { appConfig } from "../config";

function ApiDemoScreen({ navigation }: any) {
  const [accessToken, setAccessToken] = useState("");
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchProtectedData = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      if (accessToken.trim() === "") {
        throw new Error("No access token available");
      }

      const response = await fetch(`${appConfig.apiBaseUrl}/protected`, {
        headers: {
          Authorization: `Bearer ${accessToken.trim()}`,
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>API Demo</Text>

        <Text style={styles.subtitle}>
          Paste an access token from the main App.tsx flow and call the
          protected endpoint manually.
        </Text>

        <View style={styles.tokenInputContainer}>
          <Text style={styles.tokenLabel}>Access Token</Text>
          <TextInput
            style={styles.tokenInput}
            value={accessToken}
            onChangeText={setAccessToken}
            autoCapitalize="none"
            autoCorrect={false}
            placeholder="Paste access token"
            placeholderTextColor="#666"
            multiline
          />
        </View>

        <TouchableOpacity
          style={[styles.button, loading && styles.buttonDisabled]}
          onPress={fetchProtectedData}
          disabled={loading}
        >
          {loading ? (
            <ActivityIndicator color="#fff" />
          ) : (
            <Text style={styles.buttonText}>Fetch Protected Data</Text>
          )}
        </TouchableOpacity>

        {error && (
          <View style={styles.errorContainer}>
            <Text style={styles.errorTitle}>Error:</Text>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        )}

        {result && (
          <View style={styles.resultContainer}>
            <Text style={styles.resultTitle}>Response:</Text>
            <Text style={styles.resultText}>
              {JSON.stringify(result, null, 2)}
            </Text>
          </View>
        )}

        <TouchableOpacity
          style={[styles.button, styles.secondaryButton]}
          onPress={() => navigation.navigate("Home")}
        >
          <Text style={styles.buttonText}>Back to Home</Text>
        </TouchableOpacity>

        <Text style={styles.note}>
          API base URL ({Platform.OS}): {appConfig.apiBaseUrl}
        </Text>
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#242424",
  },
  content: {
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: "bold",
    color: "#fff",
    marginBottom: 10,
  },
  subtitle: {
    fontSize: 16,
    color: "#888",
    marginBottom: 20,
  },
  tokenInputContainer: {
    backgroundColor: "#1a1a1a",
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#333",
    padding: 12,
    marginBottom: 12,
  },
  tokenLabel: {
    fontSize: 12,
    color: "#888",
    marginBottom: 6,
  },
  tokenInput: {
    color: "#ddd",
    fontSize: 12,
    fontFamily: "monospace",
  },
  button: {
    backgroundColor: "#646cff",
    padding: 15,
    borderRadius: 8,
    alignItems: "center",
    marginBottom: 10,
  },
  buttonDisabled: {
    backgroundColor: "#444",
  },
  buttonText: {
    color: "#fff",
    fontSize: 16,
    fontWeight: "bold",
  },
  secondaryButton: {
    backgroundColor: "transparent",
    borderWidth: 1,
    borderColor: "#646cff",
  },
  errorContainer: {
    backgroundColor: "#2a0a0a",
    borderRadius: 8,
    padding: 15,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: "#a00",
  },
  errorTitle: {
    fontSize: 16,
    fontWeight: "bold",
    color: "#faa",
    marginBottom: 5,
  },
  errorText: {
    fontSize: 14,
    color: "#faa",
  },
  resultContainer: {
    backgroundColor: "#1a1a1a",
    borderRadius: 8,
    padding: 15,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: "#333",
  },
  resultTitle: {
    fontSize: 16,
    fontWeight: "bold",
    color: "#fff",
    marginBottom: 10,
  },
  resultText: {
    fontSize: 12,
    color: "#646cff",
    fontFamily: "monospace",
  },
  note: {
    fontSize: 12,
    color: "#666",
    marginTop: 10,
    textAlign: "center",
  },
});

export default ApiDemoScreen;
