import React, { useState } from "react";
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
  Alert,
} from "react-native";
import { useAuth } from "@guardhouse/react-native";

function ApiDemoScreen({ navigation }: any) {
  const { getAccessToken, user } = useAuth();
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchProtectedData = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const token = await getAccessToken();

      if (!token) {
        throw new Error("No access token available");
      }

      const response = await fetch("http://10.0.2.2:3001/protected", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
      Alert.alert(
        "Error",
        err instanceof Error ? err.message : "Unknown error",
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>API Demo</Text>

        {user ? (
          <>
            <Text style={styles.subtitle}>
              Test authentication by calling a protected API endpoint.
            </Text>

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
          </>
        ) : (
          <Text style={styles.subtitle}>Please log in to use API demo.</Text>
        )}

        <TouchableOpacity
          style={[styles.button, styles.secondaryButton]}
          onPress={() => navigation.navigate("Home")}
        >
          <Text style={styles.buttonText}>Back to Home</Text>
        </TouchableOpacity>

        <Text style={styles.note}>
          Note: For Android, use 10.0.2.2 to access localhost from the emulator.
          For iOS, use localhost.
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
