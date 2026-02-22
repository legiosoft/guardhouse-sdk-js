import React from "react";
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

function HomeScreen({ navigation }: any) {
  const { user, isAuthenticated, isLoading, login, logout, error } = useAuth();

  const handleLogin = async () => {
    try {
      await login();
    } catch (loginError) {
      Alert.alert(
        "Login Failed",
        loginError instanceof Error
          ? loginError.message
          : "Unknown login error",
      );
    }
  };

  const handleLogout = async () => {
    await logout();
  };

  if (isLoading) {
    return (
      <View style={styles.centerContainer}>
        <ActivityIndicator size="large" color="#646cff" />
        <Text style={styles.loadingText}>Loading...</Text>
      </View>
    );
  }

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>Welcome to Guardhouse</Text>

        {error ? (
          <View style={styles.errorContainer}>
            <Text style={styles.errorTitle}>Authentication Error</Text>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        ) : null}

        {isAuthenticated && user ? (
          <>
            <Text style={styles.subtitle}>
              You are logged in as {user.name || user.sub}
            </Text>

            <View style={styles.infoContainer}>
              <InfoItem label="Subject" value={user.sub} />
              {user.name && <InfoItem label="Name" value={user.name} />}
              {user.email && <InfoItem label="Email" value={user.email} />}
              {user.roles && user.roles.length > 0 && (
                <InfoItem label="Roles" value={user.roles.join(", ")} />
              )}
            </View>

            <TouchableOpacity
              style={styles.button}
              onPress={() => navigation.navigate("Protected")}
            >
              <Text style={styles.buttonText}>Protected Page</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.button}
              onPress={() => navigation.navigate("ApiDemo")}
            >
              <Text style={styles.buttonText}>API Demo</Text>
            </TouchableOpacity>

            <TouchableOpacity
              style={[styles.button, styles.logoutButton]}
              onPress={handleLogout}
            >
              <Text style={styles.buttonText}>Logout</Text>
            </TouchableOpacity>
          </>
        ) : (
          <>
            <Text style={styles.subtitle}>
              Please log in to access the application.
            </Text>

            <TouchableOpacity style={styles.button} onPress={handleLogin}>
              <Text style={styles.buttonText}>Login</Text>
            </TouchableOpacity>
          </>
        )}
      </View>
    </ScrollView>
  );
}

function InfoItem({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.infoItem}>
      <Text style={styles.infoLabel}>{label}</Text>
      <Text style={styles.infoValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: "#242424",
  },
  centerContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
    backgroundColor: "#242424",
  },
  content: {
    padding: 20,
  },
  title: {
    fontSize: 28,
    fontWeight: "bold",
    color: "#fff",
    marginBottom: 10,
  },
  subtitle: {
    fontSize: 16,
    color: "#888",
    marginBottom: 20,
  },
  loadingText: {
    color: "#888",
    marginTop: 10,
  },
  errorContainer: {
    backgroundColor: "#2a0a0a",
    borderRadius: 8,
    padding: 12,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: "#a00",
  },
  errorTitle: {
    color: "#faa",
    fontSize: 14,
    fontWeight: "bold",
    marginBottom: 6,
  },
  errorText: {
    color: "#faa",
    fontSize: 13,
  },
  infoContainer: {
    backgroundColor: "#1a1a1a",
    borderRadius: 8,
    padding: 15,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: "#333",
  },
  infoItem: {
    marginBottom: 15,
  },
  infoLabel: {
    fontSize: 12,
    color: "#888",
    marginBottom: 5,
  },
  infoValue: {
    fontSize: 14,
    color: "#fff",
    fontFamily: "monospace",
  },
  button: {
    backgroundColor: "#646cff",
    padding: 15,
    borderRadius: 8,
    alignItems: "center",
    marginBottom: 10,
  },
  buttonText: {
    color: "#fff",
    fontSize: 16,
    fontWeight: "bold",
  },
  logoutButton: {
    backgroundColor: "#a00",
  },
});

export default HomeScreen;
