import React from "react";
import {
  View,
  Text,
  StyleSheet,
  TouchableOpacity,
  ScrollView,
  ActivityIndicator,
} from "react-native";
import { useAuth } from "@guardhouse/react-native";

function ProtectedScreen({ navigation }: any) {
  const { user, isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <View style={styles.centerContainer}>
        <ActivityIndicator size="large" color="#646cff" />
        <Text style={styles.loadingText}>Loading...</Text>
      </View>
    );
  }

  if (!isAuthenticated) {
    return (
      <View style={styles.container}>
        <View style={styles.content}>
          <Text style={styles.title}>Access Denied</Text>
          <Text style={styles.subtitle}>
            You need to log in to access this page.
          </Text>
          <TouchableOpacity
            style={styles.button}
            onPress={() => navigation.navigate("Home")}
          >
            <Text style={styles.buttonText}>Go to Home</Text>
          </TouchableOpacity>
        </View>
      </View>
    );
  }

  return (
    <ScrollView style={styles.container}>
      <View style={styles.content}>
        <Text style={styles.title}>Protected Page</Text>
        <Text style={styles.subtitle}>
          Welcome to the protected page! You are authenticated as{" "}
          {user?.name || user?.sub}.
        </Text>

        <View style={styles.infoContainer}>
          <InfoItem label="User ID" value={user?.sub || "N/A"} />
          <InfoItem label="Name" value={user?.name || "N/A"} />
          <InfoItem label="Email" value={user?.email || "N/A"} />
          <InfoItem label="Roles" value={user?.roles?.join(", ") || "None"} />
        </View>

        <TouchableOpacity
          style={styles.button}
          onPress={() => navigation.navigate("ApiDemo")}
        >
          <Text style={styles.buttonText}>API Demo</Text>
        </TouchableOpacity>

        <TouchableOpacity
          style={[styles.button, styles.secondaryButton]}
          onPress={() => navigation.navigate("Home")}
        >
          <Text style={styles.buttonText}>Back to Home</Text>
        </TouchableOpacity>
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
  loadingText: {
    color: "#888",
    marginTop: 10,
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
    borderBottomWidth: 1,
    borderBottomColor: "#333",
    paddingBottom: 10,
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
  secondaryButton: {
    backgroundColor: "transparent",
    borderWidth: 1,
    borderColor: "#646cff",
  },
});

export default ProtectedScreen;
