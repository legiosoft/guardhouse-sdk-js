/**
 * Usage Example: Enabling Biometric Authentication
 *
 * This example demonstrates how to enable biometric authentication
 * (FaceID/TouchID) for accessing stored tokens.
 */

import React from "react";
import { View, Text, Button, StyleSheet, Alert } from "react-native";
import { GuardhouseProvider, useAuth } from "@guardhouse/react-native";

function BiometricExample() {
  const {
    isAuthenticated,
    isLoading,
    user,
    login,
    logout,
    getAccessToken,
    error,
  } = useAuth();

  const handleLogin = async () => {
    try {
      await login();
    } catch (err: any) {
      Alert.alert("Login Failed", err.message);
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
    } catch (err: any) {
      Alert.alert("Logout Failed", err.message);
    }
  };

  const handleApiCall = async () => {
    try {
      // When requireBiometrics is true, this will trigger:
      // - FaceID/TouchID prompt on iOS
      // - Fingerprint/Face Unlock prompt on Android
      const token = await getAccessToken();

      if (!token) {
        Alert.alert("Error", "Failed to get access token");
        return;
      }

      // Use the token to call your API
      console.log("Access token obtained");

      Alert.alert("Success", "Access token obtained successfully");
    } catch (err: any) {
      if (err.name === "BiometricAuthFailedError") {
        Alert.alert(
          "Biometric Cancelled",
          "You cancelled biometric authentication",
        );
      } else if (err.name === "SessionExpiredError") {
        Alert.alert(
          "Session Expired",
          "Your session has expired. Please login again.",
        );
        // Redirect to login screen
      } else if (err.name === "RefreshTokenError") {
        Alert.alert(
          "Refresh Failed",
          "Failed to refresh token. Please login again.",
        );
        // Redirect to login screen
      } else {
        Alert.alert("Error", err.message);
      }
    }
  };

  if (isLoading) {
    return (
      <View style={styles.centerContainer}>
        <Text style={styles.text}>Loading...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Biometric Authentication Example</Text>

      {error && (
        <View style={styles.errorContainer}>
          <Text style={styles.errorText}>Error: {error}</Text>
        </View>
      )}

      {isAuthenticated && user ? (
        <View style={styles.content}>
          <Text style={styles.welcome}>Welcome, {user.name || user.sub}!</Text>

          <View style={styles.userInfo}>
            <Text style={styles.infoLabel}>Subject ID:</Text>
            <Text style={styles.infoValue}>{user.sub}</Text>
          </View>

          {user.email && (
            <View style={styles.userInfo}>
              <Text style={styles.infoLabel}>Email:</Text>
              <Text style={styles.infoValue}>{user.email}</Text>
            </View>
          )}

          {user.roles && user.roles.length > 0 && (
            <View style={styles.userInfo}>
              <Text style={styles.infoLabel}>Roles:</Text>
              <Text style={styles.infoValue}>{user.roles.join(", ")}</Text>
            </View>
          )}

          <Button
            title="Call Protected API"
            onPress={handleApiCall}
            color="#646cff"
          />

          <Button title="Logout" onPress={handleLogout} color="#dc2626" />
        </View>
      ) : (
        <View style={styles.content}>
          <Text style={styles.description}>
            This app requires biometric authentication to access your tokens.
            {"\n\n"}
            When you call APIs, you'll be prompted to authenticate with FaceID,
            TouchID, or fingerprint.
          </Text>

          <Button
            title="Login with Biometrics"
            onPress={handleLogin}
            color="#646cff"
          />
        </View>
      )}
    </View>
  );
}

function App() {
  return (
    <GuardhouseProvider
      authority="https://your-guardhouse-domain.com"
      clientId="your-client-id"
      redirectUri="com.example.app://callback"
      scopes={["openid", "profile", "offline_access"]}
      requireBiometrics={true} // Enable biometric authentication
    >
      <BiometricExample />
    </GuardhouseProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    padding: 20,
    backgroundColor: "#f5f5f5",
  },
  centerContainer: {
    flex: 1,
    justifyContent: "center",
    alignItems: "center",
  },
  title: {
    fontSize: 24,
    fontWeight: "bold",
    marginBottom: 20,
    color: "#1a1a1a",
  },
  content: {
    flex: 1,
  },
  welcome: {
    fontSize: 18,
    fontWeight: "600",
    marginBottom: 20,
    color: "#1a1a1a",
  },
  description: {
    fontSize: 14,
    color: "#666",
    marginBottom: 30,
    lineHeight: 20,
  },
  userInfo: {
    marginBottom: 15,
    padding: 12,
    backgroundColor: "#fff",
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#e5e5e5",
  },
  infoLabel: {
    fontSize: 12,
    color: "#666",
    marginBottom: 4,
    textTransform: "uppercase",
  },
  infoValue: {
    fontSize: 14,
    color: "#1a1a1a",
  },
  errorContainer: {
    backgroundColor: "#fee2e2",
    borderWidth: 1,
    borderColor: "#dc2626",
    borderRadius: 8,
    padding: 12,
    marginBottom: 20,
  },
  errorText: {
    color: "#dc2626",
    fontSize: 14,
  },
  text: {
    fontSize: 16,
    color: "#1a1a1a",
  },
});

export default App;

/**
 * Key Features Demonstrated:
 *
 * 1. Biometric Requirement:
 *    - Set `requireBiometrics={true}` in GuardhouseProvider
 *    - Tokens are stored with BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE
 *    - Accessing tokens triggers native biometric prompt
 *
 * 2. Silent Token Refresh:
 *    - Tokens automatically refresh when expired
 *    - Multiple concurrent refresh requests are prevented
 *    - JWT expiration is checked directly from token
 *
 * 3. Error Handling:
 *    - BiometricAuthFailedError: User cancelled biometrics
 *    - SessionExpiredError: No refresh token available
 *    - RefreshTokenError: Refresh request failed
 *
 * 4. Concurrency Control:
 *    - PromiseLock ensures only one refresh request
 *    - Prevents multiple simultaneous refresh attempts
 *
 * 5. User State:
 *    - isAuthenticated: Derived from valid token presence
 *    - user: Parsed ID token payload (strictly typed)
 *    - accessToken: Current access token (null if not available)
 *
 * Usage:
 *
 * ```tsx
 * const { isAuthenticated, user, getAccessToken } = useAuth();
 *
 * // Call API with automatic token refresh and biometric auth
 * const fetchData = async () => {
 *   try {
 *     const token = await getAccessToken();
 *     // User will see biometric prompt if requireBiometrics is true
 *     const response = await fetch('https://api.example.com/data', {
 *       headers: { Authorization: `Bearer ${token}` },
 *     });
 *     return await response.json();
 *   } catch (error) {
 *     if (error.name === 'BiometricAuthFailedError') {
 *       // User cancelled
 *     } else if (error.name === 'SessionExpiredError') {
 *       // Session expired, redirect to login
 *     }
 *   }
 * };
 * ```
 */
