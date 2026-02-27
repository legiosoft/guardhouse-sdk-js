import React from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";

type AuthBusyAction = "login" | "register" | "passkey" | "refresh" | "logout";

interface AuthScreenProps {
  isBusy: boolean;
  busyAction: AuthBusyAction | null;
  error: string | null;
  redirectUri: string;
  onLogin: () => void;
  onRegister: () => void;
  onPasskeyLogin: () => void;
}

export default function AuthScreen({
  isBusy,
  busyAction,
  error,
  redirectUri,
  onLogin,
  onRegister,
  onPasskeyLogin,
}: AuthScreenProps): React.JSX.Element {
  return (
    <SafeAreaView edges={["top", "left", "right"]} style={styles.safeArea}>
      <ScrollView contentContainerStyle={styles.contentContainer}>
        <Text style={styles.title}>Guardhouse Authentication</Text>
        <Text style={styles.subtitle}>
          Login and signup open an ephemeral browser session. Returning users
          can sign in directly with a passkey.
        </Text>

        <View style={styles.actionsRow}>
          <Pressable
            onPress={onLogin}
            disabled={isBusy}
            style={[styles.primaryButton, isBusy && styles.buttonDisabled]}
          >
            <Text style={styles.primaryButtonText}>
              {busyAction === "login" ? "Logging in..." : "Login"}
            </Text>
          </Pressable>

          <Pressable
            onPress={onRegister}
            disabled={isBusy}
            style={[styles.secondaryButton, isBusy && styles.buttonDisabled]}
          >
            <Text style={styles.secondaryButtonText}>
              {busyAction === "register" ? "Registering..." : "Register"}
            </Text>
          </Pressable>

          <View style={styles.passkeyContainer}>
            <Pressable
              onPress={onPasskeyLogin}
              disabled={isBusy}
              style={[styles.passkeyButton, isBusy && styles.buttonDisabled]}
            >
              <Text style={styles.passkeyGlyph}>ID</Text>
            </Pressable>
            <Text style={styles.passkeyLabel}>
              {busyAction === "passkey" ? "Verifying" : "Passkey"}
            </Text>
          </View>
        </View>

        {error ? <Text style={styles.errorText}>{error}</Text> : null}

        <Text selectable style={styles.redirectText}>
          Redirect URI: {redirectUri}
        </Text>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: "#f2f4f8",
  },
  contentContainer: {
    padding: 20,
    gap: 18,
  },
  title: {
    fontSize: 24,
    fontWeight: "700",
    color: "#16233b",
  },
  subtitle: {
    fontSize: 14,
    color: "#455166",
    lineHeight: 20,
  },
  actionsRow: {
    gap: 12,
  },
  primaryButton: {
    backgroundColor: "#1d4ed8",
    borderRadius: 12,
    paddingVertical: 14,
    alignItems: "center",
  },
  primaryButtonText: {
    color: "#ffffff",
    fontSize: 16,
    fontWeight: "600",
  },
  secondaryButton: {
    backgroundColor: "#ffffff",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "#cad2e0",
    paddingVertical: 14,
    alignItems: "center",
  },
  secondaryButtonText: {
    color: "#1f2f4d",
    fontSize: 16,
    fontWeight: "600",
  },
  passkeyContainer: {
    alignItems: "center",
    gap: 6,
  },
  passkeyButton: {
    width: 72,
    height: 72,
    borderRadius: 36,
    backgroundColor: "#0f766e",
    alignItems: "center",
    justifyContent: "center",
  },
  passkeyGlyph: {
    color: "#ffffff",
    fontSize: 24,
    fontWeight: "700",
  },
  passkeyLabel: {
    fontSize: 13,
    color: "#223041",
    fontWeight: "600",
  },
  buttonDisabled: {
    opacity: 0.55,
  },
  errorText: {
    color: "#b42318",
    fontSize: 14,
  },
  redirectText: {
    fontSize: 11,
    color: "#5d6b82",
  },
});
