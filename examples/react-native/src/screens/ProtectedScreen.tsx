import React, { useMemo } from "react";
import { Pressable, ScrollView, StyleSheet, Text, View } from "react-native";
import type { GuardhouseSession } from "@guardhouse/react-native";
import { jwtDecode } from "jwt-decode";
import { SafeAreaView } from "react-native-safe-area-context";

type ProtectedBusyAction =
  | "login"
  | "register"
  | "passkey"
  | "refresh"
  | "logout";

interface IdTokenClaims {
  sub: string;
  name?: string;
  email?: string;
  preferred_username?: string;
}

interface ProtectedScreenProps {
  session?: GuardhouseSession | null;
  isBusy?: boolean;
  busyAction?: ProtectedBusyAction | null;
  error?: string | null;
  onRefresh?: () => void;
  onLogout?: () => void;
}

function decodeIdToken(idToken: string | undefined): IdTokenClaims | null {
  if (!idToken) {
    return null;
  }

  try {
    const decoded = jwtDecode<IdTokenClaims>(idToken);
    if (typeof decoded.sub !== "string" || decoded.sub.trim() === "") {
      return null;
    }

    return decoded;
  } catch {
    return null;
  }
}

function formatToken(token: string | undefined): string {
  if (!token) {
    return "N/A";
  }

  if (token.length <= 40) {
    return token;
  }

  return `${token.slice(0, 20)}...${token.slice(-20)}`;
}

export default function ProtectedScreen({
  session,
  isBusy = false,
  busyAction = null,
  error = null,
  onRefresh,
  onLogout,
}: ProtectedScreenProps): React.JSX.Element {
  const decodedClaims = useMemo(
    () => decodeIdToken(session?.idToken),
    [session],
  );

  if (!session) {
    return (
      <SafeAreaView edges={["top", "left", "right"]} style={styles.safeArea}>
        <View style={styles.emptyState}>
          <Text style={styles.title}>Protected Screen</Text>
          <Text style={styles.subtitle}>
            This screen requires an authenticated session.
          </Text>
        </View>
      </SafeAreaView>
    );
  }

  const displayName =
    session.user?.name ||
    decodedClaims?.name ||
    decodedClaims?.preferred_username;
  const displayEmail =
    session.user?.email || decodedClaims?.email || "No email claim";
  const displaySubject =
    session.user?.sub || decodedClaims?.sub || "Unknown subject";

  return (
    <SafeAreaView edges={["top", "left", "right"]} style={styles.safeArea}>
      <ScrollView contentContainerStyle={styles.contentContainer}>
        <Text style={styles.title}>Protected Screen</Text>
        <Text style={styles.subtitle}>
          This screen is rendered only when the user is authenticated.
        </Text>

        <View style={styles.infoCard}>
          <InfoItem label="Name" value={displayName || "No name claim"} />
          <InfoItem label="Email" value={displayEmail} />
          <InfoItem label="Subject" value={displaySubject} />
          <InfoItem
            label="Token Expires"
            value={new Date(session.expiresAt * 1000).toISOString()}
          />
        </View>

        <View style={styles.infoCard}>
          <Text style={styles.cardLabel}>Access Token</Text>
          <Text selectable style={styles.tokenValue}>
            {formatToken(session.accessToken)}
          </Text>
        </View>

        <View style={styles.actionsRow}>
          <Pressable
            onPress={onRefresh}
            disabled={isBusy || !onRefresh}
            style={[styles.refreshButton, isBusy && styles.buttonDisabled]}
          >
            <Text style={styles.refreshButtonText}>
              {busyAction === "refresh" ? "Refreshing..." : "Refresh Token"}
            </Text>
          </Pressable>

          <Pressable
            onPress={onLogout}
            disabled={isBusy || !onLogout}
            style={[styles.logoutButton, isBusy && styles.buttonDisabled]}
          >
            <Text style={styles.logoutButtonText}>
              {busyAction === "logout" ? "Logging out..." : "Logout"}
            </Text>
          </Pressable>
        </View>

        {error ? <Text style={styles.errorText}>{error}</Text> : null}
      </ScrollView>
    </SafeAreaView>
  );
}

function InfoItem({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.infoRow}>
      <Text style={styles.infoLabel}>{label}</Text>
      <Text style={styles.infoValue}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: "#f2f4f8",
  },
  contentContainer: {
    padding: 20,
    gap: 14,
  },
  emptyState: {
    flex: 1,
    padding: 20,
    justifyContent: "center",
    gap: 10,
  },
  title: {
    fontSize: 24,
    fontWeight: "700",
    color: "#15284d",
  },
  subtitle: {
    fontSize: 14,
    color: "#455166",
    lineHeight: 20,
  },
  infoCard: {
    backgroundColor: "#ffffff",
    borderRadius: 12,
    borderWidth: 1,
    borderColor: "#d6dce7",
    padding: 14,
    gap: 10,
  },
  infoRow: {
    gap: 4,
  },
  infoLabel: {
    color: "#64748b",
    fontSize: 12,
    fontWeight: "700",
  },
  infoValue: {
    color: "#1f2937",
    fontSize: 14,
  },
  cardLabel: {
    color: "#64748b",
    fontSize: 12,
    fontWeight: "700",
  },
  tokenValue: {
    color: "#1f2937",
    fontSize: 12,
  },
  actionsRow: {
    flexDirection: "row",
    gap: 10,
  },
  refreshButton: {
    flex: 1,
    borderRadius: 10,
    backgroundColor: "#dbeafe",
    paddingVertical: 12,
    alignItems: "center",
  },
  refreshButtonText: {
    color: "#1d4ed8",
    fontWeight: "600",
  },
  logoutButton: {
    flex: 1,
    borderRadius: 10,
    backgroundColor: "#fee2e2",
    paddingVertical: 12,
    alignItems: "center",
  },
  logoutButtonText: {
    color: "#b91c1c",
    fontWeight: "600",
  },
  buttonDisabled: {
    opacity: 0.55,
  },
  errorText: {
    color: "#b42318",
    fontSize: 14,
  },
});
