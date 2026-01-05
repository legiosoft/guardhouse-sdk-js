/**
 * Example React Native App using Guardhouse SDK
 * 
 * SECURITY NOTES:
 * 
 * 1. requireBiometrics: true
 *    - Triggers FaceID/TouchID/Fingerprint when accessing tokens
 *    - Provides additional security layer beyond device lock
 *    - User-friendly (only authenticates when using app)
 * 
 * 2. Android: Set android:launchMode="singleTask" in AndroidManifest.xml
 *    - Critical for preventing task hijacking attacks
 *    - OWASP M-STG-RES-008 requirement
 * 
 * 3. iOS: Configure deep link scheme in Info.plist
 *    - Required for OAuth callback handling
 *    - Prevents other apps from intercepting redirect
 */

import React from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  View,
  Button,
  Alert,
  ActivityIndicator,
} from 'react-native';
import { GuardhouseProvider, useAuth } from '@guardhouse/react-native';

function App() {
  const {
    isAuthenticated,
    isLoading,
    error,
    user,
    login,
    logout,
    getAccessToken,
  } = useAuth();

  const handleLogin = async () => {
    try {
      await login();
    } catch (err: any) {
      Alert.alert('Login Failed', err.message || 'Unknown error');
    }
  };

  const handleLogout = async () => {
    try {
      await logout();
    } catch (err: any) {
      Alert.alert('Logout Failed', err.message || 'Unknown error');
    }
  };

  const handleApiCall = async () => {
    try {
      // Will trigger biometric prompt if requireBiometrics is true
      const token = await getAccessToken();

      if (!token) {
        Alert.alert('Error', 'No access token available');
        return;
      }

      // Example: Call your protected API
      // const response = await fetch('https://api.example.com/protected', {
      //   headers: { Authorization: `Bearer ${token}` },
      // });

      Alert.alert('Success', 'Access token obtained successfully');
      console.log('Token:', token.substring(0, 20) + '...');
    } catch (err: any) {
      if (err.name === 'BiometricAuthFailedError') {
        Alert.alert(
          'Biometric Cancelled',
          'You cancelled the biometric authentication',
        );
      } else if (err.name === 'SessionExpiredError') {
        Alert.alert(
          'Session Expired',
          'Your session has expired. Please login again.',
        );
        // Redirect to login screen here
      } else if (err.name === 'RefreshTokenError') {
        Alert.alert(
          'Refresh Failed',
          'Failed to refresh token. Please login again.',
        );
        // Redirect to login screen here
      } else {
        Alert.alert('Error', err.message || 'Unknown error');
      }
    }
  };

  if (isLoading) {
    return (
      <SafeAreaView style={styles.centerContainer}>
        <StatusBar barStyle="dark-content" />
        <ActivityIndicator size="large" color="#646cff" />
        <Text style={styles.loadingText}>Loading...</Text>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="dark-content" backgroundColor="#f5f5f5" />
      <ScrollView contentContainerStyle={styles.scrollContainer}>
        <View style={styles.content}>
          <Text style={styles.title}>Guardhouse React Native SDK</Text>

          {error && (
            <View style={styles.errorContainer}>
              <Text style={styles.errorText}>Error: {error}</Text>
            </View>
          )}

          {isAuthenticated && user ? (
            <>
              <View style={styles.card}>
                <Text style={styles.cardTitle}>Welcome!</Text>
                <View style={styles.userInfo}>
                  <Text style={styles.infoLabel}>Subject ID:</Text>
                  <Text style={styles.infoValue}>{user.sub}</Text>
                </View>

                {user.name && (
                  <View style={styles.userInfo}>
                    <Text style={styles.infoLabel}>Name:</Text>
                    <Text style={styles.infoValue}>{user.name}</Text>
                  </View>
                )}

                {user.email && (
                  <View style={styles.userInfo}>
                    <Text style={styles.infoLabel}>Email:</Text>
                    <Text style={styles.infoValue}>{user.email}</Text>
                  </View>
                )}

                {user.roles && user.roles.length > 0 && (
                  <View style={styles.userInfo}>
                    <Text style={styles.infoLabel}>Roles:</Text>
                    <Text style={styles.infoValue}>{user.roles.join(', ')}</Text>
                  </View>
                )}
              </View>

              <View style={styles.buttonGroup}>
                <Button
                  title="Call Protected API"
                  onPress={handleApiCall}
                  color="#646cff"
                />
                <Button
                  title="Logout"
                  onPress={handleLogout}
                  color="#dc2626"
                />
              </View>
            </>
          ) : (
            <View style={styles.card}>
              <Text style={styles.cardTitle}>Authentication Required</Text>
              <Text style={styles.description}>
                This app demonstrates the Guardhouse React Native SDK with:
              </Text>
              <Text style={styles.feature}>
                • OAuth 2.0 Authorization Code Flow with PKCE
              </Text>
              <Text style={styles.feature}>
                • Silent token refresh with mutex
              </Text>
              <Text style={styles.feature}>
                • Biometric authentication (FaceID/TouchID/Fingerprint)
              </Text>
              <Text style={styles.feature}>
                • Secure Keychain storage
              </Text>
              <Text style={styles.feature}>
                • Concurrency-safe token management
              </Text>

              <View style={styles.loginButton}>
                <Button
                  title="Login with Biometrics"
                  onPress={handleLogin}
                  color="#646cff"
                />
              </View>
            </View>
          )}

          <View style={styles.infoCard}>
            <Text style={styles.infoCardTitle}>Security Features</Text>
            <Text style={styles.infoCardText}>
              <Text style={styles.bullet}>• Hardware-backed encryption</Text>
              <Text style={styles.bullet}>• Biometric access control</Text>
              <Text style={styles.bullet}>• Silent token refresh</Text>
              <Text style={styles.bullet}>• CSRF protection (state validation)</Text>
              <Text style={styles.bullet}>• JWT algorithm whitelisting</Text>
              <Text style={styles.bullet}>• Token expiration checking</Text>
            </Text>
          </View>

          <View style={styles.infoCard}>
            <Text style={styles.infoCardTitle}>Current Status</Text>
            <Text style={styles.infoCardText}>
              Authenticated: <Text style={styles.statusValue}>
                {isAuthenticated ? 'Yes' : 'No'}
              </Text>
            </Text>
            <Text style={styles.infoCardText}>
              Loading: <Text style={styles.statusValue}>
                {isLoading ? 'Yes' : 'No'}
              </Text>
            </Text>
            <Text style={styles.infoCardText}>
              Has Access Token: <Text style={styles.statusValue}>
                {user ? 'Yes' : 'No'}
              </Text>
            </Text>
          </View>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  centerContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f5f5f5',
  },
  scrollContainer: {
    flexGrow: 1,
  },
  content: {
    padding: 20,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#1a1a1a',
    marginBottom: 20,
  },
  loadingText: {
    fontSize: 16,
    color: '#666',
    marginTop: 10,
  },
  errorContainer: {
    backgroundColor: '#fee2e2',
    borderWidth: 1,
    borderColor: '#dc2626',
    borderRadius: 8,
    padding: 12,
    marginBottom: 20,
  },
  errorText: {
    color: '#dc2626',
    fontSize: 14,
  },
  card: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    padding: 20,
    marginBottom: 20,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  cardTitle: {
    fontSize: 20,
    fontWeight: '600',
    color: '#1a1a1a',
    marginBottom: 15,
  },
  description: {
    fontSize: 14,
    color: '#666',
    lineHeight: 20,
    marginBottom: 20,
  },
  feature: {
    fontSize: 14,
    color: '#333',
    marginBottom: 8,
    paddingLeft: 10,
  },
  userInfo: {
    marginBottom: 15,
    paddingBottom: 10,
    borderBottomWidth: 1,
    borderBottomColor: '#e5e5e5',
  },
  infoLabel: {
    fontSize: 12,
    color: '#888',
    marginBottom: 4,
    textTransform: 'uppercase',
    fontWeight: '500',
  },
  infoValue: {
    fontSize: 16,
    color: '#1a1a1a',
    fontFamily: 'monospace',
  },
  buttonGroup: {
    gap: 10,
  },
  loginButton: {
    marginTop: 20,
  },
  infoCard: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    padding: 20,
    marginBottom: 20,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  infoCardTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#1a1a1a',
    marginBottom: 10,
  },
  infoCardText: {
    fontSize: 14,
    color: '#333',
    lineHeight: 22,
  },
  bullet: {
    fontSize: 14,
    color: '#555',
  },
  statusValue: {
    fontWeight: '600',
    color: user?.roles?.length > 0 ? '#28a745' : '#666',
  },
});

export default App;

/**
 * SECURITY CONFIGURATION REQUIRED
 * 
 * To use this example app, you must configure:
 * 
 * 1. Android (AndroidManifest.xml):
 *    <activity
 *      android:name=".MainActivity"
 *      android:launchMode="singleTask"  <!-- CRITICAL: Prevents task hijacking -->
 *      ...>
 *      <intent-filter>
 *        <action android:name="android.intent.action.VIEW" />
 *        <category android:name="android.intent.category.DEFAULT" />
 *        <category android:name="android.intent.category.BROWSABLE" />
 *        <data
 *          android:scheme="com.yourapp"  <!-- Change to your scheme -->
 *          android:host="callback" />
 *      </intent-filter>
 *    </activity>
 * 
 * 2. iOS (Info.plist):
 *    <key>CFBundleURLTypes</key>
 *    <array>
 *      <dict>
 *        <key>CFBundleURLSchemes</key>
 *        <array>
 *          <string>com.yourapp</string>  <!-- Change to your scheme -->
 *        </array>
 *      </dict>
 *    </array>
 * 
 * SECURITY CHECKLIST:
 * 
 * [x] OAuth 2.0 Authorization Code Flow with PKCE (S256)
 * [x] Cryptographically secure random for state/nonce (CSPRNG)
 * [x] State parameter validation (CSRF protection)
 * [x] Silent token refresh with mutex (concurrency control)
 * [x] JWT expiration checking (exp claim)
 * [x] Hardware-backed Keychain/Keystore storage
 * [x] Biometric authentication support
 * [x] InAppBrowser for secure authentication windows
 * [x] TLS enforcement
 * [x] Deep link sanitization
 * [x] Log redaction for sensitive data
 * [x] Algorithm whitelisting (RS256, HS256, etc.)
 * [ ] Android: launchMode="singleTask" (developer's responsibility)
 * [ ] iOS: Deep link scheme in Info.plist (developer's responsibility)
 */
