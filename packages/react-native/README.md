# @guardhouse/react-native

A production-grade, audit-ready React Native SDK that implements OAuth 2.0 Authorization Code Flow with PKCE for mobile applications.

## Features

- **Secure Authentication**: OAuth 2.0 Authorization Code Flow with PKCE (S256)
- **Secure Storage**: Hardware-backed Keychain storage for tokens
- **Secure Browser**: InAppBrowser for isolated authentication sessions
- **Deep Linking**: Full support for deep link callbacks
- **Type-Safe**: Fully typed with TypeScript
- **Auto-Refresh**: Automatic token refresh when expired
- **Security-Focused**: OWASP MASVS compliant, audit-ready

## Security Architecture

This SDK is designed with security as the top priority:

### OWASP MASVS Compliance

- **M1 - Secure Storage**: Uses `react-native-keychain` for hardware-backed storage
- **M2 - Secure Authentication**: Uses `InAppBrowser` for secure browser sessions
- **M3 - Secure Communication**: Enforces TLS, strict SSL verification
- **M5 - Cryptography**: Uses `@guardhouse/core` for PKCE generation with S256
- **M7 - Code Quality**: Fully typed, comprehensive error handling

### Security Features

- **State Validation**: Strict CSRF protection with state parameter validation
- **Token Security**: JWT validation with algorithm whitelisting (RS256, HS256, etc.)
- **Deep Link Sanitization**: Sanitizes all incoming URLs before processing
- **Log Redaction**: Automatically redacts tokens and secrets from logs
- **CSPRNG**: Uses cryptographically secure random number generation

## Installation

```bash
npm install @guardhouse/react-native react-native react
```

### Dependencies

The SDK includes the following vetted dependencies:

- `@guardhouse/core` - Shared PKCE, URL construction, and API client logic
- `react-native-inappbrowser-reborn` - Secure browser sessions
- `react-native-keychain` - Hardware-backed secure storage
- `jwt-decode` - JWT decoding and validation

## iOS Setup

### 1. Configure Deep Links

In your `ios/YourProject/Info.plist`, add:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>com.yourapp</string>
    </array>
  </dict>
</array>
```

### 2. Update Podfile

Add the following to your `ios/Podfile`:

```ruby
pod 'RNInAppBrowser', :path => '../node_modules/react-native-inappbrowser-reborn'
```

Then run:

```bash
cd ios && pod install && cd ..
```

### 3. Associated Domains (Optional)

For SSO and credential autofill, add associated domains to your Apple Developer account and update `Info.plist`:

```xml
<key>com.apple.developer.associated-domains</key>
<array>
  <string>webcredentials:https://your-domain.com</string>
</array>
```

## Android Setup

### 1. Configure Deep Links

In `android/app/src/main/AndroidManifest.xml`, add the intent filter to your main activity:

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data
    android:scheme="com.yourapp"
    android:host="callback" />
</intent-filter>
```

### 2. Configure Launch Mode (IMPORTANT!)

To prevent task hijacking attacks, set `launchMode="singleTask"` in your main activity:

```xml
<activity
  android:name=".MainActivity"
  android:launchMode="singleTask"
  ...>
```

**Security Note**: This is critical for preventing malicious apps from hijacking the redirect intent. See OWASP M-STG-RES-008 for details.

### 3. Add to build.gradle

In `android/app/build.gradle`, ensure the following dependencies:

```gradle
dependencies {
  // ... other dependencies
  implementation 'com.facebook.react:react-native:+'
}
```

## Usage

### Basic Setup

Wrap your app with the `GuardhouseProvider`:

```tsx
import React from "react";
import { GuardhouseProvider } from "@guardhouse/react-native";
import App from "./App";

const index = () => {
  return (
    <GuardhouseProvider
      authority="https://your-guardhouse-domain.com"
      clientId="your-client-id"
      redirectUri="com.yourapp://callback"
      scopes={["openid", "profile", "offline_access"]}
      debug={true}
    >
      <App />
    </GuardhouseProvider>
  );
};

export default index;
```

### Using the Hook

```tsx
import React from "react";
import { View, Button, Text } from "react-native";
import { useAuth } from "@guardhouse/react-native";

const MyComponent = () => {
  const { user, login, logout, getAccessToken, isAuthenticated, isLoading } =
    useAuth();

  const handleLogin = async () => {
    await login();
  };

  const handleLogout = async () => {
    await logout();
  };

  const handleApiCall = async () => {
    const token = await getAccessToken();
    if (token) {
      // Make authenticated API call
      const response = await fetch("https://api.example.com/data", {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
      // Handle response...
    }
  };

  if (isLoading) {
    return <Text>Loading...</Text>;
  }

  return (
    <View>
      {isAuthenticated ? (
        <>
          <Text>Welcome, {user?.name || user?.sub}</Text>
          <Button title="API Call" onPress={handleApiCall} />
          <Button title="Logout" onPress={handleLogout} />
        </>
      ) : (
        <Button title="Login" onPress={handleLogin} />
      )}
    </View>
  );
};

export default MyComponent;
```

### Accessing User Information

The `useAuth` hook provides access to the authenticated user:

```tsx
const { user } = useAuth();

console.log(user?.sub); // Subject ID
console.log(user?.name); // User's name
console.log(user?.email); // User's email
console.log(user?.roles); // User's roles
```

### Custom Login Options

You can pass custom options to the login method:

```tsx
const login = () => {
  useAuth().login({
    appState: { returnTo: "com.yourapp://dashboard" },
    prompt: "login", // Force login prompt
    scope: "openid profile email", // Override default scopes
  });
};
```

### Logout Options

```tsx
const logout = () => {
  useAuth().logout({
    returnTo: "com.yourapp://welcome", // Redirect after logout
  });
};
```

## API Reference

### GuardhouseProvider

Props:

- `authority` (string, required): Guardhouse domain (e.g., `https://your-domain.com`)
- `clientId` (string, required): Your application's client ID
- `redirectUri` (string, required): Deep link URI for callbacks (e.g., `com.myapp://callback`)
- `scopes` (string[], optional): Default scopes (default: `['openid', 'profile', 'offline_access']`)
- `debug` (boolean, optional): Enables verbose SDK logs when true
- `children` (ReactNode, required): Your app components

### useAuth

Returns an object with:

- `user` (User | null): The authenticated user profile
- `accessToken` (string | null): The current access token
- `isAuthenticated` (boolean): Whether the user is authenticated
- `isLoading` (boolean): Whether authentication is in progress
- `error` (string | null): Error message if authentication failed
- `login(options?: LoginOptions)`: Initiate authentication flow
- `logout(options?: LogoutOptions)`: Log out and clear session
- `getAccessToken()`: Get access token, auto-refreshing if expired

### LoginOptions

- `appState?: AppState`: Application state to restore after login
- `prompt?: string`: Prompt mode ('none', 'login', 'consent', 'select_account')
- `scope?: string`: Custom scopes for this login
- `audience?: string`: Target audience

### LogoutOptions

- `returnTo?: string`: Redirect URI after logout
- `federated?: boolean`: Enable federated logout

## Security Best Practices

### 1. Deep Link Configuration

Always configure deep links correctly:

- **iOS**: Add schemes to `Info.plist`
- **Android**: Add intent filters to `AndroidManifest.xml`
- **Android**: Use `android:launchMode="singleTask"` (CRITICAL)

### 2. Token Storage

The SDK automatically uses secure storage:

- Uses `react-native-keychain` for hardware-backed storage
- Tokens are encrypted and stored in the iOS Keychain or Android Keystore
- Never use AsyncStorage or SharedPreferences for tokens

### 3. HTTPS Enforcement

The SDK enforces HTTPS for all communication:

- Authority URL must use HTTPS
- Token endpoint uses HTTPS
- All API calls should use HTTPS

### 4. Error Handling

Always handle authentication errors:

```tsx
const { error, isAuthenticated } = useAuth();

useEffect(() => {
  if (error) {
    console.error("Auth error:", error);
    // Show error to user or redirect to login
  }
}, [error]);
```

### 5. Token Refresh

The SDK automatically refreshes tokens when expired:

- Call `getAccessToken()` before each API call
- The method handles refresh automatically
- If refresh fails, the session is cleared

## Troubleshooting

### Deep Links Not Working

**iOS**:

- Check `Info.plist` for correct URL scheme
- Restart Xcode after changes
- Test with: `xcrun simctl openurl booted "com.yourapp://callback"`

**Android**:

- Check `AndroidManifest.xml` for intent filter
- Verify `launchMode="singleTask"` is set
- Test with: `adb shell am start -W -a android.intent.action.VIEW -d "com.yourapp://callback"`

### Keychain Issues

**iOS**:

- Ensure Keychain Sharing is enabled in capabilities
- Check that the app has proper entitlements

**Android**:

- Verify Keychain permissions in `AndroidManifest.xml`

### InAppBrowser Issues

**iOS**:

- Ensure `SFSafariViewController` is available (iOS 9+)
- Check that `ephemeralWebSession: false` is used for SSO

**Android**:

- Ensure Chrome Custom Tabs is available
- Verify that Chrome is installed on the device

## Audit Checklist

When auditing this implementation:

- [ ] Tokens stored in Keychain/Keystore (not AsyncStorage/SharedPreferences)
- [ ] InAppBrowser used for authentication (not Linking.openURL)
- [ ] PKCE with S256 enforced
- [ ] State parameter validation implemented
- [ ] JWT algorithm whitelisting (RS256/HS256)
- [ ] CSPRNG for state/nonce generation
- [ ] TLS enforcement
- [ ] Deep link sanitization
- [ ] Log redaction for tokens/secrets
- [ ] Android launchMode="singleTask" configured

## License

MIT
