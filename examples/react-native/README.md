# React Native Example

This is a complete example of a React Native application using `@guardhouse/react-native` for OAuth 2.0 authentication.

## Features

- OAuth 2.0 Authorization Code Flow with PKCE
- Secure token storage in Keychain/Keystore
- InAppBrowser for secure authentication
- User profile display
- Token management with auto-refresh
- API integration example
- React Navigation

## Prerequisites

- Node.js >= 18.0.0
- React Native development environment
- A Guardhouse instance running
- Node example server running (for API demo)

## Setup

1. Install dependencies:

```bash
npm install
```

2. Configure authentication in `App.tsx`:

```typescript
const AUTHORITY = "https://your-guardhouse-domain.com";
const CLIENT_ID = "your-client-id";
const REDIRECT_URI = "com.example.guardhouse://callback";
```

3. iOS Setup:

Add the following to `ios/YourProject/Info.plist`:

```xml
<key>CFBundleURLTypes</key>
<array>
  <dict>
    <key>CFBundleURLSchemes</key>
    <array>
      <string>com.example.guardhouse</string>
    </array>
  </dict>
</array>
```

Install iOS dependencies:

```bash
cd ios
pod install
cd ..
```

4. Android Setup:

Add the following to `android/app/src/main/AndroidManifest.xml` in your main activity:

```xml
<intent-filter>
  <action android:name="android.intent.action.VIEW" />
  <category android:name="android.intent.category.DEFAULT" />
  <category android:name="android.intent.category.BROWSABLE" />
  <data
    android:scheme="com.example.guardhouse"
    android:host="callback" />
</intent-filter>
```

**Important**: Set `launchMode="singleTask"` in your main activity:

```xml
<activity
  android:name=".MainActivity"
  android:launchMode="singleTask"
  ...>
```

## Running

Start Metro bundler:

```bash
npm start
```

Run on iOS:

```bash
npm run ios
```

Run on Android:

```bash
npm run android
```

## Screens

### Home Screen

- Shows user profile if authenticated
- Login/logout functionality
- User information display
- Navigation to other screens

### Protected Screen

- Requires authentication
- Shows detailed user information
- Automatically redirects if not authenticated

### API Demo Screen

- Demonstrates calling a protected API endpoint
- Uses access token for authentication
- Displays API response

## Usage Examples

### Basic Usage

```typescript
import { GuardhouseProvider, useAuth } from '@guardhouse/react-native';

function App() {
  return (
    <GuardhouseProvider
      authority={AUTHORITY}
      clientId={CLIENT_ID}
      redirectUri={REDIRECT_URI}
    >
      <YourApp />
    </GuardhouseProvider>
  );
}

function YourApp() {
  const { user, isAuthenticated, isLoading, login, logout } =
    useAuth();

  return (
    <>
      {isAuthenticated ? (
        <>
          <Text>Welcome, {user?.name}</Text>
          <Button title="Logout" onPress={logout} />
        </>
      ) : (
        <Button title="Login" onPress={login} />
      )}
    </>
  );
}
```

### Accessing User Information

```typescript
const { user } = useAuth();

console.log(user?.sub); // Subject ID
console.log(user?.name); // User's name
console.log(user?.email); // User's email
console.log(user?.roles); // User's roles
```

### Calling Protected APIs

```typescript
const { getAccessToken } = useAuth();

const fetchData = async () => {
  const token = await getAccessToken();

  if (token) {
    const response = await fetch("http://api.example.com/protected", {
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    const data = await response.json();
    console.log(data);
  }
};
```

### Custom Login Options

```typescript
const { login } = useAuth();

const handleLogin = () => {
  login({
    appState: { returnTo: "com.example://dashboard" },
    prompt: "login",
    scope: "openid profile email",
  });
};
```

### Logout Options

```typescript
const { logout } = useAuth();

const handleLogout = () => {
  logout({
    returnTo: "com.example://welcome",
  });
};
```

## Configuration

### GuardhouseProvider Props

```typescript
<GuardhouseProvider
  authority="https://your-domain.com"              // Required
  clientId="your-client-id"                        // Required
  redirectUri="com.yourapp://callback"            // Required
  scopes={['openid', 'profile', 'offline_access']}  // Optional
>
```

### Deep Link Configuration

#### iOS

In `Info.plist`:

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

#### Android

In `AndroidManifest.xml`:

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

**Security**: Always use `android:launchMode="singleTask"` to prevent task hijacking.

## API Integration

The example includes an API demo that calls a protected endpoint.

### Android Emulator

Use `10.0.2.2` to access localhost from Android emulator:

```typescript
fetch("http://10.0.2.2:3001/protected", {
  headers: {
    Authorization: `Bearer ${token}`,
  },
});
```

### iOS Simulator

Use `localhost`:

```typescript
fetch("http://localhost:3001/protected", {
  headers: {
    Authorization: `Bearer ${token}`,
  },
});
```

## Security Features

### Secure Storage

- Tokens stored in iOS Keychain / Android Keystore
- Hardware-backed encryption
- Biometric authentication support
- Device-specific storage (no backup)

### Secure Browser

- InAppBrowser for isolated authentication
- SSO support via shared cookies
- Clickjacking protection

### PKCE Flow

- S256 hash for code challenge
- CSPRNG for state/nonce generation
- CSRF protection via state parameter

### JWT Validation

- Algorithm whitelisting
- `none` algorithm rejected
- Nonce validation

## Troubleshooting

### Deep Links Not Working

**iOS**:

- Check `Info.plist` for correct URL scheme
- Restart Xcode after changes
- Test with: `xcrun simctl openurl booted "com.example://callback"`

**Android**:

- Check `AndroidManifest.xml` for intent filter
- Verify `launchMode="singleTask"` is set
- Test with: `adb shell am start -W -a android.intent.action.VIEW -d "com.example://callback"`

### Token Storage Issues

**iOS**:

- Ensure Keychain Sharing is enabled in capabilities
- Check app entitlements

**Android**:

- Verify Keychain permissions in `AndroidManifest.xml`

### InAppBrowser Issues

**iOS**:

- Ensure `SFSafariViewController` is available (iOS 9+)
- Check that `ephemeralWebSession: false` is used

**Android**:

- Ensure Chrome Custom Tabs is available
- Verify Chrome is installed

### API Demo Not Working

- Ensure Node example server is running on port 3001
- Check Android emulator uses `10.0.2.2`
- Check iOS simulator uses `localhost`

## Building for Production

### iOS

1. Update `Info.plist` with production deep link URL
2. Update authentication config in `App.tsx`
3. Build and archive in Xcode

### Android

1. Update `AndroidManifest.xml` with production deep link URL
2. Update authentication config in `App.tsx`
3. Build release APK or AAB

## License

MIT
