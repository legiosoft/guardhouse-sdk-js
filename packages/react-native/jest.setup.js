/**
 * Jest Setup for Guardhouse React Native SDK
 * 
 * SECURITY DECISIONS:
 * 
 * 1. Why mock native modules?
 *    - Jest runs in Node.js environment (not React Native)
 *    - Native modules don't exist without React Native runtime
 *    - Tests would crash without mocks
 *    - We need to simulate native behavior for unit testing
 * 
 * 2. Mocking Strategy:
 *    - Use jest.mock() to replace native modules
 *    - Provide realistic mock implementations
 *    - Maintain API compatibility for tests
 * 
 * 3. Keychain Mock:
 *    - Simulates secure storage in memory
 *    - Maintains same API as react-native-keychain
 *    - Allows testing of biometric logic
 *    - Throws errors appropriately (UserCanceled, etc.)
 * 
 * 4. InAppBrowser Mock:
 *    - Simulates browser opening and closing
 *    - Returns success/cancel/dismiss results
 *    - Allows testing of auth flow without actual browser
 * 
 * 5. Linking Mock:
 *    - Simulates deep link handling
 *    - Allows testing of redirect logic
 *    - Mocks canOpenURL and openURL
 */

/**
 * Mock for react-native-keychain
 * 
 * Simulates secure storage in memory for testing
 * Maintains same API as real module
 */
const mockKeychain = {
  ACCESS_CONTROL: {
    USER_PRESENCE: "USER_PRESENCE",
    BIOMETRY_ANY: "BIOMETRY_ANY",
    BIOMETRY_CURRENT_SET: "BIOMETRY_CURRENT_SET",
    DEVICE_PASSCODE: "DEVICE_PASSCODE",
    BIOMETRY_ANY_OR_DEVICE_PASSCODE:
      "BIOMETRY_ANY_OR_DEVICE_PASSCODE",
    BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE:
      "BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE",
  },
  ACCESSIBLE: {
    WHEN_UNLOCKED: "WHEN_UNLOCKED",
    WHEN_UNLOCKED_THIS_DEVICE_ONLY: "WHEN_UNLOCKED_THIS_DEVICE_ONLY",
    AFTER_FIRST_UNLOCK: "AFTER_FIRST_UNLOCK",
    ALWAYS: "ALWAYS",
    WHEN_PASSCODE_SET_THIS_DEVICE_ONLY:
      "WHEN_PASSCODE_SET_THIS_DEVICE_ONLY",
  },
  STORAGE_TYPE: {
    AES_CBC: "AES_CBC",
    AES_GCM_NO_AUTH: "AES_GCM_NO_AUTH",
    AES_GCM: "AES_GCM",
    RSA: "RSA",
  },

  // In-memory storage for testing
  _storage: new Map<string, { username: string; password: string }>(),

  async setGenericPassword(
    username: string,
    password: string,
    options?: any,
  ): Promise<false | any> {
    const service = options?.service || username;
    mockKeychain._storage.set(service, { username, password });
    return { service, storage: "keychain" };
  },

  async getGenericPassword(options?: any): Promise<false | any> {
    const service = options?.service || "default";
    const result = mockKeychain._storage.get(service);

    if (!result) {
      return false;
    }

    // Simulate biometric prompt delay
    if (options?.authenticationPrompt) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    return { password: result.password, service };
  },

  async resetGenericPassword(options?: any): Promise<boolean> {
    const service = options?.service || "default";
    mockKeychain._storage.delete(service);
    return true;
  },

  async getAllGenericPasswordServices(): Promise<string[]> {
    return Array.from(mockKeychain._storage.keys());
  },
};

/**
 * Mock for react-native-inappbrowser-reborn
 * 
 * Simulates browser opening and authentication flow
 */
const mockInAppBrowser = {
  InAppBrowser: {
    openAuth: jest.fn(async () => {
      // Simulate user authentication
      return {
        type: "success",
        url: "com.example://callback?code=test_code&state=test_state",
      };
    }),

    open: jest.fn(async () => {
      return { type: "cancel" };
    }),

    close: jest.fn(),
    closeAuth: jest.fn(),
    isAvailable: jest.fn(async () => true),

    dismiss: jest.fn(),
    openAuth: jest.fn(async () => {
      return {
        type: "success",
        url: "com.example://callback?code=test_code&state=test_state",
      };
    }),
  },
};

/**
 * Mock for React Native Linking
 * 
 * Simulates deep link handling
 */
const mockLinking = {
  openURL: jest.fn(async () => true),
  canOpenURL: jest.fn(async () => true),
  getInitialURL: jest.fn(async () => null),
  addEventListener: jest.fn(() => {
    return { remove: jest.fn() };
  }),
  removeEventListener: jest.fn(),
};

// Setup mocks before tests run
beforeAll(() => {
  jest.mock("react-native-keychain", () => mockKeychain, { virtual: true });
  jest.mock("react-native-inappbrowser-reborn", () => mockInAppBrowser, {
    virtual: true,
  });
  jest.mock("react-native/Linking", () => mockLinking, { virtual: true });
});

// Clear storage between tests
beforeEach(() => {
  mockKeychain._storage.clear();
  mockInAppBrowser.InAppBrowser.openAuth.mockClear();
  mockLinking.openURL.mockClear();
  mockLinking.canOpenURL.mockResolvedValue(true);
});

// Cleanup after tests
afterAll(() => {
  jest.clearAllMocks();
});

/**
 * Helper for tests to simulate callback URL
 */
export function mockCallbackUrl(url: string) {
  mockInAppBrowser.InAppBrowser.openAuth.mockResolvedValueOnce({
    type: "success",
    url,
  });
}

/**
 * Helper for tests to simulate browser cancellation
 */
export function mockBrowserCancel() {
  mockInAppBrowser.InAppBrowser.openAuth.mockResolvedValueOnce({
    type: "cancel",
  });
}

/**
 * Helper for tests to simulate user cancellation in Keychain
 */
export function mockKeychainUserCancel() {
  mockKeychain.getGenericPassword.mockRejectedValueOnce(
    new Error("UserCanceled"),
  );
}

/**
 * Helper to set stored session in mock Keychain
 */
export function mockStoredSession(data: {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  user?: any;
}) {
  mockKeychain._storage.set("gh_access_token", {
    username: "access",
    password: data.accessToken,
  });
  mockKeychain._storage.set("gh_refresh_token", {
    username: "refresh",
    password: data.refreshToken || "",
  });
  mockKeychain._storage.set("gh_id_token", {
    username: "id_token",
    password: data.idToken || "",
  });
  mockKeychain._storage.set("gh_user", {
    username: "user",
    password: JSON.stringify(data.user || {}),
  });
  mockKeychain._storage.set("gh_expires_at", {
    username: "expires",
    password: Math.floor(Date.now() / 1000 + 3600).toString(),
  });
}
