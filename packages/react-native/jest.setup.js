const mockKeychain = {
  ACCESS_CONTROL: {
    USER_PRESENCE: "USER_PRESENCE",
    BIOMETRY_ANY: "BIOMETRY_ANY",
    BIOMETRY_CURRENT_SET: "BIOMETRY_CURRENT_SET",
    DEVICE_PASSCODE: "DEVICE_PASSCODE",
    BIOMETRY_ANY_OR_DEVICE_PASSCODE: "BIOMETRY_ANY_OR_DEVICE_PASSCODE",
    BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE:
      "BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE",
  },
  ACCESSIBLE: {
    WHEN_UNLOCKED: "WHEN_UNLOCKED",
    WHEN_UNLOCKED_THIS_DEVICE_ONLY: "WHEN_UNLOCKED_THIS_DEVICE_ONLY",
    AFTER_FIRST_UNLOCK: "AFTER_FIRST_UNLOCK",
    ALWAYS: "ALWAYS",
    WHEN_PASSCODE_SET_THIS_DEVICE_ONLY: "WHEN_PASSCODE_SET_THIS_DEVICE_ONLY",
  },
  STORAGE_TYPE: {
    AES_CBC: "AES_CBC",
    AES_GCM_NO_AUTH: "AES_GCM_NO_AUTH",
    AES_GCM: "AES_GCM",
    RSA: "RSA",
  },
  _storage: new Map(),

  setGenericPassword: jest.fn(async (username, password, options) => {
    const service = options && options.service ? options.service : username;
    mockKeychain._storage.set(service, { username, password });
    return { service, storage: "keychain" };
  }),

  getGenericPassword: jest.fn(async (options) => {
    const service = options && options.service ? options.service : "default";
    const result = mockKeychain._storage.get(service);

    if (!result) {
      return false;
    }

    if (options && options.authenticationPrompt) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }

    return { password: result.password, service };
  }),

  resetGenericPassword: jest.fn(async (options) => {
    const service = options && options.service ? options.service : "default";
    mockKeychain._storage.delete(service);
    return true;
  }),

  getAllGenericPasswordServices: jest.fn(async () => {
    return Array.from(mockKeychain._storage.keys());
  }),
};

const mockInAppBrowser = {
  InAppBrowser: {
    openAuth: jest.fn(async () => ({
      type: "success",
      url: "com.example://callback?code=test_code&state=test_state",
    })),
    open: jest.fn(async () => ({ type: "cancel" })),
    close: jest.fn(),
    closeAuth: jest.fn(),
    isAvailable: jest.fn(async () => true),
    dismiss: jest.fn(),
  },
};

const mockLinking = {
  openURL: jest.fn(async () => true),
  canOpenURL: jest.fn(async () => true),
  getInitialURL: jest.fn(async () => null),
  addEventListener: jest.fn(() => ({ remove: jest.fn() })),
  removeEventListener: jest.fn(),
};

jest.mock("react-native-keychain", () => mockKeychain, { virtual: true });
jest.mock("react-native-inappbrowser-reborn", () => mockInAppBrowser, {
  virtual: true,
});
jest.mock("react-native/Linking", () => mockLinking, { virtual: true });

beforeEach(() => {
  mockKeychain._storage.clear();
  mockKeychain.setGenericPassword.mockClear();
  mockKeychain.getGenericPassword.mockClear();
  mockKeychain.resetGenericPassword.mockClear();
  mockKeychain.getAllGenericPasswordServices.mockClear();

  mockInAppBrowser.InAppBrowser.openAuth.mockClear();
  mockInAppBrowser.InAppBrowser.open.mockClear();
  mockInAppBrowser.InAppBrowser.close.mockClear();
  mockInAppBrowser.InAppBrowser.closeAuth.mockClear();
  mockInAppBrowser.InAppBrowser.isAvailable.mockClear();
  mockInAppBrowser.InAppBrowser.dismiss.mockClear();

  mockLinking.openURL.mockClear();
  mockLinking.canOpenURL.mockClear();
  mockLinking.getInitialURL.mockClear();
  mockLinking.addEventListener.mockClear();
  mockLinking.removeEventListener.mockClear();
  mockLinking.canOpenURL.mockResolvedValue(true);
});

afterAll(() => {
  jest.clearAllMocks();
});

function mockCallbackUrl(url) {
  mockInAppBrowser.InAppBrowser.openAuth.mockResolvedValueOnce({
    type: "success",
    url,
  });
}

function mockBrowserCancel() {
  mockInAppBrowser.InAppBrowser.openAuth.mockResolvedValueOnce({
    type: "cancel",
  });
}

function mockKeychainUserCancel() {
  mockKeychain.getGenericPassword.mockRejectedValueOnce(
    new Error("UserCanceled"),
  );
}

function mockStoredSession(data) {
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

module.exports = {
  mockCallbackUrl,
  mockBrowserCancel,
  mockKeychainUserCancel,
  mockStoredSession,
};
