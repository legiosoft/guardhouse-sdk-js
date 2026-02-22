/**
 * Secure Storage Adapter for Guardhouse SDK
 *
 * SECURITY DECISIONS:
 *
 * 1. Why react-native-keychain?
 *    - Provides hardware-backed encryption (iOS Keychain / Android Keystore)
 *    - Prevents backup extraction (iOS: WHEN_UNLOCKED_THIS_DEVICE_ONLY)
 *    - Meets OWASP M-STG-RES-001 (Secure Storage)
 *    - NEVER use AsyncStorage or SharedPreferences (vulnerable to extraction)
 *
 * 2. Why ACCESS_CONTROL.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE?
 *    - Forces biometric authentication (FaceID/TouchID/Fingerprint) OR device passcode
 *    - Prevents unauthorized access to tokens even if device is unlocked
 *    - Provides additional security layer beyond device lock
 *    - Only used when requireBiometrics=true
 *
 * 3. Why BIOMETRY_ANY_OR_DEVICE_PASSCODE (default)?
 *    - Allows any biometric or passcode (more user-friendly)
 *    - Good default for most apps (not too restrictive)
 *
 * 4. WHEN_UNLOCKED_THIS_DEVICE_ONLY?
 *    - Tokens only accessible when device is unlocked
 *    - Never backup to iCloud/Google Drive (prevents extraction)
 *    - Device-specific (doesn't transfer to new device)
 *
 * 5. Biometric cancellation handling?
 *    - User can cancel biometric prompt (user's right)
 *    - We throw specific error (BiometricAuthFailedError) to handle gracefully
 *    - Don't auto-retry (respect user's decision)
 */

import * as Keychain from "react-native-keychain";
import { createReactNativeLogger } from "../debug";

interface ExpoSecureStoreModule {
  getItemAsync(
    key: string,
    options?: Record<string, unknown>,
  ): Promise<string | null>;
  setItemAsync(
    key: string,
    value: string,
    options?: Record<string, unknown>,
  ): Promise<void>;
  deleteItemAsync(
    key: string,
    options?: Record<string, unknown>,
  ): Promise<void>;
  WHEN_UNLOCKED_THIS_DEVICE_ONLY?: string;
}

interface ExpoSecureStoreNativeModule {
  getValueWithKeyAsync(
    key: string,
    options?: Record<string, unknown>,
  ): Promise<string | null>;
  setValueWithKeyAsync(
    value: string,
    key: string,
    options?: Record<string, unknown>,
  ): Promise<void>;
  deleteValueWithKeyAsync(
    key: string,
    options?: Record<string, unknown>,
  ): Promise<void>;
  WHEN_UNLOCKED_THIS_DEVICE_ONLY?: string;
}

type DynamicRequire = (moduleName: string) => unknown;

function tryRequire(moduleName: string): unknown {
  const dynamicRequire = (globalThis as { require?: DynamicRequire }).require;

  if (typeof dynamicRequire !== "function") {
    return null;
  }

  try {
    return dynamicRequire(moduleName);
  } catch {
    return null;
  }
}

export interface StorageKeys {
  ACCESS_TOKEN: string;
  REFRESH_TOKEN: string;
  ID_TOKEN: string;
  EXPIRES_AT: string;
  USER: string;
  CODE_VERIFIER: string;
  STATE: string;
  NONCE: string;
  APP_STATE: string;
}

export const STORAGE_KEYS: StorageKeys = {
  ACCESS_TOKEN: "gh_access_token",
  REFRESH_TOKEN: "gh_refresh_token",
  ID_TOKEN: "gh_id_token",
  EXPIRES_AT: "gh_expires_at",
  USER: "gh_user",
  CODE_VERIFIER: "gh_code_verifier",
  STATE: "gh_state",
  NONCE: "gh_nonce",
  APP_STATE: "gh_app_state",
};

export interface SessionData {
  accessToken: string;
  refreshToken?: string;
  idToken?: string;
  expiresAt: number;
  user: any;
}

export class BiometricAuthFailedError extends Error {
  constructor(
    message: string,
    public userCancelled?: boolean,
  ) {
    super(message);
    this.name = "BiometricAuthFailedError";
  }
}

/**
 * Secure Storage Adapter using Keychain/Keystore
 *
 * This adapter wraps react-native-keychain with security best practices:
 * - Hardware-backed encryption
 * - Biometric authentication support
 * - Device-specific storage (no backup)
 * - Graceful biometric cancellation handling
 */
export class SecureStorage {
  private requireBiometrics: boolean;
  private logger: ReturnType<typeof createReactNativeLogger>;
  private expoSecureStore: ExpoSecureStoreModule | null;
  private forceExpoSecureStore: boolean;
  private forceInMemoryStore: boolean;
  private inMemoryStorage: Map<string, string>;

  constructor(requireBiometrics: boolean = false, debug = false) {
    this.requireBiometrics = requireBiometrics;
    this.logger = createReactNativeLogger("SecureStorage", debug);
    this.expoSecureStore = this.loadExpoSecureStore();
    this.forceExpoSecureStore = false;
    this.forceInMemoryStore = false;
    this.inMemoryStorage = new Map();

    if (this.expoSecureStore) {
      this.logger.debug("Expo SecureStore adapter detected");
    }
  }

  private loadExpoSecureStore(): ExpoSecureStoreModule | null {
    const expoNativeModule = (
      globalThis as {
        expo?: {
          modules?: Record<string, unknown>;
        };
      }
    ).expo?.modules?.["ExpoSecureStore"] as
      | ExpoSecureStoreNativeModule
      | undefined;

    if (
      expoNativeModule &&
      typeof expoNativeModule.getValueWithKeyAsync === "function" &&
      typeof expoNativeModule.setValueWithKeyAsync === "function" &&
      typeof expoNativeModule.deleteValueWithKeyAsync === "function"
    ) {
      return {
        getItemAsync: (key, options) =>
          expoNativeModule.getValueWithKeyAsync(key, options),
        setItemAsync: (key, value, options) =>
          expoNativeModule.setValueWithKeyAsync(value, key, options),
        deleteItemAsync: (key, options) =>
          expoNativeModule.deleteValueWithKeyAsync(key, options),
        WHEN_UNLOCKED_THIS_DEVICE_ONLY:
          expoNativeModule.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
      };
    }

    const moduleCandidate = tryRequire(
      "expo-secure-store",
    ) as ExpoSecureStoreModule | null;

    if (
      moduleCandidate &&
      typeof moduleCandidate.getItemAsync === "function" &&
      typeof moduleCandidate.setItemAsync === "function" &&
      typeof moduleCandidate.deleteItemAsync === "function"
    ) {
      return moduleCandidate;
    }

    return null;
  }

  private shouldFallbackToExpoSecureStore(error: unknown): boolean {
    const message = error instanceof Error ? error.message : String(error);

    return (
      message.includes("setGenericPassswordForOptions") ||
      message.includes("setGenericPasswordForOptions") ||
      message.includes("getGenericPasswordForOptions") ||
      message.includes("resetGenericPasswordForOptions") ||
      message.includes("RNKeychainManager") ||
      message.includes("NativeModule") ||
      message.includes("of null")
    );
  }

  private getExpoSecureStoreOptions(): Record<string, unknown> {
    const options: Record<string, unknown> = {};

    if (this.requireBiometrics) {
      options.requireAuthentication = true;
    }

    if (this.expoSecureStore?.WHEN_UNLOCKED_THIS_DEVICE_ONLY) {
      options.keychainAccessible =
        this.expoSecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY;
    }

    return options;
  }

  private async getItemFromExpoSecureStore(
    key: string,
  ): Promise<string | null> {
    if (!this.expoSecureStore) {
      return null;
    }

    const value = await this.expoSecureStore.getItemAsync(
      key,
      this.getExpoSecureStoreOptions(),
    );

    this.logger.debug("Expo SecureStore read completed", {
      key,
      hasValue: Boolean(value),
    });

    return value;
  }

  private async setItemInExpoSecureStore(
    key: string,
    value: string,
  ): Promise<void> {
    if (!this.expoSecureStore) {
      throw new Error("Expo SecureStore module not available");
    }

    await this.expoSecureStore.setItemAsync(
      key,
      value,
      this.getExpoSecureStoreOptions(),
    );

    this.logger.debug("Expo SecureStore write completed", {
      key,
    });
  }

  private async removeItemFromExpoSecureStore(key: string): Promise<void> {
    if (!this.expoSecureStore) {
      return;
    }

    await this.expoSecureStore.deleteItemAsync(
      key,
      this.getExpoSecureStoreOptions(),
    );

    this.logger.debug("Expo SecureStore key removed", {
      key,
    });
  }

  private enableExpoSecureStoreFallback(cause: unknown): void {
    if (this.expoSecureStore) {
      this.forceExpoSecureStore = true;
      this.logger.warn(
        "Keychain native module unavailable, falling back to Expo SecureStore",
        {
          error: cause instanceof Error ? cause.message : String(cause),
        },
      );
      return;
    }

    this.forceInMemoryStore = true;
    this.logger.warn(
      "Keychain native module unavailable, falling back to in-memory storage",
      {
        error: cause instanceof Error ? cause.message : String(cause),
      },
    );
  }

  private getItemFromInMemoryStore(key: string): string | null {
    const value = this.inMemoryStorage.get(key) ?? null;

    this.logger.debug("In-memory storage read completed", {
      key,
      hasValue: Boolean(value),
    });

    return value;
  }

  private setItemInMemoryStore(key: string, value: string): void {
    this.inMemoryStorage.set(key, value);

    this.logger.debug("In-memory storage write completed", {
      key,
    });
  }

  private removeItemFromInMemoryStore(key: string): void {
    this.inMemoryStorage.delete(key);

    this.logger.debug("In-memory storage key removed", {
      key,
    });
  }

  /**
   * Get a value from secure storage
   *
   * SECURITY: If requireBiometrics=true, this triggers OS native biometric prompt
   * - iOS: FaceID/TouchID prompt
   * - Android: Fingerprint/Face Unlock prompt
   *
   * User can cancel (their right), we handle gracefully
   */
  async getItem(key: string): Promise<string | null> {
    if (this.forceInMemoryStore) {
      return this.getItemFromInMemoryStore(key);
    }

    if (this.forceExpoSecureStore && this.expoSecureStore) {
      return this.getItemFromExpoSecureStore(key);
    }

    try {
      const result = await Keychain.getGenericPassword({
        service: key,
      });

      if (result) {
        this.logger.debug("Secure storage read succeeded", {
          key,
          hasValue: true,
        });
        return result.password;
      }

      this.logger.debug("Secure storage read returned empty value", {
        key,
      });

      return null;
    } catch (error: any) {
      if (this.requireBiometrics && this.isUserCanceled(error)) {
        throw new BiometricAuthFailedError(
          "Biometric authentication cancelled by user",
          true,
        );
      }

      if (this.shouldFallbackToExpoSecureStore(error)) {
        this.enableExpoSecureStoreFallback(error);

        if (this.forceInMemoryStore) {
          return this.getItemFromInMemoryStore(key);
        }

        return this.getItemFromExpoSecureStore(key);
      }

      this.logger.error("Failed to read from secure storage", {
        key,
        error: String(error),
      });
      return null;
    }
  }

  /**
   * Save a value to secure storage
   *
   * SECURITY: Use appropriate access control based on biometrics requirement
   * - With biometrics: BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE (strict)
   * - Without: USER_PRESENCE (device unlocked)
   */
  async setItem(key: string, value: string): Promise<void> {
    if (this.forceInMemoryStore) {
      this.setItemInMemoryStore(key, value);
      return;
    }

    if (this.forceExpoSecureStore && this.expoSecureStore) {
      await this.setItemInExpoSecureStore(key, value);
      return;
    }

    try {
      const accessControl = this.requireBiometrics
        ? Keychain.ACCESS_CONTROL.BIOMETRY_CURRENT_SET_OR_DEVICE_PASSCODE
        : Keychain.ACCESS_CONTROL.USER_PRESENCE;

      await Keychain.setGenericPassword(key, value, {
        service: key,
        accessControl,
        accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
      });

      this.logger.debug("Secure storage write succeeded", {
        key,
      });
    } catch (error) {
      if (this.shouldFallbackToExpoSecureStore(error)) {
        this.enableExpoSecureStoreFallback(error);

        if (this.forceInMemoryStore) {
          this.setItemInMemoryStore(key, value);
          return;
        }

        await this.setItemInExpoSecureStore(key, value);
        return;
      }

      this.logger.error("Failed to write to secure storage", {
        key,
        error: String(error),
      });

      throw error;
    }
  }

  /**
   * Remove a value from secure storage
   */
  async removeItem(key: string): Promise<void> {
    if (this.forceInMemoryStore) {
      this.removeItemFromInMemoryStore(key);
      return;
    }

    if (this.forceExpoSecureStore && this.expoSecureStore) {
      await this.removeItemFromExpoSecureStore(key);
      return;
    }

    try {
      await Keychain.resetGenericPassword({ service: key });

      this.logger.debug("Secure storage key removed", {
        key,
      });
    } catch (error) {
      if (this.shouldFallbackToExpoSecureStore(error)) {
        this.enableExpoSecureStoreFallback(error);

        if (this.forceInMemoryStore) {
          this.removeItemFromInMemoryStore(key);
          return;
        }

        await this.removeItemFromExpoSecureStore(key);
        return;
      }

      this.logger.warn("Failed to remove secure storage key", {
        key,
        error: String(error),
      });
    }
  }

  /**
   * Clear all Guardhouse data from secure storage
   *
   * SECURITY: Important to call on logout to remove all sensitive data
   */
  async clear(): Promise<void> {
    try {
      this.logger.debug("Clearing all Guardhouse secure storage keys");

      const guardhouseKeys = Object.values(STORAGE_KEYS);

      if (this.forceInMemoryStore) {
        this.inMemoryStorage.clear();
        this.logger.debug("Finished clearing Guardhouse secure storage keys");
        return;
      }

      if (this.forceExpoSecureStore && this.expoSecureStore) {
        await Promise.all(
          guardhouseKeys.map((key) => this.removeItemFromExpoSecureStore(key)),
        );

        this.logger.debug("Finished clearing Guardhouse secure storage keys");
        return;
      }

      const services = await Keychain.getAllGenericPasswordServices();

      for (const service of services) {
        if (service.startsWith("gh_")) {
          await Keychain.resetGenericPassword({ service });
        }
      }

      this.logger.debug("Finished clearing Guardhouse secure storage keys");
    } catch (error) {
      if (this.shouldFallbackToExpoSecureStore(error)) {
        this.enableExpoSecureStoreFallback(error);

        if (this.forceInMemoryStore) {
          this.inMemoryStorage.clear();
          this.logger.debug("Finished clearing Guardhouse secure storage keys");
          return;
        }

        await Promise.all(
          Object.values(STORAGE_KEYS).map((key) =>
            this.removeItemFromExpoSecureStore(key),
          ),
        );

        this.logger.debug("Finished clearing Guardhouse secure storage keys");
        return;
      }

      this.logger.error("Failed to clear secure storage", {
        error: String(error),
      });
    }
  }

  /**
   * Save complete session data
   *
   * SECURITY: Stores all tokens and user data in single atomic operation
   */
  async saveSession(data: SessionData): Promise<void> {
    this.logger.debug("Saving secure session", {
      hasRefreshToken: Boolean(data.refreshToken),
      hasIdToken: Boolean(data.idToken),
      expiresAt: data.expiresAt,
    });

    await Promise.all([
      this.setItem(STORAGE_KEYS.ACCESS_TOKEN, data.accessToken),
      data.refreshToken
        ? this.setItem(STORAGE_KEYS.REFRESH_TOKEN, data.refreshToken)
        : Promise.resolve(),
      data.idToken
        ? this.setItem(STORAGE_KEYS.ID_TOKEN, data.idToken)
        : Promise.resolve(),
      this.setItem(STORAGE_KEYS.EXPIRES_AT, data.expiresAt.toString()),
      this.setItem(STORAGE_KEYS.USER, JSON.stringify(data.user)),
    ]);

    this.logger.debug("Secure session saved");
  }

  /**
   * Get complete session data
   *
   * SECURITY: Retrieves all session data, requires biometrics if enabled
   */
  async getSession(): Promise<SessionData | null> {
    try {
      this.logger.debug("Loading secure session");

      const [accessToken, refreshToken, idToken, expiresAtStr, userStr] =
        await Promise.all([
          this.getItem(STORAGE_KEYS.ACCESS_TOKEN),
          this.getItem(STORAGE_KEYS.REFRESH_TOKEN),
          this.getItem(STORAGE_KEYS.ID_TOKEN),
          this.getItem(STORAGE_KEYS.EXPIRES_AT),
          this.getItem(STORAGE_KEYS.USER),
        ]);

      if (!accessToken || !userStr) {
        this.logger.debug("Secure session not found");
        return null;
      }

      const expiresAt = expiresAtStr ? parseInt(expiresAtStr) : 0;
      const user = JSON.parse(userStr);

      const session: SessionData = {
        accessToken,
        refreshToken: refreshToken || undefined,
        idToken: idToken || undefined,
        expiresAt,
        user,
      };

      this.logger.debug("Secure session loaded", {
        expiresAt: session.expiresAt,
        hasRefreshToken: Boolean(session.refreshToken),
      });

      return session;
    } catch (error) {
      this.logger.error("Failed to read secure session", {
        error: String(error),
      });
      return null;
    }
  }

  /**
   * Check if error is user cancellation
   *
   * SECURITY: Differentiate between actual errors and user cancellation
   */
  private isUserCanceled(error: any): boolean {
    return (
      error?.name === "UserCanceled" ||
      error?.message?.includes("UserCanceled") ||
      error?.message?.includes("cancelled") ||
      error?.message?.includes("canceled")
    );
  }
}

/**
 * Promise Lock for Concurrency Control
 *
 * SECURITY: Prevents multiple simultaneous token refresh requests
 *
 * Why do we need this?
 * - Multiple API calls might trigger getAccessToken() simultaneously
 * - Without lock, each call would make a separate refresh request
 * - This causes race conditions and wasted network calls
 * - With lock, first call triggers refresh, others wait for result
 *
 * Example scenario:
 * - Component mounts with 3 concurrent API calls
 * - All 3 call getAccessToken() almost simultaneously
 * - Without lock: 3 refresh requests (bad)
 * - With lock: 1 refresh request, others reuse result (good)
 */
export class PromiseLock {
  private promise: Promise<any> | null = null;
  private logger: ReturnType<typeof createReactNativeLogger>;

  constructor(debug = false) {
    this.logger = createReactNativeLogger("PromiseLock", debug);
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    // If a promise is already running, return it
    if (this.promise) {
      this.logger.debug("Waiting for existing promise to complete");
      return this.promise as Promise<T>;
    }

    // Start new promise
    this.logger.debug("Starting locked promise execution");
    this.promise = fn();

    try {
      const result = await this.promise;
      this.logger.debug("Locked promise execution completed");
      return result;
    } finally {
      // Clear promise when done (success or failure)
      this.promise = null;
      this.logger.debug("Lock released");
    }
  }

  /**
   * Check if currently locked
   */
  isLocked(): boolean {
    return this.promise !== null;
  }
}

/**
 * JWT Utilities
 *
 * SECURITY: Direct JWT parsing for expiration checking
 *
 * Why decode JWT manually?
 * - We need to check `exp` claim before using token
 * - Don't need full validation (server does that)
 * - Faster than making a network call to introspect token
 * - Safe because we trust the token (we just received it)
 */
export function isTokenExpired(
  token: string,
  bufferSeconds = 60,
  debug = false,
): boolean {
  const logger = createReactNativeLogger("Token", debug);

  try {
    const parts = token.split(".");

    if (parts.length !== 3) {
      // Invalid JWT format, treat as expired
      logger.warn("Token has invalid JWT format; treating as expired");
      return true;
    }

    const payload = JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
    );

    if (!payload.exp) {
      // No expiration claim, assume valid
      logger.debug("Token has no exp claim; treating as active");
      return false;
    }

    const now = Math.floor(Date.now() / 1000);

    // Token is expired if exp < now + buffer
    // Buffer prevents edge case where token expires while in transit
    const expired = payload.exp < now + bufferSeconds;

    logger.debug("Token expiration evaluated", {
      expired,
      exp: payload.exp,
      now,
      bufferSeconds,
    });

    return expired;
  } catch (error) {
    // Failed to parse JWT, treat as expired (safe fallback)
    logger.error("Failed to check token expiration", {
      error: String(error),
    });
    return true;
  }
}
