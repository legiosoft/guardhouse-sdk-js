import * as Keychain from "react-native-keychain";
import { createReactNativeLogger } from "../debug";

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
  user: Record<string, unknown>;
}

export interface SessionStorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  removeItem(key: string): Promise<void>;
  saveSession(data: SessionData): Promise<void>;
  getSession(): Promise<SessionData | null>;
  clear?(): Promise<void>;
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

type StorageOperation = "read" | "write" | "remove" | "clear";

export class SecureStorageError extends Error {
  constructor(
    message: string,
    public operation: StorageOperation,
    public key?: string,
    public cause?: unknown,
  ) {
    super(message);
    this.name = "SecureStorageError";
  }
}

/**
 * Secure storage adapter backed by react-native-keychain.
 *
 * SECURITY: This implementation is fail-closed.
 * - No fallback to weaker stores.
 * - No fallback to in-memory token storage.
 * - Any secure storage failure throws and stops auth flow.
 */
export class SecureStorage implements SessionStorageAdapter {
  private readonly requireBiometrics: boolean;
  private readonly logger: ReturnType<typeof createReactNativeLogger>;

  constructor(requireBiometrics: boolean = false, debug = false) {
    this.requireBiometrics = requireBiometrics;
    this.logger = createReactNativeLogger("SecureStorage", debug);
  }

  async getItem(key: string): Promise<string | null> {
    try {
      const result = await Keychain.getGenericPassword({
        service: key,
      });

      if (!result) {
        this.logger.debug("Secure storage read returned empty value", {
          key,
        });
        return null;
      }

      this.logger.debug("Secure storage read succeeded", {
        key,
        hasValue: true,
      });
      return result.password;
    } catch (error: unknown) {
      if (this.requireBiometrics && this.isUserCanceled(error)) {
        throw new BiometricAuthFailedError(
          "Biometric authentication cancelled by user",
          true,
        );
      }

      const secureStorageError = this.toStorageError("read", key, error);
      this.logger.error("Failed to read from secure storage", {
        key,
        error: secureStorageError.message,
      });
      throw secureStorageError;
    }
  }

  async setItem(key: string, value: string): Promise<void> {
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
    } catch (error: unknown) {
      const secureStorageError = this.toStorageError("write", key, error);
      this.logger.error("Failed to write to secure storage", {
        key,
        error: secureStorageError.message,
      });
      throw secureStorageError;
    }
  }

  async removeItem(key: string): Promise<void> {
    try {
      await Keychain.resetGenericPassword({ service: key });

      this.logger.debug("Secure storage key removed", {
        key,
      });
    } catch (error: unknown) {
      const secureStorageError = this.toStorageError("remove", key, error);
      this.logger.error("Failed to remove secure storage key", {
        key,
        error: secureStorageError.message,
      });
      throw secureStorageError;
    }
  }

  async clear(): Promise<void> {
    try {
      this.logger.debug("Clearing all Guardhouse secure storage keys");

      const services = await Keychain.getAllGenericPasswordServices();

      await Promise.all(
        services
          .filter((service) => service.startsWith("gh_"))
          .map((service) => Keychain.resetGenericPassword({ service })),
      );

      this.logger.debug("Finished clearing Guardhouse secure storage keys");
    } catch (error: unknown) {
      const secureStorageError = this.toStorageError("clear", undefined, error);
      this.logger.error("Failed to clear secure storage", {
        error: secureStorageError.message,
      });
      throw secureStorageError;
    }
  }

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

  async getSession(): Promise<SessionData | null> {
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

    let user: Record<string, unknown>;
    try {
      const parsed = JSON.parse(userStr) as unknown;
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("User payload is not a JSON object");
      }
      user = parsed as Record<string, unknown>;
    } catch (error: unknown) {
      throw this.toStorageError("read", STORAGE_KEYS.USER, error);
    }

    const expiresAt = expiresAtStr ? Number.parseInt(expiresAtStr, 10) : 0;
    if (!Number.isFinite(expiresAt) || expiresAt < 0) {
      throw this.toStorageError(
        "read",
        STORAGE_KEYS.EXPIRES_AT,
        new Error("Invalid expiresAt value in secure storage"),
      );
    }

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
  }

  private toStorageError(
    operation: StorageOperation,
    key: string | undefined,
    cause: unknown,
  ): SecureStorageError {
    const keyInfo = key ? ` for key ${key}` : "";

    if (this.isNativeModuleUnavailable(cause)) {
      return new SecureStorageError(
        `Secure storage unavailable during ${operation}${keyInfo}. react-native-keychain native module is required and must be correctly linked.`,
        operation,
        key,
        cause,
      );
    }

    const message =
      cause instanceof Error && cause.message.trim() !== ""
        ? cause.message
        : String(cause);

    return new SecureStorageError(
      `Secure storage ${operation} failed${keyInfo}: ${message}`,
      operation,
      key,
      cause,
    );
  }

  private isNativeModuleUnavailable(error: unknown): boolean {
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

  private isUserCanceled(error: unknown): boolean {
    const errorName =
      error && typeof error === "object" && "name" in error
        ? String((error as { name: unknown }).name)
        : "";
    const errorMessage =
      error && typeof error === "object" && "message" in error
        ? String((error as { message: unknown }).message)
        : "";

    return (
      errorName === "UserCanceled" ||
      errorMessage.includes("UserCanceled") ||
      errorMessage.includes("cancelled") ||
      errorMessage.includes("canceled")
    );
  }
}

export class PromiseLock {
  private promise: Promise<unknown> | null = null;
  private readonly logger: ReturnType<typeof createReactNativeLogger>;

  constructor(debug = false) {
    this.logger = createReactNativeLogger("PromiseLock", debug);
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.promise) {
      this.logger.debug("Waiting for existing promise to complete");
      return this.promise as Promise<T>;
    }

    this.logger.debug("Starting locked promise execution");
    this.promise = fn();

    try {
      const result = await this.promise;
      this.logger.debug("Locked promise execution completed");
      return result as T;
    } finally {
      this.promise = null;
      this.logger.debug("Lock released");
    }
  }

  isLocked(): boolean {
    return this.promise !== null;
  }
}

export function isTokenExpired(
  token: string,
  bufferSeconds = 60,
  debug = false,
): boolean {
  const logger = createReactNativeLogger("Token", debug);

  try {
    const parts = token.split(".");

    if (parts.length !== 3) {
      logger.warn("Token has invalid JWT format; treating as expired");
      return true;
    }

    const payload = JSON.parse(
      atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")),
    );

    if (!payload.exp) {
      logger.debug("Token has no exp claim; treating as active");
      return false;
    }

    const now = Math.floor(Date.now() / 1000);
    const expired = payload.exp < now + bufferSeconds;

    logger.debug("Token expiration evaluated", {
      expired,
      exp: payload.exp,
      now,
      bufferSeconds,
    });

    return expired;
  } catch (error) {
    logger.error("Failed to check token expiration", {
      error: String(error),
    });
    return true;
  }
}
