import { Linking } from "react-native";
import InAppBrowser from "react-native-inappbrowser-reborn";
import { GuardhouseAuthError } from "../types/errors";
import { createLogger } from "../utils/logger";
import {
  createRedirectMatcher,
  isMatchingRedirectUri,
  toErrorMessage,
} from "../utils/url";

const DEFAULT_BROWSER_TIMEOUT_MS = 180000;

/**
 * Browser auth session options.
 */
export interface BrowserSessionOptions {
  ephemeralSession?: boolean;
  timeoutMs?: number;
}

/**
 * Browser auth completion payload.
 */
export interface BrowserAuthSessionResult {
  url: string;
}

/**
 * Adapter contract for opening OAuth browser sessions.
 */
export interface GuardhouseBrowserAdapter {
  name?: string;
  openAuthSession(
    authorizationUrl: string,
    redirectUri: string,
    options?: BrowserSessionOptions,
  ): Promise<BrowserAuthSessionResult>;
}

/**
 * Default React Native browser adapter based on in-app browser + Linking fallback.
 */
export class InAppBrowserAuthAdapter implements GuardhouseBrowserAdapter {
  public readonly name = "InAppBrowserAuthAdapter";
  private readonly logger;

  constructor(debug = false) {
    this.logger = createLogger("InAppBrowserAdapter", debug);
  }

  async openAuthSession(
    authorizationUrl: string,
    redirectUri: string,
    options: BrowserSessionOptions = {},
  ): Promise<BrowserAuthSessionResult> {
    if (await this.isInAppBrowserAvailable()) {
      return this.openInAppBrowserSession(
        authorizationUrl,
        redirectUri,
        options.ephemeralSession ?? false,
      );
    }

    this.logger.warn(
      "InAppBrowser unavailable, using external browser fallback",
    );
    return this.openExternalAuthSession(
      authorizationUrl,
      redirectUri,
      options.timeoutMs ?? DEFAULT_BROWSER_TIMEOUT_MS,
    );
  }

  private async isInAppBrowserAvailable(): Promise<boolean> {
    try {
      return await InAppBrowser.isAvailable();
    } catch (error) {
      this.logger.warn("InAppBrowser availability check failed", {
        error: toErrorMessage(error),
      });
      return false;
    }
  }

  private async openInAppBrowserSession(
    authorizationUrl: string,
    redirectUri: string,
    ephemeralSession: boolean,
  ): Promise<BrowserAuthSessionResult> {
    const result = await InAppBrowser.openAuth(authorizationUrl, redirectUri, {
      ephemeralWebSession: ephemeralSession,
      showTitle: false,
      enableDefaultShare: false,
      enableUrlBarHiding: true,
      showInRecents: true,
    });

    if (result.type === "success" && typeof result.url === "string") {
      return { url: result.url };
    }

    if (result.type === "cancel") {
      throw new GuardhouseAuthError(
        "Authentication cancelled by user",
        "BROWSER_ERROR",
      );
    }

    if (result.type === "dismiss") {
      throw new GuardhouseAuthError(
        "Authentication session dismissed",
        "BROWSER_ERROR",
      );
    }

    throw new GuardhouseAuthError(
      `Unsupported browser result: ${String(result.type)}`,
      "BROWSER_ERROR",
    );
  }

  private async openExternalAuthSession(
    authorizationUrl: string,
    redirectUri: string,
    timeoutMs: number,
  ): Promise<BrowserAuthSessionResult> {
    const redirectMatcher = createRedirectMatcher(redirectUri);

    return new Promise((resolve, reject) => {
      let settled = false;
      let subscription: { remove: () => void } | undefined;

      const timeoutHandle = setTimeout(() => {
        if (settled) {
          return;
        }

        settled = true;
        subscription?.remove();
        reject(
          new GuardhouseAuthError(
            "Authentication redirect timed out",
            "BROWSER_ERROR",
          ),
        );
      }, timeoutMs);

      const resolveOnce = (result: BrowserAuthSessionResult) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timeoutHandle);
        subscription?.remove();
        resolve(result);
      };

      const rejectOnce = (error: unknown) => {
        if (settled) {
          return;
        }

        settled = true;
        clearTimeout(timeoutHandle);
        subscription?.remove();

        if (error instanceof GuardhouseAuthError) {
          reject(error);
          return;
        }

        reject(
          new GuardhouseAuthError(
            `External auth session failed: ${toErrorMessage(error)}`,
            "BROWSER_ERROR",
          ),
        );
      };

      subscription = Linking.addEventListener("url", ({ url }) => {
        if (!isMatchingRedirectUri(url, redirectMatcher)) {
          return;
        }

        resolveOnce({ url });
      });

      Linking.openURL(authorizationUrl).catch(rejectOnce);
    });
  }
}
