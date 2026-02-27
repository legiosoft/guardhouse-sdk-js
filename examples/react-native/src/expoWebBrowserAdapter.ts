import * as WebBrowser from "expo-web-browser";
import type {
  BrowserSessionOptions,
  GuardhouseBrowserAdapter,
} from "@guardhouse/react-native";

const AuthSessionModule = require("expo-auth-session") as {
  makeRedirectUri: (options?: { path?: string }) => string;
};

WebBrowser.maybeCompleteAuthSession();

export function resolveExpoRedirectUri(configuredRedirectUri?: string): string {
  const trimmed = configuredRedirectUri?.trim();

  if (trimmed && trimmed.toLowerCase() !== "auto") {
    return trimmed;
  }

  return AuthSessionModule.makeRedirectUri({
    path: "callback",
  });
}

export const expoWebBrowserAdapter: GuardhouseBrowserAdapter = {
  name: "ExpoWebBrowserAdapter",
  async openAuthSession(
    authorizationUrl: string,
    redirectUri: string,
    options?: BrowserSessionOptions,
  ) {
    const callbackUri = resolveExpoRedirectUri(redirectUri);

    const result = await WebBrowser.openAuthSessionAsync(
      authorizationUrl,
      callbackUri,
      {
        preferEphemeralSession: options?.ephemeralSession ?? false,
        createTask: false,
        showInRecents: true,
      },
    );

    if (result.type === "success" && result.url) {
      return { url: result.url };
    }

    if (result.type === "cancel") {
      throw new Error("Authentication cancelled by user");
    }

    if (result.type === "dismiss") {
      throw new Error("Authentication session was dismissed");
    }

    throw new Error(`Authentication failed: ${result.type}`);
  },
};
