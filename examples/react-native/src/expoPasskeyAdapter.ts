import type {
  GuardhousePasskeyAdapter,
  PasskeyAssertionResult,
  PasskeyCredentialRequestOptions,
} from "@guardhouse/react-native";

type PasskeyModule = {
  Passkey: {
    isSupported?: () => boolean;
    get: (requestOptions: Record<string, unknown>) => Promise<unknown>;
  };
};

function getPasskeyRuntime() {
  try {
    const moduleCandidate = require("react-native-passkey") as
      | PasskeyModule
      | undefined;

    if (
      !moduleCandidate ||
      !moduleCandidate.Passkey ||
      typeof moduleCandidate.Passkey.get !== "function"
    ) {
      throw new Error("react-native-passkey module shape is invalid");
    }

    return moduleCandidate.Passkey;
  } catch {
    throw new Error(
      "react-native-passkey is unavailable. Build with Expo dev-client or bare React Native to use passkeys.",
    );
  }
}

export const expoPasskeyAdapter: GuardhousePasskeyAdapter = {
  name: "ReactNativePasskeyAdapter",

  async get(
    requestOptions: PasskeyCredentialRequestOptions,
  ): Promise<PasskeyAssertionResult> {
    const passkeyRuntime = getPasskeyRuntime();

    if (passkeyRuntime.isSupported && !passkeyRuntime.isSupported()) {
      throw new Error("Passkeys are not supported on this device.");
    }

    const assertion = await passkeyRuntime.get(
      requestOptions as unknown as Record<string, unknown>,
    );

    return assertion as PasskeyAssertionResult;
  },
};
