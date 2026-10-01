export { GuardhouseClient } from "./core/GuardhouseClient";

export {
  InAppBrowserAuthAdapter,
  type BrowserAuthSessionResult,
  type BrowserSessionOptions,
  type GuardhouseBrowserAdapter,
} from "./adapters/BrowserAdapter";

export {
  ChunkedSecureStore,
  KeychainStorageAdapter,
  type GuardhouseStorageAdapter,
} from "./adapters/StorageAdapter";

export { resolveReactNativeCryptoAdapter } from "./crypto";

export type {
  BrowserLoginOptions,
  GetAccessTokenOptions,
  GuardhouseClientConfig,
  GuardhouseClientEndpoints,
  GuardhouseLogoutOptions,
  GuardhousePasskeyAdapter,
  LoginWithPasskeyOptions,
  PasskeyAssertionResponse,
  PasskeyAssertionResult,
  PasskeyCredentialDescriptor,
  PasskeyCredentialRequestOptions,
  RefreshTokenOptions,
  RestoreSessionOptions,
  GuardhouseAuthResult,
  GuardhouseSession,
  GuardhouseTokenResponse,
  GuardhouseErrorCode,
} from "./types/index";

export {
  GuardhouseAuthError,
  GuardhouseClientError,
  GuardhouseConfigurationError,
  GuardhouseError,
  GuardhouseNetworkError,
  GuardhouseStorageError,
} from "./types/index";
