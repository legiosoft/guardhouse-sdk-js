import type {
  AuthorizationTransaction,
  OidcIdentityMetadata,
  User as CoreUser,
  VerifiedIdTokenPayload,
} from "@guardhouse/core";
import { restoreAuthorizationTransaction } from "@guardhouse/core";
import type { OidcSessionData, StorageAdapter, TokenData } from "./types";
import { parseQueryParams } from "./utils";

export const OIDC_SESSION_VERSION = 3 as const;
export const LOGIN_TRANSACTION_VERSION = 2 as const;
export const LOGIN_TRANSACTION_TTL_MS = 10 * 60 * 1000;

const FRONT_CHANNEL_TOKEN_KEYS = [
  "access_token",
  "id_token",
  "refresh_token",
  "token_type",
  "expires_in",
] as const;

const OAUTH_RESPONSE_KEYS = [
  "code",
  "state",
  "session_state",
  "error",
  "error_description",
  "iss",
  "scope",
  ...FRONT_CHANNEL_TOKEN_KEYS,
] as const;

const RETRYABLE_PRE_RESPONSE_REFRESH_ERROR_CODES = new Set([
  "NETWORK_ERROR",
  "REQUEST_TIMEOUT",
  "OIDC_METADATA_REQUEST_FAILED",
]);

export type LoginTransactionData = AuthorizationTransaction;

export interface AuthorizationResponseParams {
  params: Record<string, string>;
  /**
   * Every state value from both response channels. Do not collapse this list:
   * Core must receive the original callback URL so it can reject duplicate or
   * mixed-channel responses after React locates the bound transaction.
   */
  stateCandidates: readonly string[];
  source: "query" | "fragment";
  hasMixedChannelParameters: boolean;
  hasFrontChannelTokens: boolean;
}

export interface AuthenticatedUserResolution {
  user: CoreUser;
}

function cloneAndFreezeClaim(
  value: unknown,
  ancestors: WeakSet<object>,
): unknown {
  if (
    value === null ||
    value === undefined ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value !== "object") {
    throw new Error("Authenticated user contains a non-JSON claim value");
  }

  if (ancestors.has(value)) {
    throw new Error("Authenticated user contains a cyclic claim value");
  }
  ancestors.add(value);

  try {
    if (Array.isArray(value)) {
      return Object.freeze(
        value.map((entry) => cloneAndFreezeClaim(entry, ancestors)),
      );
    }

    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error("Authenticated user contains a non-JSON claim value");
    }

    const clone: Record<string, unknown> = {};
    for (const key of Object.keys(value)) {
      Object.defineProperty(clone, key, {
        configurable: false,
        enumerable: true,
        writable: false,
        value: cloneAndFreezeClaim(
          (value as Record<string, unknown>)[key],
          ancestors,
        ),
      });
    }
    return Object.freeze(clone);
  } finally {
    ancestors.delete(value);
  }
}

/** Creates an immutable, detached snapshot before claims enter React state. */
export function snapshotAuthenticatedUser(user: CoreUser): CoreUser {
  const snapshot = cloneAndFreezeClaim(user, new WeakSet<object>());
  if (
    !snapshot ||
    typeof snapshot !== "object" ||
    Array.isArray(snapshot) ||
    typeof (snapshot as Record<string, unknown>)["sub"] !== "string" ||
    ((snapshot as Record<string, unknown>)["sub"] as string).trim() === ""
  ) {
    throw new Error("Authenticated user is missing its subject");
  }
  return snapshot as CoreUser;
}

export async function resolveAuthenticatedUser(
  verifiedIdTokenPayload: VerifiedIdTokenPayload,
  loadUserInfo: () => Promise<CoreUser>,
): Promise<AuthenticatedUserResolution> {
  const subject = verifiedIdTokenPayload.sub;

  if (typeof subject !== "string" || subject.trim() === "") {
    throw new Error("Verified ID token is missing its subject");
  }

  const verifiedUser: CoreUser = {
    ...verifiedIdTokenPayload,
    sub: subject,
  };

  const userInfo = await loadUserInfo();

  if (userInfo.sub !== subject) {
    throw new Error("UserInfo subject does not match the ID token subject");
  }

  return {
    user: snapshotAuthenticatedUser({
      ...verifiedUser,
      ...userInfo,
      sub: subject,
    }),
  };
}

export function oidcIdentitiesEqual(
  left: OidcIdentityMetadata,
  right: OidcIdentityMetadata,
): boolean {
  return (
    left.issuer === right.issuer &&
    left.clientId === right.clientId &&
    left.subject === right.subject &&
    left.authorizedParty === right.authorizedParty &&
    left.issuedAt === right.issuedAt &&
    left.expiresAt === right.expiresAt &&
    left.nonce === right.nonce &&
    left.authTime === right.authTime &&
    left.acr === right.acr &&
    left.sessionId === right.sessionId &&
    left.audiences.length === right.audiences.length &&
    left.audiences.every(
      (audience, index) => audience === right.audiences[index],
    ) &&
    left.amr.length === right.amr.length &&
    left.amr.every((method, index) => method === right.amr[index])
  );
}

export function buildRefreshedOidcSession(
  sessionData: OidcSessionData,
  tokenResponse: TokenData,
  identity: OidcIdentityMetadata,
  nowSeconds = Math.floor(Date.now() / 1000),
): OidcSessionData {
  return {
    ...sessionData,
    accessToken: tokenResponse.access_token,
    refreshToken: tokenResponse.refresh_token || sessionData.refreshToken,
    idToken: tokenResponse.id_token ?? sessionData.idToken,
    tokenType: tokenResponse.token_type,
    scope: tokenResponse.scope || sessionData.scope,
    identity,
    expiresAt: nowSeconds + tokenResponse.expires_in,
  };
}

export function isAuthOperationCurrent(
  operationEpoch: number,
  currentEpoch: number,
  operationNamespace: string,
  currentNamespace: string,
): boolean {
  return (
    operationEpoch === currentEpoch && operationNamespace === currentNamespace
  );
}

export function isRetryablePreResponseRefreshError(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;

  const code = (error as Record<string, unknown>)["code"];
  return (
    typeof code === "string" &&
    RETRYABLE_PRE_RESPONSE_REFRESH_ERROR_CODES.has(code.trim().toUpperCase())
  );
}

export async function removeStorageValueIfMatches(
  storage: StorageAdapter,
  key: string,
  expectedValue: string,
): Promise<boolean> {
  return withStorageKeyLock(key, async () => {
    if (storage.compareAndRemoveItem) {
      const removed = await storage.compareAndRemoveItem(key, expectedValue);
      if (!removed) {
        if ((await storage.getItem(key)) === expectedValue) {
          throw new Error("Failed to remove persisted authentication state");
        }
        return false;
      }

      if ((await storage.getItem(key)) === expectedValue) {
        throw new Error("Failed to remove persisted authentication state");
      }
      return true;
    }

    const currentValue = await storage.getItem(key);

    if (currentValue !== expectedValue) {
      return false;
    }

    await storage.removeItem(key);
    if ((await storage.getItem(key)) === expectedValue) {
      throw new Error("Failed to remove persisted authentication state");
    }
    return true;
  });
}

export async function replaceStorageValueIfMatches(
  storage: StorageAdapter,
  key: string,
  expectedValue: string,
  value: string,
): Promise<boolean> {
  return withStorageKeyLock(key, async () => {
    if (storage.compareAndSetItem) {
      const replaced = await storage.compareAndSetItem(
        key,
        expectedValue,
        value,
      );
      const currentValue = await storage.getItem(key);

      if (!replaced) {
        if (currentValue === expectedValue) {
          throw new Error("Failed to replace persisted authentication state");
        }
        return false;
      }

      if (currentValue === expectedValue) {
        throw new Error("Failed to replace persisted authentication state");
      }
      return true;
    }

    const currentValue = await storage.getItem(key);
    if (currentValue !== expectedValue) return false;

    await storage.setItem(key, value);
    if ((await storage.getItem(key)) === expectedValue) {
      throw new Error("Failed to replace persisted authentication state");
    }
    return true;
  });
}

const storageLocks = new Map<string, Promise<unknown>>();

async function withStorageKeyLock<T>(
  key: string,
  operation: () => Promise<T>,
): Promise<T> {
  const previous = storageLocks.get(key) ?? Promise.resolve();
  const current = previous.catch(() => undefined).then(operation);
  storageLocks.set(key, current);

  try {
    return await current;
  } finally {
    if (storageLocks.get(key) === current) storageLocks.delete(key);
  }
}

export async function setStorageValue(
  storage: StorageAdapter,
  key: string,
  value: string,
): Promise<void> {
  await withStorageKeyLock(key, async () => {
    await storage.setItem(key, value);
    if ((await storage.getItem(key)) !== value) {
      throw new Error("Failed to persist authentication state");
    }
  });
}

export async function removeStorageValue(
  storage: StorageAdapter,
  key: string,
): Promise<void> {
  await withStorageKeyLock(key, async () => {
    await storage.removeItem(key);
    if ((await storage.getItem(key)) !== null) {
      throw new Error("Failed to remove persisted authentication state");
    }
  });
}

function owns(params: Record<string, string>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(params, key);
}

function containsAny(
  params: Record<string, string>,
  keys: readonly string[],
): boolean {
  return keys.some((key) => owns(params, key));
}

function hasAuthorizationResponse(params: Record<string, string>): boolean {
  return (
    owns(params, "code") ||
    owns(params, "error") ||
    containsAny(params, FRONT_CHANNEL_TOKEN_KEYS)
  );
}

function optionalNonEmptyString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() !== "" ? value : undefined;
}

export function isValidOAuthState(state: string): boolean {
  return /^[A-Za-z0-9._~-]{16,512}$/.test(state);
}

export function getIssuerIdentifier(authority: string): string {
  const parsed = new URL(authority.trim());
  const isLoopback =
    parsed.hostname === "localhost" ||
    parsed.hostname === "127.0.0.1" ||
    parsed.hostname === "[::1]" ||
    parsed.hostname === "::1";
  if (
    (parsed.protocol !== "https:" &&
      !(parsed.protocol === "http:" && isLoopback)) ||
    parsed.username ||
    parsed.password ||
    parsed.search ||
    parsed.hash
  ) {
    throw new Error("authority must be a canonical HTTPS issuer URL");
  }
  return parsed.href;
}

function storageNamespace(authority: string, clientId: string): string {
  return `${encodeURIComponent(getIssuerIdentifier(authority))}:${encodeURIComponent(
    clientId,
  )}`;
}

export function getOidcSessionStorageKey(
  authority: string,
  clientId: string,
): string {
  return `gh:v3:session:${storageNamespace(authority, clientId)}`;
}

export function getLoginTransactionStorageKey(
  authority: string,
  clientId: string,
  state: string,
): string {
  return `gh:v3:transaction:${storageNamespace(authority, clientId)}:${encodeURIComponent(
    state,
  )}`;
}

export function getLogoutStateStorageKey(
  authority: string,
  clientId: string,
): string {
  return `gh:v3:logout:${storageNamespace(authority, clientId)}`;
}

export function getAuthorizationResponseParams(
  callbackUrl: string,
): AuthorizationResponseParams | null {
  const url = new URL(callbackUrl);
  const querySearchParams = new URLSearchParams(url.search);
  const rawFragment = url.hash.startsWith("#") ? url.hash.slice(1) : url.hash;
  const fragmentSearchParams = new URLSearchParams(rawFragment);
  const query = parseQueryParams(url.search);
  const fragment = parseQueryParams(rawFragment ? `?${rawFragment}` : "");
  const queryHasResponse = hasAuthorizationResponse(query);
  const fragmentHasResponse = hasAuthorizationResponse(fragment);

  if (!queryHasResponse && !fragmentHasResponse) {
    return null;
  }

  const source: "query" | "fragment" = queryHasResponse ? "query" : "fragment";
  const params = source === "query" ? query : fragment;
  const otherParams = source === "query" ? fragment : query;

  return {
    params,
    stateCandidates: [
      ...querySearchParams.getAll("state"),
      ...fragmentSearchParams.getAll("state"),
    ],
    source,
    hasMixedChannelParameters: containsAny(otherParams, OAUTH_RESPONSE_KEYS),
    hasFrontChannelTokens: containsAny(params, FRONT_CHANNEL_TOKEN_KEYS),
  };
}

export function parseStoredOidcSession(
  serializedSession: string | null,
  expectedAuthority: string,
  expectedClientId: string,
): OidcSessionData | null {
  if (!serializedSession) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(serializedSession);
  } catch {
    return null;
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  const candidate = parsed as Record<string, unknown>;
  const identity = candidate["identity"];
  const oidc = candidate["oidc"];
  const expectedIssuer = getIssuerIdentifier(expectedAuthority);

  if (
    candidate["version"] !== OIDC_SESSION_VERSION ||
    candidate["clientId"] !== expectedClientId ||
    typeof candidate["accessToken"] !== "string" ||
    candidate["accessToken"].trim() === "" ||
    typeof candidate["tokenType"] !== "string" ||
    candidate["tokenType"].trim() === "" ||
    typeof candidate["expiresAt"] !== "number" ||
    !Number.isFinite(candidate["expiresAt"]) ||
    typeof candidate["idToken"] !== "string" ||
    candidate["idToken"].trim() === "" ||
    typeof candidate["scope"] !== "string" ||
    candidate["scope"].trim() === "" ||
    !isStoredIdentity(identity, expectedIssuer, expectedClientId) ||
    !oidc ||
    typeof oidc !== "object" ||
    typeof (oidc as Record<string, unknown>)["issuer"] !== "string" ||
    getIssuerIdentifier(
      (oidc as Record<string, unknown>)["issuer"] as string,
    ) !== expectedIssuer
  ) {
    return null;
  }

  return {
    version: OIDC_SESSION_VERSION,
    clientId: expectedClientId,
    accessToken: candidate["accessToken"],
    tokenType: candidate["tokenType"],
    expiresAt: candidate["expiresAt"],
    refreshToken: optionalNonEmptyString(candidate["refreshToken"]),
    idToken: candidate["idToken"],
    scope: candidate["scope"],
    identity,
    oidc: {
      issuer: expectedIssuer,
      audience: optionalNonEmptyString(
        (oidc as Record<string, unknown>)["audience"],
      ),
      sessionState: optionalNonEmptyString(
        (oidc as Record<string, unknown>)["sessionState"],
      ),
    },
  };
}

function isStoredIdentity(
  value: unknown,
  expectedIssuer: string,
  expectedClientId: string,
): value is OidcIdentityMetadata {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const identity = value as Record<string, unknown>;
  const audiences = identity["audiences"];
  const methods = identity["amr"];

  return (
    identity["issuer"] === expectedIssuer &&
    identity["clientId"] === expectedClientId &&
    typeof identity["subject"] === "string" &&
    identity["subject"] !== "" &&
    Array.isArray(audiences) &&
    audiences.length > 0 &&
    audiences.every((entry) => typeof entry === "string" && entry !== "") &&
    typeof identity["issuedAt"] === "number" &&
    Number.isFinite(identity["issuedAt"]) &&
    typeof identity["expiresAt"] === "number" &&
    Number.isFinite(identity["expiresAt"]) &&
    Array.isArray(methods) &&
    methods.every((entry) => typeof entry === "string") &&
    (identity["authorizedParty"] === null ||
      typeof identity["authorizedParty"] === "string") &&
    (identity["nonce"] === null || typeof identity["nonce"] === "string") &&
    (identity["authTime"] === null ||
      (typeof identity["authTime"] === "number" &&
        Number.isFinite(identity["authTime"]))) &&
    (identity["acr"] === null || typeof identity["acr"] === "string") &&
    (identity["sessionId"] === null ||
      typeof identity["sessionId"] === "string")
  );
}

export function parseLoginTransaction(
  serializedTransaction: string | null,
  expectedAuthority: string,
  expectedClientId: string,
  expectedState: string,
  now = Date.now(),
): LoginTransactionData | null {
  if (!serializedTransaction) {
    return null;
  }

  let parsed: unknown;

  try {
    parsed = JSON.parse(serializedTransaction);
  } catch {
    return null;
  }

  if (!isValidOAuthState(expectedState)) return null;

  try {
    const restored = restoreAuthorizationTransaction(
      parsed,
      {
        issuer: getIssuerIdentifier(expectedAuthority),
        clientId: expectedClientId,
      },
      now,
    );
    if (restored.state !== expectedState) return null;
    if (
      restored.applicationState !== undefined &&
      (!restored.applicationState ||
        typeof restored.applicationState !== "object" ||
        Array.isArray(restored.applicationState))
    ) {
      return null;
    }
    return restored;
  } catch {
    return null;
  }
}
