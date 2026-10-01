import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  GuardhouseClient,
  generateState,
  setGuardhouseDebug,
  isTransientAuthError,
} from "@guardhouse/core";
import type {
  GuardhouseConfig as CoreGuardhouseConfig,
  User as CoreUser,
} from "@guardhouse/core";
import type {
  AuthState,
  AuthContextValue,
  AppState,
  GuardhouseProviderProps,
  LoginOptions,
  LogoutOptions,
  OidcSessionData,
  StorageAdapter,
  TokenData,
} from "./types";
import {
  SessionStorageAdapter,
  StorageKeys,
  parseQueryParams,
  removeQueryParams,
  getCurrentReturnTo,
  normalizeReturnTo,
} from "./utils";
import {
  OIDC_SESSION_VERSION,
  buildRefreshedOidcSession,
  getAuthorizationResponseParams,
  getLoginTransactionStorageKey,
  getLogoutStateStorageKey,
  getOidcSessionStorageKey,
  isAuthOperationCurrent,
  isRetryablePreResponseRefreshError,
  isValidOAuthState,
  oidcIdentitiesEqual,
  getIssuerIdentifier,
  parseLoginTransaction,
  parseStoredOidcSession,
  removeStorageValueIfMatches,
  replaceStorageValueIfMatches,
  removeStorageValue,
  setStorageValue,
  resolveAuthenticatedUser,
  snapshotAuthenticatedUser,
} from "./security-state";
import { createReactLogger } from "./debug";

const DEFAULT_SCOPE = "openid profile email";
const ACCESS_TOKEN_REFRESH_LEEWAY_SECONDS = 60;
interface RefreshedSessionResult {
  session: OidcSessionData;
  snapshot: StoredOidcSessionSnapshot;
  user: CoreUser;
}
interface StoredOidcSessionSnapshot {
  session: OidcSessionData;
  serialized: string;
}
const LEGACY_STORAGE_KEYS = [
  StorageKeys.OIDC_SESSION,
  StorageKeys.ACCESS_TOKEN,
  StorageKeys.REFRESH_TOKEN,
  StorageKeys.ID_TOKEN,
  StorageKeys.EXPIRES_AT,
  StorageKeys.USER,
  StorageKeys.CODE_VERIFIER,
  StorageKeys.STATE,
  StorageKeys.NONCE,
  StorageKeys.REQUESTED_SCOPE,
  StorageKeys.REQUESTED_AUDIENCE,
  StorageKeys.PROMPT,
  StorageKeys.APP_STATE,
  StorageKeys.LOGOUT_STATE,
] as const;

const AuthContext = createContext<AuthContextValue | null>(null);

function scopeContains(scope: string | undefined, value: string): boolean {
  if (!scope) {
    return false;
  }

  return scope
    .trim()
    .split(/\s+/)
    .some((entry) => entry === value);
}

function useStableStringArray(values: readonly string[] | undefined) {
  const snapshot = useRef<string[] | undefined>(undefined);
  if (
    values === undefined ||
    snapshot.current?.length !== values.length ||
    values.some((value, index) => value !== snapshot.current?.[index])
  ) {
    snapshot.current = values === undefined ? undefined : [...values];
  }
  return snapshot.current;
}

export function GuardhouseProvider({
  config,
  children,
}: GuardhouseProviderProps) {
  // Equivalent inline arrays and redirect callbacks must not restart an
  // in-flight callback or logout. Real security-policy changes still revalidate.
  const allowedPostLogoutRedirectUris = useStableStringArray(
    config.allowedPostLogoutRedirectUris,
  );
  const requiredAcrValues = useStableStringArray(config.requiredAcrValues);
  const requiredAmrValues = useStableStringArray(config.requiredAmrValues);
  const onRedirectCallbackRef = useRef(config.onRedirectCallback);
  onRedirectCallbackRef.current = config.onRedirectCallback;
  const [state, setState] = useState<AuthState>({
    isAuthenticated: false,
    isLoading: true,
    error: null,
    user: null,
  });
  const initializedNamespaceRef = useRef<string | null>(null);
  const logoutRedirectRef = useRef<{ namespace: string } | null>(null);
  const verifiedSessionRef = useRef<{
    serialized: string;
    epoch: number;
    namespace: string;
    verify: (session: OidcSessionData) => Promise<CoreUser>;
  } | null>(null);
  const activeRefreshPromise = useRef<{
    namespace: string;
    epoch: number;
    snapshot: string;
    promise: Promise<RefreshedSessionResult | null>;
  } | null>(null);
  const activeLoginPromise = useRef<{
    namespace: string;
    epoch: number;
    promise: Promise<void>;
  } | null>(null);
  const activeCallbackPromises = useRef(new Map<string, Promise<boolean>>());
  const authOperationEpochRef = useRef(0);
  const isMountedRef = useRef<boolean>(true);

  const storage: StorageAdapter = useMemo(
    () => new SessionStorageAdapter(),
    [],
  );
  const logger = useMemo(
    () => createReactLogger("Provider", config.debug),
    [config.debug],
  );
  const issuerIdentifier = useMemo(
    () => getIssuerIdentifier(config.authority),
    [config.authority],
  );
  const oidcSessionStorageKey = useMemo(
    () => getOidcSessionStorageKey(issuerIdentifier, config.clientId),
    [config.clientId, issuerIdentifier],
  );
  const logoutStateStorageKey = useMemo(
    () => getLogoutStateStorageKey(issuerIdentifier, config.clientId),
    [config.clientId, issuerIdentifier],
  );
  const currentNamespaceRef = useRef(oidcSessionStorageKey);
  currentNamespaceRef.current = oidcSessionStorageKey;
  const invalidateAuthOperations = useCallback((): number => {
    verifiedSessionRef.current = null;
    authOperationEpochRef.current += 1;
    return authOperationEpochRef.current;
  }, []);
  const isCurrentAuthOperation = useCallback(
    (operationEpoch: number, operationNamespace: string): boolean =>
      isAuthOperationCurrent(
        operationEpoch,
        authOperationEpochRef.current,
        operationNamespace,
        currentNamespaceRef.current,
      ),
    [],
  );

  const clientConfig = useMemo<CoreGuardhouseConfig>(
    () => ({
      authority: config.authority,
      clientId: config.clientId,
      scope: config.scope,
      tokenEndpoint: config.tokenEndpoint,
      userInfoEndpoint: config.userInfoEndpoint,
      introspectionEndpoint: config.introspectionEndpoint,
      revocationEndpoint: config.revocationEndpoint,
      requestTimeoutMs: config.requestTimeoutMs,
      discoveryCacheTtlMs: config.discoveryCacheTtlMs,
      allowScopeNarrowing: config.allowScopeNarrowing,
      maxAuthorizationHeaderBytes: config.maxAuthorizationHeaderBytes,
      maxSilentAuthAttempts: config.maxSilentAuthAttempts,
      requireUserInteractionForSensitiveOperations:
        config.requireUserInteractionForSensitiveOperations,
      allowedPostLogoutRedirectUris,
      allowUnsafeHttpMethods: config.allowUnsafeHttpMethods,
      requireDpopForAccessTokenRequests:
        config.requireDpopForAccessTokenRequests,
      dpopProofFactory: config.dpopProofFactory,
      debug: config.debug,
    }),
    [
      config.allowScopeNarrowing,
      config.allowUnsafeHttpMethods,
      allowedPostLogoutRedirectUris,
      config.authority,
      config.clientId,
      config.debug,
      config.discoveryCacheTtlMs,
      config.dpopProofFactory,
      config.introspectionEndpoint,
      config.maxAuthorizationHeaderBytes,
      config.maxSilentAuthAttempts,
      config.requestTimeoutMs,
      config.requireDpopForAccessTokenRequests,
      config.requireUserInteractionForSensitiveOperations,
      config.revocationEndpoint,
      config.scope,
      config.tokenEndpoint,
      config.userInfoEndpoint,
    ],
  );

  const client = useMemo(
    () => new GuardhouseClient(clientConfig),
    [clientConfig],
  );

  useEffect(() => {
    isMountedRef.current = true;

    return () => {
      invalidateAuthOperations();
      isMountedRef.current = false;
    };
  }, [invalidateAuthOperations]);

  useEffect(() => {
    setGuardhouseDebug(Boolean(config.debug));
    logger.info("Debug mode updated", { enabled: Boolean(config.debug) });
  }, [config.debug, logger]);

  const handleError = useCallback(
    (error: unknown) => {
      verifiedSessionRef.current = null;
      const normalizedError =
        error instanceof Error ? error : new Error("Authentication failed");
      logger.error("Authentication flow failed", {
        error: normalizedError.message,
      });

      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: normalizedError,
        isAuthenticated: false,
        user: null,
      }));
    },
    [logger],
  );

  const handleSuccess = useCallback(
    (user: CoreUser, tokenData?: TokenData) => {
      const immutableUser = snapshotAuthenticatedUser(user);
      logger.debug("Updating auth state to authenticated", {
        subject: immutableUser.sub,
        hasTokenData: Boolean(tokenData),
      });

      setState((prev) => ({
        ...prev,
        isLoading: false,
        error: null,
        isAuthenticated: true,
        user: immutableUser,
      }));

      logger.info("Authentication flow completed", {
        subject: immutableUser.sub,
      });
    },
    [logger],
  );

  const handleLoading = useCallback(() => {
    logger.debug("Authentication flow loading state enabled");
    setState((prev) => ({ ...prev, isLoading: true }));
  }, [logger]);

  const clearLegacyStorage = useCallback(async () => {
    await Promise.all(
      LEGACY_STORAGE_KEYS.map((key) => removeStorageValue(storage, key)),
    );
  }, [storage]);

  const clearAuthState = useCallback(async (): Promise<number> => {
    const invalidationEpoch = invalidateAuthOperations();
    logger.debug("Clearing stored auth state from session storage");

    await Promise.all([
      removeStorageValue(storage, oidcSessionStorageKey),
      clearLegacyStorage(),
    ]);
    await client.clearSessionState();

    if (
      isMountedRef.current &&
      isCurrentAuthOperation(invalidationEpoch, oidcSessionStorageKey)
    ) {
      setState({
        isAuthenticated: false,
        // The document is still alive until the logout navigation completes.
        // Route guards must not start another login in this interval.
        isLoading: true,
        error: null,
        user: null,
      });
    }

    return invalidationEpoch;
  }, [
    clearLegacyStorage,
    client,
    invalidateAuthOperations,
    isCurrentAuthOperation,
    logger,
    oidcSessionStorageKey,
    storage,
  ]);

  const parseOidcSessionSnapshot = useCallback(
    (serialized: string | null): StoredOidcSessionSnapshot | null => {
      if (!serialized) return null;
      const session = parseStoredOidcSession(
        serialized,
        issuerIdentifier,
        config.clientId,
      );
      return session ? { session, serialized } : null;
    },
    [config.clientId, issuerIdentifier],
  );

  const readCurrentOidcSessionSnapshot = useCallback(
    async (): Promise<StoredOidcSessionSnapshot | null> =>
      parseOidcSessionSnapshot(await storage.getItem(oidcSessionStorageKey)),
    [oidcSessionStorageKey, parseOidcSessionSnapshot, storage],
  );

  const readStoredOidcSession =
    useCallback(async (): Promise<StoredOidcSessionSnapshot | null> => {
      await clearLegacyStorage();

      const serializedSession = await storage.getItem(oidcSessionStorageKey);
      const snapshot = parseOidcSessionSnapshot(serializedSession);
      if (snapshot || !serializedSession) return snapshot;

      await removeStorageValueIfMatches(
        storage,
        oidcSessionStorageKey,
        serializedSession,
      );

      // A compare-and-remove can lose to a newer writer. Inspect at most one
      // replacement record and never delete it using the stale serialization.
      const replacementSerialized = await storage.getItem(
        oidcSessionStorageKey,
      );
      const replacement = parseOidcSessionSnapshot(replacementSerialized);
      if (replacement || !replacementSerialized) return replacement;

      await removeStorageValueIfMatches(
        storage,
        oidcSessionStorageKey,
        replacementSerialized,
      );
      return null;
    }, [
      clearLegacyStorage,
      oidcSessionStorageKey,
      parseOidcSessionSnapshot,
      storage,
    ]);

  const createOidcSessionSnapshot = useCallback(
    (sessionData: OidcSessionData): StoredOidcSessionSnapshot => {
      if (
        sessionData.version !== OIDC_SESSION_VERSION ||
        sessionData.clientId !== config.clientId ||
        getIssuerIdentifier(sessionData.oidc.issuer) !== issuerIdentifier ||
        sessionData.identity.clientId !== config.clientId ||
        getIssuerIdentifier(sessionData.identity.issuer) !== issuerIdentifier ||
        !sessionData.idToken ||
        !sessionData.scope
      ) {
        throw new Error(
          "Refusing to persist an OIDC session for another client",
        );
      }

      return {
        session: sessionData,
        serialized: JSON.stringify(sessionData),
      };
    },
    [config.clientId, issuerIdentifier],
  );

  const persistOidcSession = useCallback(
    async (
      sessionData: OidcSessionData,
    ): Promise<StoredOidcSessionSnapshot> => {
      const snapshot = createOidcSessionSnapshot(sessionData);
      await setStorageValue(
        storage,
        oidcSessionStorageKey,
        snapshot.serialized,
      );
      return snapshot;
    },
    [createOidcSessionSnapshot, oidcSessionStorageKey, storage],
  );

  const replacePersistedOidcSessionIfMatches = useCallback(
    async (
      previousSnapshot: StoredOidcSessionSnapshot,
      sessionData: OidcSessionData,
    ): Promise<StoredOidcSessionSnapshot | null> => {
      const replacement = createOidcSessionSnapshot(sessionData);
      const replaced = await replaceStorageValueIfMatches(
        storage,
        oidcSessionStorageKey,
        previousSnapshot.serialized,
        replacement.serialized,
      );
      return replaced ? replacement : null;
    },
    [createOidcSessionSnapshot, oidcSessionStorageKey, storage],
  );

  const removePersistedSessionIfMatches = useCallback(
    async (
      snapshot: StoredOidcSessionSnapshot,
    ): Promise<StoredOidcSessionSnapshot | null> => {
      await removeStorageValueIfMatches(
        storage,
        oidcSessionStorageKey,
        snapshot.serialized,
      );

      const currentSerialized = await storage.getItem(oidcSessionStorageKey);
      const current = parseOidcSessionSnapshot(currentSerialized);
      if (current) return current;

      if (currentSerialized) {
        await removeStorageValueIfMatches(
          storage,
          oidcSessionStorageKey,
          currentSerialized,
        );

        // One bounded read lets a valid session that won the invalid-record
        // cleanup race survive and be restored by the caller.
        const replacementSerialized = await storage.getItem(
          oidcSessionStorageKey,
        );
        const replacement = parseOidcSessionSnapshot(replacementSerialized);
        if (replacement) return replacement;
        if (replacementSerialized) {
          await removeStorageValueIfMatches(
            storage,
            oidcSessionStorageKey,
            replacementSerialized,
          );
        }
      }

      await client.clearSessionState();
      return null;
    },
    [client, oidcSessionStorageKey, parseOidcSessionSnapshot, storage],
  );

  const verifySessionIdentity = useCallback(
    async (sessionData: OidcSessionData): Promise<CoreUser> => {
      // Stored metadata only selects the verification path. The signed token
      // and live UserInfo must still agree before any user is authenticated.
      if (
        sessionData.idTokenCurrent === false ||
        sessionData.identity.expiresAt <= Math.floor(Date.now() / 1000)
      ) {
        const restored = await client.restoreOidcSession(
          sessionData.accessToken,
          {
            idToken: sessionData.idToken,
            requiredAcrValues,
            requiredAmrValues,
          },
        );
        if (!oidcIdentitiesEqual(restored.identity, sessionData.identity)) {
          throw new Error(
            "Stored OIDC identity does not match the signed ID token",
          );
        }
        return snapshotAuthenticatedUser(restored.userInfo);
      }
      const verified = await client.verifyIdToken(sessionData.idToken, {
        purpose: "session",
        requiredAcrValues,
        requiredAmrValues,
      });
      if (!oidcIdentitiesEqual(verified.identity, sessionData.identity)) {
        throw new Error(
          "Stored OIDC identity does not match the signed ID token",
        );
      }

      const { user } = await resolveAuthenticatedUser(verified.payload, () =>
        client.getUserInfo(sessionData.accessToken, verified.identity),
      );
      return user;
    },
    [client, requiredAcrValues, requiredAmrValues],
  );

  const rememberVerifiedSession = useCallback(
    (snapshot: StoredOidcSessionSnapshot, epoch: number) => {
      if (isCurrentAuthOperation(epoch, oidcSessionStorageKey)) {
        verifiedSessionRef.current = {
          serialized: snapshot.serialized,
          epoch,
          namespace: oidcSessionStorageKey,
          verify: verifySessionIdentity,
        };
      }
    },
    [isCurrentAuthOperation, oidcSessionStorageKey, verifySessionIdentity],
  );

  const refreshSession = useCallback(
    async (
      sessionSnapshot: StoredOidcSessionSnapshot,
      allowNewerRecovery = true,
    ): Promise<RefreshedSessionResult | null> => {
      const operationEpoch = authOperationEpochRef.current;

      if (
        activeRefreshPromise.current?.namespace === oidcSessionStorageKey &&
        activeRefreshPromise.current.epoch === operationEpoch &&
        activeRefreshPromise.current.snapshot === sessionSnapshot.serialized
      ) {
        logger.debug("Joining in-flight token refresh request");
        return activeRefreshPromise.current.promise;
      }

      const refreshPromise =
        (async (): Promise<RefreshedSessionResult | null> => {
          const restoreReplacement = async (
            replacement: StoredOidcSessionSnapshot,
          ): Promise<RefreshedSessionResult | null> => {
            if (
              !isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)
            ) {
              return null;
            }

            if (
              replacement.session.expiresAt <= Math.floor(Date.now() / 1000)
            ) {
              return runRefresh(replacement, false);
            }

            try {
              const user = await verifySessionIdentity(replacement.session);
              const current = await readCurrentOidcSessionSnapshot();
              if (current?.serialized !== replacement.serialized) {
                return null;
              }
              return {
                session: replacement.session,
                snapshot: replacement,
                user,
              };
            } catch (error) {
              logger.warn("Newer stored session could not be restored", {
                error: String(error),
              });
              if (isTransientAuthError(error)) throw error;
              await removePersistedSessionIfMatches(replacement);
              return null;
            }
          };

          const discardAndMaybeRecover = async (
            staleSnapshot: StoredOidcSessionSnapshot,
            canRecoverNewer: boolean,
          ): Promise<RefreshedSessionResult | null> => {
            const replacement =
              await removePersistedSessionIfMatches(staleSnapshot);
            if (!replacement || !canRecoverNewer) return null;
            return restoreReplacement(replacement);
          };

          const restoreCurrentWinner = async (
            staleSnapshot: StoredOidcSessionSnapshot,
            canRecoverNewer: boolean,
          ): Promise<RefreshedSessionResult | null> => {
            const current = await readCurrentOidcSessionSnapshot();
            if (
              !current ||
              current.serialized === staleSnapshot.serialized ||
              !canRecoverNewer
            ) {
              return null;
            }
            return restoreReplacement(current);
          };

          async function runRefresh(
            candidate: StoredOidcSessionSnapshot,
            canRecoverNewer: boolean,
          ): Promise<RefreshedSessionResult | null> {
            const sessionData = candidate.session;
            if (
              sessionData.version !== OIDC_SESSION_VERSION ||
              sessionData.clientId !== config.clientId ||
              getIssuerIdentifier(sessionData.oidc.issuer) !==
                issuerIdentifier ||
              !sessionData.idToken
            ) {
              return discardAndMaybeRecover(candidate, canRecoverNewer);
            }

            if (!sessionData.refreshToken) {
              return discardAndMaybeRecover(candidate, canRecoverNewer);
            }

            let refreshResponseSucceeded = false;
            try {
              const refreshResult = await client.refreshOidcSession(
                sessionData.refreshToken,
                {
                  previousIdToken: sessionData.idToken,
                  grantedScope: sessionData.scope,
                  requiredAcrValues,
                  requiredAmrValues,
                },
              );
              refreshResponseSucceeded = true;
              const tokenResponse = refreshResult.tokens;

              if (
                !isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)
              ) {
                return null;
              }

              const refreshedSession = buildRefreshedOidcSession(
                sessionData,
                tokenResponse,
                refreshResult.identity,
              );

              let refreshedUser: CoreUser;
              if (refreshResult.identityStatus === "current") {
                const resolved = await resolveAuthenticatedUser(
                  refreshResult.idToken.payload,
                  () =>
                    client.getUserInfo(
                      tokenResponse.access_token,
                      refreshResult.identity,
                    ),
                );
                refreshedUser = resolved.user;
              } else {
                // Historical evidence may authorize UserInfo subject binding,
                // but it never turns the expired ID token into a current token.
                const userInfo = await client.getUserInfo(
                  tokenResponse.access_token,
                  refreshResult.identity,
                );
                if (userInfo.sub !== refreshResult.identity.subject) {
                  throw new Error(
                    "UserInfo subject does not match the historical ID token subject",
                  );
                }
                refreshedUser = snapshotAuthenticatedUser(userInfo);
              }

              if (
                !isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)
              ) {
                return null;
              }

              const refreshedSnapshot =
                await replacePersistedOidcSessionIfMatches(
                  candidate,
                  refreshedSession,
                );

              if (!refreshedSnapshot) {
                return restoreCurrentWinner(candidate, canRecoverNewer);
              }

              if (
                !isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)
              ) {
                await removePersistedSessionIfMatches(refreshedSnapshot);
                return null;
              }

              const currentSnapshot = await readCurrentOidcSessionSnapshot();
              if (
                currentSnapshot?.serialized !== refreshedSnapshot.serialized
              ) {
                if (!currentSnapshot || !canRecoverNewer) return null;
                return restoreReplacement(currentSnapshot);
              }

              logger.info("Silent token refresh succeeded", {
                expiresAt: refreshedSession.expiresAt,
              });

              return {
                session: refreshedSession,
                snapshot: refreshedSnapshot,
                user: refreshedUser,
              };
            } catch (error) {
              if (
                !isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)
              ) {
                return null;
              }

              logger.error("Token refresh failed", {
                error: String(error),
              });
              if (
                refreshResponseSucceeded ||
                !isRetryablePreResponseRefreshError(error)
              ) {
                return discardAndMaybeRecover(candidate, canRecoverNewer);
              }
              const winner = await restoreCurrentWinner(
                candidate,
                canRecoverNewer,
              );
              if (winner) return winner;
              throw error;
            }
          }

          return runRefresh(sessionSnapshot, allowNewerRecovery);
        })();

      activeRefreshPromise.current = {
        namespace: oidcSessionStorageKey,
        epoch: operationEpoch,
        snapshot: sessionSnapshot.serialized,
        promise: refreshPromise,
      };

      try {
        const result = await refreshPromise;
        if (result) rememberVerifiedSession(result.snapshot, operationEpoch);
        return result;
      } finally {
        if (activeRefreshPromise.current?.promise === refreshPromise) {
          activeRefreshPromise.current = null;
        }
      }
    },
    [
      client,
      config.clientId,
      requiredAcrValues,
      requiredAmrValues,
      logger,
      isCurrentAuthOperation,
      issuerIdentifier,
      oidcSessionStorageKey,
      readCurrentOidcSessionSnapshot,
      replacePersistedOidcSessionIfMatches,
      removePersistedSessionIfMatches,
      verifySessionIdentity,
      rememberVerifiedSession,
    ],
  );

  const restoreSessionSnapshot = useCallback(
    async (
      initialSnapshot: StoredOidcSessionSnapshot,
      allowNewerRecovery = true,
    ): Promise<RefreshedSessionResult | null> => {
      const operationEpoch = authOperationEpochRef.current;
      const restore = async (
        candidate: StoredOidcSessionSnapshot,
        canRecoverNewer: boolean,
      ): Promise<RefreshedSessionResult | null> => {
        if (candidate.session.expiresAt <= Math.floor(Date.now() / 1000)) {
          return refreshSession(candidate, canRecoverNewer);
        }

        let user: CoreUser;
        try {
          user = await verifySessionIdentity(candidate.session);
        } catch (error) {
          logger.warn("Stored session identity validation failed", {
            error: String(error),
          });
          if (isTransientAuthError(error)) throw error;
          const replacement = await removePersistedSessionIfMatches(candidate);
          if (!replacement || !canRecoverNewer) return null;
          return restore(replacement, false);
        }

        const current = await readCurrentOidcSessionSnapshot();
        if (current?.serialized === candidate.serialized) {
          return {
            session: candidate.session,
            snapshot: candidate,
            user,
          };
        }

        if (!current || !canRecoverNewer) return null;
        return restore(current, false);
      };

      const result = await restore(initialSnapshot, allowNewerRecovery);
      if (result) rememberVerifiedSession(result.snapshot, operationEpoch);
      return result;
    },
    [
      logger,
      readCurrentOidcSessionSnapshot,
      refreshSession,
      removePersistedSessionIfMatches,
      verifySessionIdentity,
      rememberVerifiedSession,
    ],
  );

  const handleCallback = useCallback(async (): Promise<boolean> => {
    const callbackUrl = window.location.href;
    const response = getAuthorizationResponseParams(callbackUrl);
    const returnedStates = response
      ? [...new Set(response.stateCandidates.filter(isValidOAuthState))]
      : [];

    if (!response || returnedStates.length === 0) {
      logger.debug("Ignoring URL without a matching OAuth transaction");
      return false;
    }

    const candidateTransactions = returnedStates.map((returnedState) => ({
      returnedState,
      storageKey: getLoginTransactionStorageKey(
        issuerIdentifier,
        config.clientId,
        returnedState,
      ),
    }));
    const existingCallback = candidateTransactions
      .map(({ storageKey }) => activeCallbackPromises.current.get(storageKey))
      .find((candidate): candidate is Promise<boolean> => Boolean(candidate));

    if (existingCallback) {
      return existingCallback;
    }

    const callbackPromise = (async (): Promise<boolean> => {
      await clearLegacyStorage();

      let matchedTransaction:
        | {
            storageKey: string;
            serialized: string;
            transaction: NonNullable<ReturnType<typeof parseLoginTransaction>>;
          }
        | undefined;

      for (const { returnedState, storageKey } of candidateTransactions) {
        const serializedTransaction = await storage.getItem(storageKey);
        const transaction = parseLoginTransaction(
          serializedTransaction,
          issuerIdentifier,
          config.clientId,
          returnedState,
        );

        if (transaction && serializedTransaction) {
          matchedTransaction = {
            storageKey,
            serialized: serializedTransaction,
            transaction,
          };
          break;
        }

        if (serializedTransaction) {
          await removeStorageValueIfMatches(
            storage,
            storageKey,
            serializedTransaction,
          );
        }
      }

      if (!matchedTransaction) {
        return false;
      }

      if (!isMountedRef.current) {
        return true;
      }

      const operationEpoch = invalidateAuthOperations();
      handleLoading();

      try {
        const consumed = await removeStorageValueIfMatches(
          storage,
          matchedTransaction.storageKey,
          matchedTransaction.serialized,
        );
        if (!consumed) {
          return false;
        }

        const transaction = matchedTransaction.transaction;
        const callback = await client.validateOAuthCallback(
          { mode: "query", url: callbackUrl },
          transaction,
        );
        removeQueryParams();

        if (callback.type === "error") {
          const callbackError = new Error(
            callback.errorDescription || callback.error,
          ) as Error & { code?: string };
          callbackError.code = callback.error;
          throw callbackError;
        }

        if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
          return true;
        }

        const exchangeResult = await client.exchangeAuthorizationCode(callback);
        if (exchangeResult.mode !== "oidc") {
          throw new Error(
            "React authentication requires an OIDC token response",
          );
        }
        const tokenData = exchangeResult.tokens;
        const verifiedIdToken = exchangeResult.idToken;

        if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
          return true;
        }

        logger.debug("Token exchange succeeded", {
          expiresIn: tokenData.expires_in,
          hasRefreshToken: Boolean(tokenData.refresh_token),
          hasIdToken: Boolean(tokenData.id_token),
        });

        const { user: authenticatedUser } = await resolveAuthenticatedUser(
          verifiedIdToken.payload,
          () =>
            client.getUserInfo(
              tokenData.access_token,
              verifiedIdToken.identity,
            ),
        );

        if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
          return true;
        }

        const oidcSession: OidcSessionData = {
          version: OIDC_SESSION_VERSION,
          clientId: transaction.clientId,
          accessToken: tokenData.access_token,
          tokenType: tokenData.token_type,
          expiresAt: Math.floor(Date.now() / 1000) + tokenData.expires_in,
          refreshToken: tokenData.refresh_token,
          idToken: tokenData.id_token!,
          idTokenCurrent: true,
          scope: tokenData.scope || transaction.requestedScope,
          identity: verifiedIdToken.identity,
          oidc: {
            issuer: transaction.issuer,
            audience: transaction.requestedAudience,
            sessionState: callback.sessionState,
          },
        };

        if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
          return true;
        }

        const persistedSnapshot = await persistOidcSession(oidcSession);

        if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
          await removePersistedSessionIfMatches(persistedSnapshot);
          return true;
        }

        rememberVerifiedSession(persistedSnapshot, operationEpoch);
        handleSuccess(authenticatedUser, tokenData);
        if (onRedirectCallbackRef.current) {
          await onRedirectCallbackRef.current(
            transaction.applicationState as AppState | undefined,
          );
        } else {
          const applicationState = transaction.applicationState as
            | AppState
            | undefined;
          const returnTo = normalizeReturnTo(applicationState?.returnTo ?? "/");
          window.location.replace(
            new URL(returnTo, window.location.origin).toString(),
          );
        }

        logger.info("OAuth callback handled successfully", {
          subject: authenticatedUser.sub,
        });
      } catch (error) {
        if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
          return true;
        }

        removeQueryParams();
        const normalizedError =
          error instanceof Error ? error : new Error("Unknown error occurred");

        if (
          isMountedRef.current &&
          isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)
        ) {
          const previousSnapshot = await readStoredOidcSession();
          const previousSession = previousSnapshot
            ? await restoreSessionSnapshot(previousSnapshot)
            : null;

          if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
            return true;
          }

          setState({
            isLoading: false,
            error: normalizedError,
            isAuthenticated: Boolean(previousSession),
            user: previousSession?.user ?? null,
          });
        } else {
          logger.warn(
            "Skipping callback error state update after context change",
            {
              error: normalizedError.message,
            },
          );
        }
      }

      return true;
    })();

    for (const { storageKey } of candidateTransactions) {
      activeCallbackPromises.current.set(storageKey, callbackPromise);
    }

    try {
      return await callbackPromise;
    } finally {
      for (const { storageKey } of candidateTransactions) {
        if (
          activeCallbackPromises.current.get(storageKey) === callbackPromise
        ) {
          activeCallbackPromises.current.delete(storageKey);
        }
      }
    }
  }, [
    clearLegacyStorage,
    client,
    config.clientId,
    handleLoading,
    handleSuccess,
    rememberVerifiedSession,
    invalidateAuthOperations,
    isCurrentAuthOperation,
    logger,
    issuerIdentifier,
    oidcSessionStorageKey,
    persistOidcSession,
    readStoredOidcSession,
    removePersistedSessionIfMatches,
    restoreSessionSnapshot,
    storage,
  ]);

  const handlePostLogoutRedirect = useCallback(async (): Promise<boolean> => {
    const searchParams = parseQueryParams(window.location.search);
    const hashParams = parseQueryParams(
      window.location.hash.startsWith("#")
        ? `?${window.location.hash.slice(1)}`
        : window.location.hash,
    );

    const callbackState = searchParams["state"] ?? hashParams["state"];
    if (!callbackState) {
      return false;
    }

    const expectedLogoutState = await storage.getItem(logoutStateStorageKey);
    const matchesExpectedLogoutState =
      typeof expectedLogoutState === "string" &&
      expectedLogoutState.trim() !== "" &&
      typeof callbackState === "string" &&
      callbackState.trim() !== "" &&
      callbackState === expectedLogoutState;

    if (!matchesExpectedLogoutState) {
      return false;
    }

    logger.debug("Detected post-logout callback, sanitizing URL", {
      hasState: Boolean(callbackState),
    });

    await removeStorageValue(storage, logoutStateStorageKey);
    removeQueryParams();

    return true;
  }, [logger, logoutStateStorageKey, storage]);

  const checkSession = useCallback(async () => {
    const operationEpoch = authOperationEpochRef.current;

    try {
      if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
        return;
      }

      handleLoading();
      logger.debug("Checking existing session in session storage");

      const sessionSnapshot = await readStoredOidcSession();

      if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
        return;
      }

      if (!sessionSnapshot) {
        logger.debug("No active OIDC session found");
        setState((prev) => ({ ...prev, isLoading: false }));
        return;
      }

      if (sessionSnapshot.session.expiresAt <= Math.floor(Date.now() / 1000)) {
        logger.info("Stored OIDC session has expired", {
          expiresAt: sessionSnapshot.session.expiresAt,
        });
      }

      const restoredSession = await restoreSessionSnapshot(sessionSnapshot);

      if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
        return;
      }

      if (!restoredSession) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          isAuthenticated: false,
          user: null,
        }));
        return;
      }

      handleSuccess(restoredSession.user);

      logger.info("Restored authenticated session", {
        subject: restoredSession.user.sub,
      });
    } catch (error) {
      if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
        return;
      }

      logger.error("Session check failed", {
        error: String(error),
      });
      handleError(error);
    }
  }, [
    handleLoading,
    handleSuccess,
    handleError,
    isCurrentAuthOperation,
    logger,
    oidcSessionStorageKey,
    readStoredOidcSession,
    restoreSessionSnapshot,
  ]);

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    if (initializedNamespaceRef.current === oidcSessionStorageKey) {
      return;
    }

    initializedNamespaceRef.current = oidcSessionStorageKey;
    logoutRedirectRef.current = null;
    logger.debug("Initializing Guardhouse React provider");
    setState({
      isAuthenticated: false,
      isLoading: true,
      error: null,
      user: null,
    });

    void (async () => {
      await clearLegacyStorage();
      const handledCallback = await handleCallback();

      if (
        handledCallback ||
        currentNamespaceRef.current !== oidcSessionStorageKey
      ) {
        return;
      }

      await handlePostLogoutRedirect();

      if (currentNamespaceRef.current !== oidcSessionStorageKey) {
        return;
      }

      await checkSession();
    })().catch((error: unknown) => {
      if (currentNamespaceRef.current !== oidcSessionStorageKey) {
        return;
      }

      handleError(error);
    });

    return () => {
      if (initializedNamespaceRef.current === oidcSessionStorageKey) {
        initializedNamespaceRef.current = null;
      }
    };
  }, [
    checkSession,
    clearLegacyStorage,
    handleCallback,
    handleError,
    handlePostLogoutRedirect,
    logger,
    oidcSessionStorageKey,
  ]);

  const loginWithRedirect = useCallback(
    (options?: LoginOptions): Promise<void> => {
      const operationEpoch = authOperationEpochRef.current;

      if (
        activeLoginPromise.current?.namespace === oidcSessionStorageKey &&
        activeLoginPromise.current.epoch === operationEpoch
      ) {
        logger.debug("Joining in-flight redirect login request");
        return activeLoginPromise.current.promise;
      }

      let transactionStorageKey: string | null = null;
      let serializedTransaction: string | null = null;
      let navigationAssigned = false;

      const removeOwnTransaction = async (): Promise<void> => {
        if (!transactionStorageKey || !serializedTransaction) {
          return;
        }

        await removeStorageValueIfMatches(
          storage,
          transactionStorageKey,
          serializedTransaction,
        );
      };

      const loginPromise = (async (): Promise<void> => {
        try {
          logger.info("Starting redirect login flow");
          await clearLegacyStorage();

          if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
            return;
          }

          const requestedScope =
            options?.scope?.trim() || config.scope || DEFAULT_SCOPE;
          const requestedAudience =
            options?.audience?.trim() || config.audience?.trim();
          const requestedResource = options?.resource ?? config.resource;

          if (!scopeContains(requestedScope, "openid")) {
            throw new Error(
              "GuardhouseProvider requires the openid scope for authenticated identity",
            );
          }

          if (
            scopeContains(requestedScope, "offline_access") &&
            !config.allowOfflineAccessScope
          ) {
            throw new Error(
              "offline_access scope requires allowOfflineAccessScope=true",
            );
          }

          const authorizationRequest = await client.createAuthorizationRequest({
            redirectUri: config.redirectUri,
            scope: requestedScope,
            allowOfflineAccessScope: Boolean(config.allowOfflineAccessScope),
            audiencePolicy: config.audiencePolicy ?? "guardhouse-required",
            prompt: options?.prompt,
            audience: requestedAudience,
            resource: requestedResource,
            maxAgeSeconds: options?.maxAgeSeconds ?? config.maxAgeSeconds,
            requiredAcrValues,
            requiredAmrValues,
            applicationState: {
              ...options?.appState,
              returnTo: normalizeReturnTo(
                options?.appState?.returnTo ?? getCurrentReturnTo(),
              ),
            },
          });
          const transaction = authorizationRequest.transaction;

          transactionStorageKey = getLoginTransactionStorageKey(
            issuerIdentifier,
            config.clientId,
            transaction.state,
          );
          serializedTransaction = JSON.stringify(transaction);

          if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
            return;
          }

          await setStorageValue(
            storage,
            transactionStorageKey,
            serializedTransaction,
          );

          if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
            await removeOwnTransaction();
            return;
          }

          logger.debug("Redirecting browser to authorization endpoint", {
            authority: issuerIdentifier,
          });

          if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
            await removeOwnTransaction();
            return;
          }

          window.location.href = authorizationRequest.authorizationUrl;
          navigationAssigned = true;
        } catch (error) {
          await removeOwnTransaction();

          if (isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
            handleError(error);
          }
          throw error;
        }
      })();

      activeLoginPromise.current = {
        namespace: oidcSessionStorageKey,
        epoch: operationEpoch,
        promise: loginPromise,
      };

      const releaseLogin = () => {
        if (
          !navigationAssigned &&
          activeLoginPromise.current?.promise === loginPromise
        ) {
          activeLoginPromise.current = null;
        }
      };
      void loginPromise.then(releaseLogin, releaseLogin);

      return loginPromise;
    },
    [
      clearLegacyStorage,
      config.allowOfflineAccessScope,
      client,
      config.audiencePolicy,
      config.audience,
      config.clientId,
      config.maxAgeSeconds,
      config.redirectUri,
      requiredAcrValues,
      requiredAmrValues,
      config.resource,
      config.scope,
      handleError,
      isCurrentAuthOperation,
      logger,
      issuerIdentifier,
      oidcSessionStorageKey,
      storage,
    ],
  );

  const logout = useCallback(
    async (options?: LogoutOptions) => {
      if (
        currentNamespaceRef.current !== oidcSessionStorageKey ||
        logoutRedirectRef.current?.namespace === oidcSessionStorageKey
      ) {
        return;
      }

      const operationEpoch = invalidateAuthOperations();

      const requestedReturnTo =
        options?.returnTo ||
        config.logoutRedirectUri ||
        config.redirectUri ||
        window.location.origin;
      const returnTo = new URL(
        normalizeReturnTo(requestedReturnTo),
        window.location.origin,
      ).toString();

      logger.info("Starting logout flow", {
        returnTo,
      });

      const currentSession = await readStoredOidcSession();

      if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
        return;
      }

      const logoutState = await generateState(18, config.debug);

      if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
        return;
      }

      const logoutUrl = await client.buildLogoutUrl({
        postLogoutRedirectUri: returnTo,
        idTokenHint: currentSession?.session.idToken,
        state: logoutState,
        federated: options?.federated,
      });

      await setStorageValue(storage, logoutStateStorageKey, logoutState);

      if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
        await removeStorageValueIfMatches(
          storage,
          logoutStateStorageKey,
          logoutState,
        );
        return;
      }

      logger.debug("Clearing local auth state before redirecting to logout");
      const logoutRedirect = { namespace: oidcSessionStorageKey };
      logoutRedirectRef.current = logoutRedirect;
      try {
        const clearEpoch = await clearAuthState();

        if (!isCurrentAuthOperation(clearEpoch, oidcSessionStorageKey)) {
          return;
        }

        logger.debug("Redirecting browser to logout endpoint", {
          authority: config.authority,
        });
        window.location.href = logoutUrl;
      } catch (error) {
        if (
          logoutRedirectRef.current === logoutRedirect &&
          currentNamespaceRef.current === oidcSessionStorageKey
        ) {
          logoutRedirectRef.current = null;
          handleError(error);
        }
        throw error;
      }
    },
    [
      clearAuthState,
      client,
      config.authority,
      config.debug,
      config.logoutRedirectUri,
      config.redirectUri,
      handleError,
      logger,
      invalidateAuthOperations,
      isCurrentAuthOperation,
      logoutStateStorageKey,
      oidcSessionStorageKey,
      readStoredOidcSession,
      storage,
    ],
  );

  const getAccessTokenSilently = useCallback(async (): Promise<
    string | null
  > => {
    if (logoutRedirectRef.current?.namespace === oidcSessionStorageKey) {
      return null;
    }
    const operationEpoch = authOperationEpochRef.current;

    if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
      return null;
    }

    logger.debug("Attempting silent access token retrieval");

    const sessionSnapshot = await readStoredOidcSession();

    if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
      return null;
    }

    if (!sessionSnapshot) {
      logger.debug("No OIDC session available for silent retrieval");
      verifiedSessionRef.current = null;
      setState((prev) =>
        !prev.isLoading &&
        !prev.isAuthenticated &&
        prev.user === null &&
        prev.error === null
          ? prev
          : {
              isLoading: false,
              isAuthenticated: false,
              user: null,
              error: null,
            },
      );
      return null;
    }

    const sessionData = sessionSnapshot.session;

    const now = Math.floor(Date.now() / 1000);

    const hasValidity =
      sessionData.expiresAt > now &&
      (!sessionData.refreshToken ||
        sessionData.expiresAt > now + ACCESS_TOKEN_REFRESH_LEEWAY_SECONDS);
    const verified = verifiedSessionRef.current;
    if (
      hasValidity &&
      verified?.serialized === sessionSnapshot.serialized &&
      verified.epoch === operationEpoch &&
      verified.namespace === oidcSessionStorageKey &&
      verified.verify === verifySessionIdentity
    ) {
      logger.debug("Using existing access token for silent retrieval", {
        expiresAt: sessionData.expiresAt,
      });
      return sessionData.accessToken;
    }

    let refreshedSession: RefreshedSessionResult | null;
    try {
      refreshedSession = hasValidity
        ? await restoreSessionSnapshot(sessionSnapshot)
        : await refreshSession(sessionSnapshot);
    } catch (error) {
      if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey))
        return null;
      if (!isTransientAuthError(error)) throw error;
      handleError(error);
      return null;
    }

    if (!isCurrentAuthOperation(operationEpoch, oidcSessionStorageKey)) {
      return null;
    }

    if (!refreshedSession) {
      verifiedSessionRef.current = null;
      setState((prev) => ({
        ...prev,
        error: null,
        isLoading: false,
        isAuthenticated: false,
        user: null,
      }));
      return null;
    }

    setState((prev) => ({
      ...prev,
      isLoading: false,
      isAuthenticated: true,
      error: null,
      user: refreshedSession.user,
    }));

    return refreshedSession.session.accessToken;
  }, [
    isCurrentAuthOperation,
    logger,
    oidcSessionStorageKey,
    readStoredOidcSession,
    refreshSession,
    restoreSessionSnapshot,
    verifySessionIdentity,
    handleError,
  ]);

  const getAccessToken = getAccessTokenSilently;

  const contextValue: AuthContextValue = {
    ...state,
    loginWithRedirect,
    logout,
    getAccessToken,
    getAccessTokenSilently,
  };

  return (
    <AuthContext.Provider value={contextValue}>{children}</AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);

  if (!context) {
    throw new Error("useAuth must be used within a GuardhouseProvider");
  }

  return context;
}
