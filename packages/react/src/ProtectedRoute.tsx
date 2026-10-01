import { useCallback, useEffect, useRef, useState } from "react";
import type { ComponentType } from "react";
import { isTransientAuthError } from "@guardhouse/core";
import { useAuth } from "./context";
import type {
  ProtectedRouteProps,
  WithAuthenticationRequiredOptions,
} from "./types";
import { getCurrentReturnTo, normalizeReturnTo } from "./utils";

export function ProtectedRoute<P extends object>({
  component: Component,
  componentProps,
  children,
  returnTo,
  onRedirecting,
  onRedirectError,
}: ProtectedRouteProps<P>) {
  const {
    isAuthenticated,
    isLoading,
    loginWithRedirect,
    getAccessTokenSilently,
    error,
  } = useAuth();
  const hasTriggeredLogin = useRef(false);
  const retryLoginRequested = useRef(false);
  const [redirectError, setRedirectError] = useState<Error | null>(null);
  const [retrySequence, setRetrySequence] = useState(0);
  const restorationError =
    !redirectError && isTransientAuthError(error) ? error : null;

  const retry = useCallback(() => {
    if (restorationError) {
      void getAccessTokenSilently().catch((error: unknown) => {
        setRedirectError(
          error instanceof Error
            ? error
            : new Error("Session restoration failed"),
        );
      });
      return;
    }
    hasTriggeredLogin.current = false;
    retryLoginRequested.current = true;
    setRedirectError(null);
    setRetrySequence((value) => value + 1);
  }, [getAccessTokenSilently, restorationError]);

  useEffect(() => {
    if (
      isLoading ||
      isAuthenticated ||
      (error && !retryLoginRequested.current) ||
      redirectError ||
      hasTriggeredLogin.current
    ) {
      return;
    }

    hasTriggeredLogin.current = true;
    retryLoginRequested.current = false;
    let loginPromise: Promise<void>;
    try {
      const safeReturnTo = normalizeReturnTo(returnTo ?? getCurrentReturnTo());
      loginPromise = loginWithRedirect({
        appState: { returnTo: safeReturnTo },
      });
    } catch (error) {
      hasTriggeredLogin.current = false;
      setRedirectError(
        error instanceof Error ? error : new Error("Login redirect failed"),
      );
      return;
    }

    void loginPromise.catch((error: unknown) => {
      hasTriggeredLogin.current = false;
      setRedirectError(
        error instanceof Error ? error : new Error("Login redirect failed"),
      );
    });
  }, [
    isAuthenticated,
    isLoading,
    loginWithRedirect,
    error,
    redirectError,
    restorationError,
    retrySequence,
    returnTo,
  ]);

  if (isLoading) {
    return <>{onRedirecting ? onRedirecting() : <div>Loading...</div>}</>;
  }

  if (!isAuthenticated) {
    const authError = redirectError ?? error;
    if (authError) {
      return (
        <>
          {onRedirectError ? (
            onRedirectError({ error: authError, retry })
          ) : (
            <div role="alert">
              <p>
                {restorationError
                  ? "Unable to restore your session."
                  : "Unable to start sign in."}
              </p>
              <button type="button" onClick={retry}>
                Retry
              </button>
            </div>
          )}
        </>
      );
    }

    return <>{onRedirecting ? onRedirecting() : <div>Redirecting...</div>}</>;
  }

  if (Component) {
    return <Component {...componentProps} />;
  }

  return <>{children}</>;
}

export function withAuthenticationRequired<P extends object>(
  Component: ComponentType<P>,
  options?: WithAuthenticationRequiredOptions,
) {
  return function WithAuthenticationRequired(props: P) {
    return (
      <ProtectedRoute
        component={Component}
        componentProps={props}
        returnTo={options?.returnTo}
        onRedirecting={options?.onRedirecting}
        onRedirectError={options?.onRedirectError}
      />
    );
  };
}
