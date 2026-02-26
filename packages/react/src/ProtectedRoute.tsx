import { useEffect, useRef } from "react";
import type { ComponentType, ReactNode } from "react";
import { useAuth } from "./context";
import type { ProtectedRouteProps } from "./types";

export function ProtectedRoute<P extends object>({
  component: Component,
  children,
  onRedirecting,
  ...rest
}: ProtectedRouteProps<P>) {
  const { isAuthenticated, isLoading, loginWithRedirect } = useAuth();
  const hasTriggeredLogin = useRef(false);

  useEffect(() => {
    if (isLoading || isAuthenticated || hasTriggeredLogin.current) {
      return;
    }

    hasTriggeredLogin.current = true;
    void loginWithRedirect();
  }, [isAuthenticated, isLoading, loginWithRedirect]);

  if (isLoading) {
    return <>{onRedirecting ? onRedirecting() : <div>Loading...</div>}</>;
  }

  if (!isAuthenticated) {
    return <>{onRedirecting ? onRedirecting() : <div>Redirecting...</div>}</>;
  }

  if (Component) {
    return <Component {...(rest as P)} />;
  }

  return <>{children}</>;
}

export function withAuthenticationRequired<P extends object>(
  Component: ComponentType<P>,
  options?: {
    returnTo?: string;
    onRedirecting?: () => ReactNode;
  },
) {
  return function WithAuthenticationRequired(props: P) {
    const { isAuthenticated, isLoading, loginWithRedirect } = useAuth();
    const hasTriggeredLogin = useRef(false);

    useEffect(() => {
      if (isLoading || isAuthenticated || hasTriggeredLogin.current) {
        return;
      }

      hasTriggeredLogin.current = true;
      void loginWithRedirect({ appState: { returnTo: options?.returnTo } });
    }, [isAuthenticated, isLoading, loginWithRedirect, options?.returnTo]);

    if (isLoading) {
      return (
        <>
          {options?.onRedirecting ? (
            options.onRedirecting()
          ) : (
            <div>Loading...</div>
          )}
        </>
      );
    }

    if (!isAuthenticated) {
      return (
        <>
          {options?.onRedirecting ? (
            options.onRedirecting()
          ) : (
            <div>Redirecting...</div>
          )}
        </>
      );
    }

    return <Component {...props} />;
  };
}
