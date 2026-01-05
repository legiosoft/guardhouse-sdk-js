import React from "react";
import { useAuth } from "./context";
import type { ProtectedRouteProps } from "./types";

export function ProtectedRoute({
  component: Component,
  children,
  onRedirecting,
  ...rest
}: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, loginWithRedirect } = useAuth();

  React.useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      loginWithRedirect();
    }
  }, [isAuthenticated, isLoading, loginWithRedirect]);

  if (isLoading) {
    return <>{onRedirecting ? onRedirecting() : <div>Loading...</div>}</>;
  }

  if (!isAuthenticated) {
    return <>{onRedirecting ? onRedirecting() : <div>Redirecting...</div>}</>;
  }

  if (Component) {
    return <Component {...rest} />;
  }

  return <>{children}</>;
}

export function withAuthenticationRequired<P extends object>(
  Component: React.ComponentType<P>,
  options?: {
    returnTo?: string;
    onRedirecting?: () => React.ReactNode;
  },
) {
  return function WithAuthenticationRequired(props: P) {
    const { isAuthenticated, isLoading, loginWithRedirect } = useAuth();

    React.useEffect(() => {
      if (!isLoading && !isAuthenticated) {
        loginWithRedirect({ appState: { returnTo: options?.returnTo } });
      }
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
