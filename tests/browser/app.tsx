import React, { StrictMode, useState } from "react";
import { createRoot } from "react-dom/client";
import { GuardhouseProvider, ProtectedRoute, useAuth } from "@guardhouse/react";

const settings = window.__settings;
// The custom callback below uses history.replaceState; the default callback
// replaces the document, which tests must wait for before touching storage.
const callbackDocument =
  !settings.unstableConfig && new URL(location.href).searchParams.has("code");
const clientId = location.pathname.startsWith("/admin") ? "admin" : "app";
const redirectUri = `${location.origin}/${clientId}/`;
const config = {
  authority: "https://issuer.test/",
  clientId,
  redirectUri,
  logoutRedirectUri: redirectUri,
  allowedPostLogoutRedirectUris: [redirectUri],
  scope: "openid profile email roles offline_access",
  audiencePolicy: "oidc-optional" as const,
  allowOfflineAccessScope: true,
  ...settings.config,
  ...settings.clients?.find((client) =>
    location.pathname.startsWith(new URL(client.redirectUri).pathname),
  ),
};

function Controls() {
  const auth = useAuth();
  const [result, setResult] = useState("");
  async function run(operation) {
    try {
      const value = await operation();
      setResult(value === null ? "no token" : "done");
    } catch (error) {
      setResult(`failed: ${error.message}`);
    }
  }
  return (
    <>
      <div data-testid="document-kind">
        {callbackDocument ? "callback" : "application"}
      </div>
      {settings.live && (
        <p>
          Guardhouse SDK candidate verification — local test page, real test
          identity server
        </p>
      )}
      <div data-testid="status">
        {auth.isLoading
          ? "loading"
          : auth.isAuthenticated
            ? "authenticated"
            : "anonymous"}
      </div>
      <div data-testid="subject">{auth.user?.sub ?? ""}</div>
      <div data-testid="error">{auth.error?.message ?? ""}</div>
      <div data-testid="result">{result}</div>
      <button onClick={() => void run(() => auth.loginWithRedirect())}>
        Login
      </button>
      <button onClick={() => void run(() => auth.logout())}>Logout</button>
      <button onClick={() => void run(() => auth.getAccessTokenSilently())}>
        Token
      </button>
      <button
        onClick={() =>
          void run(() =>
            Promise.all(
              Array.from({ length: 6 }, () => auth.getAccessTokenSilently()),
            ).then((tokens) =>
              tokens.every(
                (token) => typeof token === "string" && token.length > 0,
              )
                ? true
                : null,
            ),
          )
        }
      >
        Concurrent tokens
      </button>
      {settings.protected && (
        <ProtectedRoute>
          <div data-testid="private">Private content</div>
        </ProtectedRoute>
      )}
    </>
  );
}

function Application() {
  const [, update] = useState(0);
  const providerConfig = settings.unstableConfig
    ? {
        ...config,
        allowedPostLogoutRedirectUris: [redirectUri],
        onRedirectCallback: () => {
          history.replaceState(null, "", redirectUri);
        },
      }
    : config;
  return (
    <>
      <button onClick={() => update((value) => value + 1)}>
        Parent render
      </button>
      <GuardhouseProvider config={providerConfig}>
        <Controls />
      </GuardhouseProvider>
    </>
  );
}

createRoot(document.getElementById("root")!).render(
  settings.strict ? (
    <StrictMode>
      <Application />
    </StrictMode>
  ) : (
    <Application />
  ),
);
