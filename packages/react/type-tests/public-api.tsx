import type { ComponentType } from "react";
import {
  GuardhouseProvider,
  ProtectedRoute,
  type AuthContextValue,
  type GuardhouseConfig,
  type GuardhouseProviderProps,
  type LoginOptions,
  type StorageAdapter,
} from "@guardhouse/react";

const config: GuardhouseConfig = {
  authority: "https://auth.example.com",
  clientId: "browser-client",
  redirectUri: "https://app.example.com/callback",
  audiencePolicy: "oidc-optional",
  resource: ["https://api.example.com", "https://files.example.com"],
  maxAgeSeconds: 300,
  requiredAcrValues: ["urn:guardhouse:acr:passkey"],
  requiredAmrValues: ["passkey"],
};

const invalidConfig: GuardhouseConfig = {
  authority: "https://auth.example.com",
  clientId: "browser-client",
  redirectUri: "https://app.example.com/callback",
  // @ts-expect-error React v2 supports authorization code flow only.
  responseType: "id_token token",
};

const loginOptions: LoginOptions = {
  resource: ["https://api.example.com"],
  maxAgeSeconds: 120,
  appState: { returnTo: "/orders?state=open#current" },
};

const storageAdapter: StorageAdapter = {
  async getItem() {
    return null;
  },
  async setItem() {},
  async removeItem() {},
  compareAndSetItem() {
    return true;
  },
  compareAndRemoveItem() {
    return true;
  },
};

interface PageProps {
  orderId: string;
}

const Page: ComponentType<PageProps> = ({ orderId }) => <p>{orderId}</p>;

const providerProps: GuardhouseProviderProps = {
  config,
  children: <p>Application</p>,
};

const provider = <GuardhouseProvider {...providerProps} />;
const childGuard = (
  <ProtectedRoute>
    <Page orderId="one" />
  </ProtectedRoute>
);
const componentGuard = (
  <ProtectedRoute component={Page} componentProps={{ orderId: "two" }} />
);

// @ts-expect-error Component mode requires matching componentProps.
const invalidGuard = <ProtectedRoute component={Page} />;

declare const context: AuthContextValue;
void context.loginWithRedirect(loginOptions);
void storageAdapter;
void invalidConfig;
void provider;
void childGuard;
void componentGuard;
void invalidGuard;
