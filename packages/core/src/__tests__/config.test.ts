import { buildUrl, validateConfig } from "../config";

describe("config hardening", () => {
  it("validates absolute endpoint URLs when provided", () => {
    expect(() =>
      validateConfig({
        authority: "https://auth.example.com",
        clientId: "client-id",
        tokenEndpoint: "https://auth.example.com/connect/token",
        userInfoEndpoint: "https://auth.example.com/connect/userinfo",
        introspectionEndpoint: "https://auth.example.com/connect/introspect",
        revocationEndpoint: "https://auth.example.com/connect/revocation",
      }),
    ).not.toThrow();

    expect(() =>
      validateConfig({
        authority: "https://auth.example.com",
        clientId: "client-id",
        tokenEndpoint: "javascript:alert(1)",
      }),
    ).toThrow("tokenEndpoint");
  });

  it("validates logout redirect allowlist entries", () => {
    expect(() =>
      validateConfig({
        authority: "https://auth.example.com",
        clientId: "client-id",
        allowedPostLogoutRedirectUris: ["https://app.example.com/logout"],
      }),
    ).not.toThrow();

    expect(() =>
      validateConfig({
        authority: "https://auth.example.com",
        clientId: "client-id",
        allowedPostLogoutRedirectUris: ["javascript:alert(1)"],
      }),
    ).toThrow("allowedPostLogoutRedirectUris");
  });

  it("rejects directory traversal and repeated slash paths", () => {
    const config = {
      authority: "https://auth.example.com",
      clientId: "client-id",
    };

    expect(() => buildUrl(config, "../connect/token")).toThrow(
      "directory traversal",
    );
    expect(() => buildUrl(config, "/connect//token")).toThrow("repeated slash");
  });
});
