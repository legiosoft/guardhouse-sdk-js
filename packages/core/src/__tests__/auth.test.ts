import { generateAuthUrl } from "../auth";

describe("generateAuthUrl", () => {
  it("requires options", () => {
    expect(() => generateAuthUrl(undefined as any)).toThrow(
      "options is required",
    );
  });

  it("requires authority", () => {
    expect(() =>
      generateAuthUrl({
        authority: "",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value",
      }),
    ).toThrow("authority is required");
  });

  it("requires clientId", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "",
        redirectUri: "https://app.example.com/callback",
        state: "state-value",
      }),
    ).toThrow("clientId is required");
  });

  it("requires redirectUri", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "",
        state: "state-value",
      }),
    ).toThrow("redirectUri is required");
  });

  it("requires state for CSRF protection", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        codeChallenge: "code-challenge",
        nonce: "nonce-value",
      } as any),
    ).toThrow("state is required");
  });

  it("rejects insecure plain codeChallengeMethod", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value",
        codeChallenge: "code-challenge",
        codeChallengeMethod: "plain" as any,
        nonce: "nonce-value",
      }),
    ).toThrow("codeChallengeMethod must be 'S256'");
  });

  it("warns when implicit flow is requested", () => {
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    const debugSpy = jest.spyOn(console, "debug").mockImplementation(() => {});

    try {
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        responseType: "token",
        scope: "profile email",
        state: "state-value",
        debug: true,
      });

      expect(
        warnSpy.mock.calls.some((call) =>
          call.some(
            (arg) =>
              typeof arg === "string" &&
              arg.includes("Implicit Flow (response_type=token) is deprecated"),
          ),
        ),
      ).toBe(true);
    } finally {
      warnSpy.mockRestore();
      debugSpy.mockRestore();
    }
  });

  it("requires nonce when requesting openid scope", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value",
        codeChallenge: "code-challenge",
        scope: "openid profile",
      }),
    ).toThrow("nonce is required");
  });

  it("filters reserved extraParams keys", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "good-client",
      redirectUri: "https://app.example.com/callback",
      state: "good-state",
      codeChallenge: "code-challenge",
      nonce: "nonce-value",
      extraParams: {
        client_id: "evil-client",
        state: "evil-state",
        custom_param: "custom-value",
      },
    });

    const parsed = new URL(authUrl);

    expect(parsed.searchParams.get("client_id")).toBe("good-client");
    expect(parsed.searchParams.get("state")).toBe("good-state");
    expect(parsed.searchParams.get("custom_param")).toBe("custom-value");
  });

  it("ignores null extraParams values", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value",
      codeChallenge: "code-challenge",
      nonce: "nonce-value",
      extraParams: {
        nullable: null,
        valid: "yes",
      },
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("nullable")).toBeNull();
    expect(parsed.searchParams.get("valid")).toBe("yes");
  });

  it("requires PKCE for authorization code responses", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value",
        nonce: "nonce-value",
      }),
    ).toThrow("codeChallenge is required");
  });

  it("allows non-code response types without PKCE", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      responseType: "token",
      scope: "profile email",
      state: "state-value",
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("response_type")).toBe("token");
    expect(parsed.searchParams.get("code_challenge")).toBeNull();
  });

  it("preserves authority query params", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com/tenant?tenant_hint=foo",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      codeChallenge: "code-challenge",
      state: "state-value",
      nonce: "nonce-value",
    });

    const parsed = new URL(authUrl);

    expect(parsed.pathname).toBe("/tenant/connect/authorize");
    expect(parsed.searchParams.get("tenant_hint")).toBe("foo");
  });

  it("uses authorizationEndpoint when provided", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      authorizationEndpoint: "https://idp.example.com/oauth2/v2.0/authorize",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      codeChallenge: "code-challenge",
      state: "state-value",
      nonce: "nonce-value",
    });

    const parsed = new URL(authUrl);

    expect(parsed.origin).toBe("https://idp.example.com");
    expect(parsed.pathname).toBe("/oauth2/v2.0/authorize");
  });

  it("merges relative authorizationEndpoint onto authority path", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com/tenant",
      authorizationEndpoint: "/oauth2/authorize",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      codeChallenge: "code-challenge",
      state: "state-value",
      nonce: "nonce-value",
    });

    const parsed = new URL(authUrl);
    expect(parsed.origin).toBe("https://auth.example.com");
    expect(parsed.pathname).toBe("/tenant/oauth2/authorize");
  });

  it("rejects non-http protocols", () => {
    expect(() =>
      generateAuthUrl({
        authority: "javascript:alert('xss')",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        codeChallenge: "code-challenge",
        state: "state-value",
        nonce: "nonce-value",
      }),
    ).toThrow("Authority must use an http or https protocol.");
  });

  it("preserves original URL error as cause", () => {
    const originalDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      "URL",
    );

    class BrokenURL {
      constructor() {
        throw new TypeError("failed to construct 'URL'");
      }
    }

    Object.defineProperty(globalThis, "URL", {
      value: BrokenURL,
      configurable: true,
      writable: true,
    });

    try {
      expect.assertions(2);

      try {
        generateAuthUrl({
          authority: "https://auth.example.com",
          clientId: "client-id",
          redirectUri: "https://app.example.com/callback",
          codeChallenge: "code-challenge",
          state: "state-value",
          nonce: "nonce-value",
        });
      } catch (error) {
        const authError = error as Error & { cause?: unknown };

        expect(authError.message).toContain("Global URL API is unavailable");
        expect(authError.cause).toBeInstanceOf(TypeError);
      }
    } finally {
      if (originalDescriptor) {
        Object.defineProperty(globalThis, "URL", originalDescriptor);
      }
    }
  });
});
