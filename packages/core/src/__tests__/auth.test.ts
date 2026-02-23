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
      }),
    ).toThrow("authority is required");
  });

  it("requires clientId", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "",
        redirectUri: "https://app.example.com/callback",
      }),
    ).toThrow("clientId is required");
  });

  it("requires redirectUri", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "",
      }),
    ).toThrow("redirectUri is required");
  });

  it("warns when state is missing", () => {
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    const debugSpy = jest.spyOn(console, "debug").mockImplementation(() => {});

    try {
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        codeChallenge: "code-challenge",
        debug: true,
      });

      expect(warnSpy).toHaveBeenCalled();
      expect(
        warnSpy.mock.calls.some((call) =>
          call.some(
            (arg) =>
              typeof arg === "string" &&
              arg.includes("OAuth state parameter is missing"),
          ),
        ),
      ).toBe(true);
    } finally {
      warnSpy.mockRestore();
      debugSpy.mockRestore();
    }
  });

  it("warns when codeChallengeMethod is plain", () => {
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    const debugSpy = jest.spyOn(console, "debug").mockImplementation(() => {});

    try {
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value",
        codeChallenge: "code-challenge",
        codeChallengeMethod: "plain",
        debug: true,
      });

      expect(
        warnSpy.mock.calls.some((call) =>
          call.some(
            (arg) =>
              typeof arg === "string" &&
              arg.includes("codeChallengeMethod 'plain' is insecure"),
          ),
        ),
      ).toBe(true);
    } finally {
      warnSpy.mockRestore();
      debugSpy.mockRestore();
    }
  });

  it("filters reserved extraParams keys", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "good-client",
      redirectUri: "https://app.example.com/callback",
      state: "good-state",
      codeChallenge: "code-challenge",
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
      codeChallenge: "code-challenge",
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
      }),
    ).toThrow("codeChallenge is required");
  });

  it("allows non-code response types without PKCE", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      responseType: "token",
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
    });

    const parsed = new URL(authUrl);

    expect(parsed.origin).toBe("https://idp.example.com");
    expect(parsed.pathname).toBe("/oauth2/v2.0/authorize");
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
