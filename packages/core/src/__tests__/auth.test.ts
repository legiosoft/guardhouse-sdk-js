import {
  createLocationHeaderRedirect,
  generateAuthUrl as rawGenerateAuthUrl,
  isSilentAuthenticationError,
  OAuthStateManager,
  parseOAuthCallbackUrl,
  sanitizeAuthorizationUrlForHistory,
  sanitizeOAuthCallbackUrl,
  StateExpiredError,
  validateFormPostCsrfToken,
  validateFrontChannelLogoutRequest,
} from "../auth";

const generateAuthUrl = (options: unknown): string => {
  if (!options || typeof options !== "object") {
    return rawGenerateAuthUrl(options as never);
  }

  return rawGenerateAuthUrl({
    authorizationEndpoint: "/connect/authorize",
    ...(options as Record<string, unknown>),
  } as never);
};

describe("generateAuthUrl", () => {
  it("requires options", () => {
    expect(() => generateAuthUrl(undefined)).toThrow("options is required");
  });

  it("requires authority", () => {
    expect(() =>
      generateAuthUrl({
        authority: "",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
      }),
    ).toThrow("authority is required");
  });

  it("requires authorizationEndpoint", () => {
    expect(() =>
      rawGenerateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
      } as never),
    ).toThrow("authorizationEndpoint is required");
  });

  it("requires clientId", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
      }),
    ).toThrow("clientId is required");
  });

  it("requires redirectUri", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "",
        state: "state-value-123456",
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
      }),
    ).toThrow("state is required");
  });

  it("requires high-entropy state format", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        codeChallenge: "code-challenge",
        state: "short",
        nonce: "nonce-value",
        audience: "https://api.example.com",
      }),
    ).toThrow("state must be a high-entropy token");
  });

  it("rejects insecure plain codeChallengeMethod", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        codeChallenge: "code-challenge",
        codeChallengeMethod: "plain",
        nonce: "nonce-value",
        audience: "https://api.example.com",
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
        state: "state-value-123456",
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
        state: "state-value-123456",
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
      state: "good-state-123456",
      codeChallenge: "code-challenge",
      nonce: "nonce-value",
      audience: "https://api.example.com",
      extraParams: {
        client_id: "evil-client",
        state: "evil-state",
        id_token_hint: "evil-id-token",
        client_secret: "leak",
        code_verifier: "verifier",
        custom_param: "custom-value",
      },
    });

    const parsed = new URL(authUrl);

    expect(parsed.searchParams.get("client_id")).toBe("good-client");
    expect(parsed.searchParams.get("state")).toBe("good-state-123456");
    expect(parsed.searchParams.get("id_token_hint")).toBeNull();
    expect(parsed.searchParams.get("client_secret")).toBeNull();
    expect(parsed.searchParams.get("code_verifier")).toBeNull();
    expect(parsed.searchParams.get("custom_param")).toBe("custom-value");
  });

  it("ignores null extraParams values", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      codeChallenge: "code-challenge",
      nonce: "nonce-value",
      audience: "https://api.example.com",
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
        state: "state-value-123456",
        nonce: "nonce-value",
      }),
    ).toThrow("codeChallenge is required");
  });

  it("requires resource-specific audience for code flow", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        responseType: "code",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
      }),
    ).toThrow("audience or resource is required");
  });

  it("allows code flow without audience when explicitly enabled", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      responseType: "code",
      state: "state-value-123456",
      nonce: "nonce-value",
      codeChallenge: "code-challenge",
      allowAuthorizationWithoutAudience: true,
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("audience")).toBeNull();
  });

  it("preserves root redirect_uri without forcing a trailing slash", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "http://localhost:3000",
      responseType: "code",
      state: "state-value-123456",
      nonce: "nonce-value",
      codeChallenge: "code-challenge",
      audience: "api",
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("redirect_uri")).toBe(
      "http://localhost:3000",
    );
  });

  it("allows non-code response types without PKCE", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      responseType: "token",
      scope: "profile email",
      state: "state-value-123456",
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
      state: "state-value-123456",
      nonce: "nonce-value",
      audience: "https://api.example.com",
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
      state: "state-value-123456",
      nonce: "nonce-value",
      audience: "https://api.example.com",
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
      state: "state-value-123456",
      nonce: "nonce-value",
      audience: "https://api.example.com",
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
        state: "state-value-123456",
        nonce: "nonce-value",
        audience: "https://api.example.com",
      }),
    ).toThrow("Authority must use an http or https protocol.");
  });

  it("rejects internationalized authority hostnames to prevent homograph spoofing", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://xn--pple-43d.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        codeChallenge: "code-challenge",
        state: "state-value-123456",
        nonce: "nonce-value",
        audience: "https://api.example.com",
      }),
    ).toThrow("internationalized domain label");
  });

  it("allows custom redirect URI schemes for native apps", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "myapp://callback",
      state: "state-value-123456",
      nonce: "nonce-value",
      codeChallenge: "code-challenge",
      audience: "https://api.example.com",
    });

    expect(new URL(authUrl).searchParams.get("redirect_uri")).toBe(
      "myapp://callback",
    );
  });

  it("rejects non-loopback localhost-like IPv4 shortcuts", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "http://127.bad/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
      }),
    ).toThrow("redirectUri must use HTTPS unless it targets localhost");
  });

  it("blocks redirect-like extra params", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      nonce: "nonce-value",
      codeChallenge: "code-challenge",
      audience: "https://api.example.com",
      extraParams: {
        next: "https://evil.example",
        custom_param: "ok",
      },
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("next")).toBeNull();
    expect(parsed.searchParams.get("custom_param")).toBe("ok");
  });

  it("rejects invalid prompt combinations with none", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        prompt: "none login",
      }),
    ).toThrow('prompt value "none" must not be combined');
  });

  it("rejects maxAge when prompt includes none", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com/authorize",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        prompt: "none",
        maxAge: 60,
      }),
    ).toThrow("maxAge cannot be used with prompt='none'");
  });

  it("rejects unsupported prompt values", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        prompt: "login custom",
      }),
    ).toThrow("prompt contains unsupported values");
  });

  it("requires formPostCsrfToken for response_mode=form_post", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        responseMode: "form_post",
      }),
    ).toThrow("formPostCsrfToken is required");
  });

  it("includes form_post CSRF binding parameter", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      nonce: "nonce-value",
      codeChallenge: "code-challenge",
      audience: "https://api.example.com",
      responseMode: "form_post",
      formPostCsrfToken: "csrf-token-123",
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("response_mode")).toBe("form_post");
    expect(parsed.searchParams.get("guardhouse_form_post_csrf")).toBe(
      "csrf-token-123",
    );
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
          state: "state-value-123456",
          nonce: "nonce-value",
          audience: "https://api.example.com",
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

  it("validates and consumes state tokens once", () => {
    const manager = new OAuthStateManager();

    expect(() =>
      manager.validateAndConsumeState(
        "state-value-123456",
        "state-value-123456",
      ),
    ).not.toThrow();

    expect(() =>
      manager.validateAndConsumeState(
        "state-value-123456",
        "state-value-123456",
      ),
    ).toThrow("already used");
  });

  it("supports isolated state managers per instance", () => {
    const managerA = new OAuthStateManager();
    const managerB = new OAuthStateManager();

    expect(() =>
      managerA.validateAndConsumeState(
        "state-value-abcdef12",
        "state-value-abcdef12",
      ),
    ).not.toThrow();

    expect(() =>
      managerB.validateAndConsumeState(
        "state-value-abcdef12",
        "state-value-abcdef12",
      ),
    ).not.toThrow();
  });

  it("expires replay protection entries based on TTL", () => {
    const nowSpy = jest.spyOn(Date, "now");

    try {
      const manager = new OAuthStateManager({ stateTtlMs: 10 });

      nowSpy.mockReturnValue(1_000);
      manager.validateAndConsumeState(
        "state-value-ttl-123",
        "state-value-ttl-123",
      );

      nowSpy.mockReturnValue(1_005);
      expect(() =>
        manager.validateAndConsumeState(
          "state-value-ttl-123",
          "state-value-ttl-123",
        ),
      ).toThrow("already used");

      nowSpy.mockReturnValue(1_020);
      expect(() =>
        manager.validateAndConsumeState(
          "state-value-ttl-123",
          "state-value-ttl-123",
        ),
      ).not.toThrow();
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("expires state handles and throws StateExpiredError", () => {
    const nowSpy = jest.spyOn(Date, "now");

    try {
      const manager = new OAuthStateManager({ stateTtlMs: 10 });

      nowSpy.mockReturnValue(10_000);
      const handle = manager.stashExpectedState("state-value-ttl-456");

      nowSpy.mockReturnValue(10_020);
      expect(() =>
        manager.consumeStateBinding(handle, "state-value-ttl-456"),
      ).toThrow(StateExpiredError);
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("identifies silent authentication error codes", () => {
    expect(isSilentAuthenticationError("interaction_required")).toBe(true);
    expect(isSilentAuthenticationError("access_denied")).toBe(false);
  });

  it("parses OAuth callback values from query params", () => {
    const callback = parseOAuthCallbackUrl(
      "https://app.example.com/callback?code=abc&state=state123&iss=https%3A%2F%2Fauth.example.com&session_state=session-123&response=jarm.jwt&id_token=id.jwt&expires_in=3600",
    );

    expect(callback.code).toBe("abc");
    expect(callback.state).toBe("state123");
    expect(callback.iss).toBe("https://auth.example.com");
    expect(callback.sessionState).toBe("session-123");
    expect(callback.response).toBe("jarm.jwt");
    expect(callback.idToken).toBe("id.jwt");
    expect(callback.expiresIn).toBe(3600);
    expect(callback.params.code).toBe("abc");
  });

  it("parses OAuth callback values from fragment params", () => {
    const callback = parseOAuthCallbackUrl(
      "https://app.example.com/callback#code=abc&state=state123&id_token=id.jwt&expires_in=3600",
    );

    expect(callback.code).toBe("abc");
    expect(callback.state).toBe("state123");
    expect(callback.idToken).toBe("id.jwt");
    expect(callback.expiresIn).toBe(3600);
    expect(callback.params.code).toBe("abc");
  });

  it("parses standard callback fields case-insensitively", () => {
    const callback = parseOAuthCallbackUrl(
      "https://app.example.com/callback?CoDe=abc&StAtE=state123&Id_ToKeN=id.jwt&ExPiReS_In=3600&ErRoR_UrI=https%3A%2F%2Fdocs.example.com%2Foauth-errors",
    );

    expect(callback.code).toBe("abc");
    expect(callback.state).toBe("state123");
    expect(callback.idToken).toBe("id.jwt");
    expect(callback.expiresIn).toBe(3600);
    expect(callback.errorUri).toBe("https://docs.example.com/oauth-errors");
  });

  it("rejects callback params split between query and hash", () => {
    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?code=abc#state=state123",
      ),
    ).toThrow("both query and fragment");
  });

  it("rejects duplicate callback params to prevent HPP", () => {
    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?code=abc&code=def",
      ),
    ).toThrow("duplicate parameter values");
  });

  it("rejects unsafe fragment content", () => {
    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback#code=%3Cscript%3Ealert(1)%3C/script%3E",
      ),
    ).toThrow("unsafe content");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback#code=abc%0D%0Aset-cookie%3Aevil%3D1",
      ),
    ).toThrow("unsafe content");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback#code=vbscript:msgbox(1)",
      ),
    ).toThrow("unsafe content");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback#code=file:///etc/passwd",
      ),
    ).toThrow("unsafe content");
  });

  it("validates callback error_uri values as https URLs", () => {
    const callback = parseOAuthCallbackUrl(
      "https://app.example.com/callback#error=access_denied&error_uri=https%3A%2F%2Fdocs.example.com%2Foauth-errors",
    );

    expect(callback.errorUri).toBe("https://docs.example.com/oauth-errors");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=javascript:alert(1)",
      ),
    ).toThrow("unsafe error_uri");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=data:text/plain,boom",
      ),
    ).toThrow("unsafe error_uri");
  });

  it("normalizes and rejects unsafe callback error_uri values", () => {
    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=java%0ascript:alert(1)",
      ),
    ).toThrow("unsafe error_uri");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=java\\script:alert(1)",
      ),
    ).toThrow("unsafe error_uri");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=file:///etc/passwd",
      ),
    ).toThrow("unsafe error_uri");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=https%3A%2F%2F127.0.0.1%2Foauth-errors",
      ),
    ).toThrow("unsafe error_uri");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=https%3A%2F%2Flocalhost.%2Foauth-errors",
      ),
    ).toThrow("unsafe error_uri");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=https%3A%2F%2F%5B%3A%3A1%5D%2Foauth-errors",
      ),
    ).toThrow("unsafe error_uri");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=https%3A%2F%2F0x7f.0.0.1%2Foauth-errors",
      ),
    ).toThrow("unsafe error_uri");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=https%3A%2F%2F0177.0.0.1%2Foauth-errors",
      ),
    ).toThrow("unsafe error_uri");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?error=access_denied&error_uri=https%3A%2F%2F2130706433%2Foauth-errors",
      ),
    ).toThrow("unsafe error_uri");
  });

  it("requires expires_in to be a bounded positive integer", () => {
    expect(
      parseOAuthCallbackUrl(
        "https://app.example.com/callback#expires_in=2147483647",
      ).expiresIn,
    ).toBe(2147483647);

    expect(() =>
      parseOAuthCallbackUrl("https://app.example.com/callback#expires_in=0"),
    ).toThrow("invalid expires_in");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback#expires_in=2147483648",
      ),
    ).toThrow("invalid expires_in");
  });

  it("sanitizes callback URL to remove sensitive params", () => {
    const sanitized = sanitizeOAuthCallbackUrl(
      "https://app.example.com/callback?CoDe=abc&StAtE=state123&keep=yes#Id_Token=id.jwt&ExPiReS_In=3600&foo=bar",
    );

    const parsed = new URL(sanitized);
    expect(parsed.searchParams.get("CoDe")).toBeNull();
    expect(parsed.searchParams.get("StAtE")).toBeNull();
    expect(parsed.searchParams.get("keep")).toBe("yes");
    expect(parsed.hash).toBe("#foo=bar");
  });

  it("aggressively sanitizes error-only callback URLs", () => {
    const sanitized = sanitizeOAuthCallbackUrl(
      "https://user:pass@app.example.com/callback?error=access_denied&error_description=bad+request&keep=yes#foo=bar",
    );

    const parsed = new URL(sanitized);
    expect(parsed.search).toBe("");
    expect(parsed.hash).toBe("");
    expect(parsed.username).toBe("");
    expect(parsed.password).toBe("");
  });

  it("detects error-only callbacks case-insensitively", () => {
    const sanitized = sanitizeOAuthCallbackUrl(
      "https://user:pass@app.example.com/callback?ErRoR=access_denied&ErRoR_DeScRiPtIoN=bad+request&keep=yes#foo=bar",
    );

    const parsed = new URL(sanitized);
    expect(parsed.search).toBe("");
    expect(parsed.hash).toBe("");
    expect(parsed.username).toBe("");
    expect(parsed.password).toBe("");
  });

  it("does not treat id_token or state callbacks as error-only", () => {
    const withIdToken = sanitizeOAuthCallbackUrl(
      "https://user:pass@app.example.com/callback?error=access_denied&id_token=id.jwt&keep=yes#foo=bar",
    );
    const parsedWithIdToken = new URL(withIdToken);

    expect(parsedWithIdToken.searchParams.get("keep")).toBe("yes");
    expect(parsedWithIdToken.hash).toBe("#foo=bar");

    const withState = sanitizeOAuthCallbackUrl(
      "https://user:pass@app.example.com/callback?error=access_denied&state=state123&keep=yes#foo=bar",
    );
    const parsedWithState = new URL(withState);

    expect(parsedWithState.searchParams.get("keep")).toBe("yes");
    expect(parsedWithState.hash).toBe("#foo=bar");

    const withCodeCasing = sanitizeOAuthCallbackUrl(
      "https://user:pass@app.example.com/callback?ErRoR=access_denied&CoDe=abc&keep=yes#foo=bar",
    );
    const parsedWithCodeCasing = new URL(withCodeCasing);

    expect(parsedWithCodeCasing.searchParams.get("keep")).toBe("yes");
    expect(parsedWithCodeCasing.hash).toBe("#foo=bar");
  });

  it("sanitizes truthy callback hashes as URLSearchParams", () => {
    const sanitized = sanitizeOAuthCallbackUrl(
      "https://app.example.com/callback#id_token",
    );

    expect(new URL(sanitized).hash).toBe("");
  });

  it("sanitizes authorization URL to remove sensitive request params", () => {
    const authUrl =
      "https://user:pass@auth.example.com/connect/authorize?client_id=client&StAtE=s123&CoDe_ChAlLeNgE=abc&NoNcE=n1&Id_ToKeN_HiNt=hint&GuArDhOuSe_FoRm_PoSt_CsRf=csrf&scope=openid#fragment";

    const sanitized = sanitizeAuthorizationUrlForHistory(authUrl);
    const parsed = new URL(sanitized);

    expect(parsed.searchParams.get("StAtE")).toBeNull();
    expect(parsed.searchParams.get("CoDe_ChAlLeNgE")).toBeNull();
    expect(parsed.searchParams.get("NoNcE")).toBeNull();
    expect(parsed.searchParams.get("Id_ToKeN_HiNt")).toBeNull();
    expect(parsed.searchParams.get("GuArDhOuSe_FoRm_PoSt_CsRf")).toBeNull();
    expect(parsed.searchParams.get("scope")).toBe("openid");
    expect(parsed.username).toBe("");
    expect(parsed.password).toBe("");
    expect(parsed.hash).toBe("");
  });

  it("validates form_post CSRF token using timing-safe compare", () => {
    expect(() =>
      validateFormPostCsrfToken("csrf-token-1", "csrf-token-1"),
    ).not.toThrow();

    expect(() =>
      validateFormPostCsrfToken("csrf-token-1", "csrf-token-2"),
    ).toThrow("CSRF token validation failed");
  });

  it("supports multi-tab state binding handles", () => {
    const manager = new OAuthStateManager();
    const handle = manager.stashExpectedState("state-binding-123456");

    expect(() =>
      manager.consumeStateBinding(handle, "state-binding-123456"),
    ).not.toThrow();

    expect(() =>
      manager.consumeStateBinding(handle, "state-binding-123456"),
    ).toThrow("already been consumed");
  });

  it("validates front-channel logout issuer and sid", () => {
    const result = validateFrontChannelLogoutRequest(
      "https://app.example.com/logout-callback?iss=https%3A%2F%2Fauth.example.com&sid=session-123",
      {
        expectedIssuer: "https://auth.example.com",
        expectedSessionId: "session-123",
      },
    );

    expect(result.issuer).toBe("https://auth.example.com");
    expect(result.sessionId).toBe("session-123");
  });

  it("rejects invalid front-channel logout issuer", () => {
    expect(() =>
      validateFrontChannelLogoutRequest(
        "https://app.example.com/logout-callback?iss=https%3A%2F%2Fevil.example",
        {
          expectedIssuer: "https://auth.example.com",
        },
      ),
    ).toThrow("issuer validation failed");
  });

  it("rejects malformed front-channel logout request URLs gracefully", () => {
    expect(() =>
      validateFrontChannelLogoutRequest("http://%", {
        expectedIssuer: "https://auth.example.com",
      }),
    ).toThrow("Invalid logout request URL format");
  });

  it("normalizes and validates acr_values", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      nonce: "nonce-value",
      codeChallenge: "code-challenge",
      audience: "https://api.example.com",
      acrValues: ["urn:mace:incommon:iap:silver", "phrh"],
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("acr_values")).toBe(
      "urn:mace:incommon:iap:silver phrh",
    );
  });

  it("rejects unsafe ui_locales and login_hint values", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        uiLocales: ["en-US", "<script>"],
      }),
    ).toThrow("invalid locale");

    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        loginHint: 'bad@example.com" onfocus=alert(1)',
      }),
    ).toThrow("loginHint contains unsafe characters");

    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        loginHint: "user(name)",
      }),
    ).toThrow("loginHint contains unsafe characters");

    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        loginHint: "user\\name",
      }),
    ).toThrow("loginHint contains unsafe characters");
  });

  it("supports request_uri based authorization URLs", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      responseType: "code",
      scope: "profile email",
      requestUri: "urn:ietf:params:oauth:request_uri:abc123",
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("request_uri")).toBe(
      "urn:ietf:params:oauth:request_uri:abc123",
    );
    expect(parsed.searchParams.get("code_challenge")).toBeNull();
  });

  it("accepts secure request_uri URLs and rejects unsafe schemes", () => {
    const httpsAuthUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      responseType: "code",
      scope: "profile email",
      requestUri: "https://request.example.com/obj.jwt",
    });

    expect(new URL(httpsAuthUrl).searchParams.get("request_uri")).toBe(
      "https://request.example.com/obj.jwt",
    );

    const localhostAuthUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      responseType: "code",
      scope: "profile email",
      requestUri: "http://localhost:5173/request.jwt",
    });

    expect(new URL(localhostAuthUrl).searchParams.get("request_uri")).toBe(
      "http://localhost:5173/request.jwt",
    );

    const loopbackIPv4AuthUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      responseType: "code",
      scope: "profile email",
      requestUri: "http://127.0.0.1:5173/request.jwt",
    });

    expect(new URL(loopbackIPv4AuthUrl).searchParams.get("request_uri")).toBe(
      "http://127.0.0.1:5173/request.jwt",
    );

    const loopbackIPv6AuthUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      responseType: "code",
      scope: "profile email",
      requestUri: "http://[::1]:5173/request.jwt",
    });

    expect(new URL(loopbackIPv6AuthUrl).searchParams.get("request_uri")).toBe(
      "http://[::1]:5173/request.jwt",
    );

    const androidEmulatorAuthUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      responseType: "code",
      scope: "profile email",
      requestUri: "http://10.0.2.2:8080/request.jwt",
    });

    expect(
      new URL(androidEmulatorAuthUrl).searchParams.get("request_uri"),
    ).toBe("http://10.0.2.2:8080/request.jwt");

    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        responseType: "code",
        scope: "profile email",
        requestUri: "javascript:alert(1)",
      }),
    ).toThrow("requestUri must");

    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        responseType: "code",
        scope: "profile email",
        requestUri: "file:///tmp/request.jwt",
      }),
    ).toThrow("requestUri must");
  });

  it("rejects non-integer maxAge values", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        maxAge: 1.5,
      }),
    ).toThrow("maxAge must be a non-negative integer");
  });

  it("creates server-side redirect responses using Location header", () => {
    const redirect = createLocationHeaderRedirect(
      "https://app.example.com/callback",
    );

    expect(redirect.statusCode).toBe(302);
    expect(redirect.headers.Location).toBe("https://app.example.com/callback");
    expect(redirect.headers["Cache-Control"]).toBe("no-store");
    expect(redirect.headers.Pragma).toBe("no-cache");
    expect(redirect.headers.Expires).toBe("0");
  });

  it("enforces redirect allowlists for Location header redirects", () => {
    const redirect = createLocationHeaderRedirect(
      "https://app.example.com/callback",
      ["HTTPS://APP.EXAMPLE.COM:443/callback", "myapp://callback"],
    );

    expect(redirect.headers.Location).toBe("https://app.example.com/callback");

    expect(() =>
      createLocationHeaderRedirect("https://evil.example/callback", [
        "https://app.example.com/callback",
      ]),
    ).toThrow("not included in allowedUris");
  });

  it("encodes extraParams values to prevent parameter injection", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      nonce: "nonce-value",
      codeChallenge: "code-challenge",
      audience: "https://api.example.com",
      extraParams: {
        note: "safe&response_type=token",
      },
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("response_type")).toBe("code");
    expect(parsed.searchParams.get("note")).toBe("safe&response_type=token");
  });

  it("blocks prototype-polluting keys in extraParams", () => {
    const extraParams = Object.create(null) as Record<
      string,
      string | number | null | undefined
    >;
    extraParams["__proto__"] = "polluted";
    extraParams["safe"] = "ok";

    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      nonce: "nonce-value",
      codeChallenge: "code-challenge",
      audience: "https://api.example.com",
      extraParams,
    });

    const parsed = new URL(authUrl);
    expect(parsed.searchParams.get("__proto__")).toBeNull();
    expect(parsed.searchParams.get("safe")).toBe("ok");
  });

  it("rejects unsafe callback parameter keys", () => {
    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?code=abc&state=state123&__proto__=x",
      ),
    ).toThrow("unsafe parameter key");

    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?code=abc&state=state123&__PrOtO__=x",
      ),
    ).toThrow("unsafe parameter key");
  });

  it("normalizes callback params object keys to lowercase", () => {
    const callback = parseOAuthCallbackUrl(
      "https://app.example.com/callback?CoDe=abc&StAtE=state123&Custom_Key=value",
    );

    expect(callback.params.code).toBe("abc");
    expect(callback.params.state).toBe("state123");
    expect(callback.params.custom_key).toBe("value");
    expect(callback.params.CoDe).toBeUndefined();
  });

  it("requires explicit consent for offline_access scope", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        scope: "openid offline_access",
      }),
    ).toThrow("allowOfflineAccessScope=true");

    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        scope: "openid offline_access",
        allowOfflineAccessScope: true,
      }),
    ).not.toThrow();
  });

  it("validates and serializes claims request parameter", () => {
    const authUrl = generateAuthUrl({
      authority: "https://auth.example.com",
      clientId: "client-id",
      redirectUri: "https://app.example.com/callback",
      state: "state-value-123456",
      nonce: "nonce-value",
      codeChallenge: "code-challenge",
      audience: "https://api.example.com",
      claims: {
        id_token: {
          acr: { essential: true },
        },
      },
    });

    const parsed = new URL(authUrl);
    const claims = parsed.searchParams.get("claims");
    expect(claims).toBeTruthy();
    expect(claims?.includes('"id_token"')).toBe(true);

    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "https://app.example.com/callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
        claims: {
          "<script>": true,
        },
      }),
    ).toThrow("claims key is invalid");
  });
});
