import {
  consumeStateBinding,
  createLocationHeaderRedirect,
  generateAuthUrl,
  isSilentAuthenticationError,
  parseOAuthCallbackUrl,
  sanitizeAuthorizationUrlForHistory,
  sanitizeOAuthCallbackUrl,
  stashExpectedState,
  validateFormPostCsrfToken,
  validateFrontChannelLogoutRequest,
  validateAndConsumeState,
} from "../auth";

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
        state: "state-value-123456",
      }),
    ).toThrow("authority is required");
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
      } as any),
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
        codeChallengeMethod: "plain" as any,
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
        custom_param: "custom-value",
      },
    });

    const parsed = new URL(authUrl);

    expect(parsed.searchParams.get("client_id")).toBe("good-client");
    expect(parsed.searchParams.get("state")).toBe("good-state-123456");
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

  it("rejects custom redirect URI schemes", () => {
    expect(() =>
      generateAuthUrl({
        authority: "https://auth.example.com",
        clientId: "client-id",
        redirectUri: "myapp://callback",
        state: "state-value-123456",
        nonce: "nonce-value",
        codeChallenge: "code-challenge",
        audience: "https://api.example.com",
      }),
    ).toThrow("custom URI schemes are not allowed");
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
    expect(() =>
      validateAndConsumeState("state-value-123456", "state-value-123456"),
    ).not.toThrow();

    expect(() =>
      validateAndConsumeState("state-value-123456", "state-value-123456"),
    ).toThrow("already used");
  });

  it("identifies silent authentication error codes", () => {
    expect(isSilentAuthenticationError("interaction_required")).toBe(true);
    expect(isSilentAuthenticationError("access_denied")).toBe(false);
  });

  it("parses OAuth callback values from query and hash", () => {
    const callback = parseOAuthCallbackUrl(
      "https://app.example.com/callback?code=abc&state=state123#id_token=id.jwt&expires_in=3600",
    );

    expect(callback.code).toBe("abc");
    expect(callback.state).toBe("state123");
    expect(callback.idToken).toBe("id.jwt");
    expect(callback.expiresIn).toBe(3600);
    expect(callback.params.code).toBe("abc");
  });

  it("rejects duplicate callback params to prevent HPP", () => {
    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback?code=abc#code=def",
      ),
    ).toThrow("duplicate parameter values");
  });

  it("rejects unsafe fragment content", () => {
    expect(() =>
      parseOAuthCallbackUrl(
        "https://app.example.com/callback#code=%3Cscript%3Ealert(1)%3C/script%3E",
      ),
    ).toThrow("unsafe content");
  });

  it("sanitizes callback URL to remove sensitive params", () => {
    const sanitized = sanitizeOAuthCallbackUrl(
      "https://app.example.com/callback?code=abc&state=state123&keep=yes#id_token=id.jwt&foo=bar",
    );

    const parsed = new URL(sanitized);
    expect(parsed.searchParams.get("code")).toBeNull();
    expect(parsed.searchParams.get("state")).toBeNull();
    expect(parsed.searchParams.get("keep")).toBe("yes");
    expect(parsed.hash).toBe("#foo=bar");
  });

  it("sanitizes authorization URL to remove sensitive request params", () => {
    const authUrl =
      "https://auth.example.com/connect/authorize?client_id=client&state=s123&code_challenge=abc&nonce=n1&scope=openid";

    const sanitized = sanitizeAuthorizationUrlForHistory(authUrl);
    const parsed = new URL(sanitized);

    expect(parsed.searchParams.get("state")).toBeNull();
    expect(parsed.searchParams.get("code_challenge")).toBeNull();
    expect(parsed.searchParams.get("nonce")).toBeNull();
    expect(parsed.searchParams.get("scope")).toBe("openid");
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
    const handle = stashExpectedState("state-binding-123456");

    expect(() =>
      consumeStateBinding(handle, "state-binding-123456"),
    ).not.toThrow();

    expect(() => consumeStateBinding(handle, "state-binding-123456")).toThrow(
      "already been consumed",
    );
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
        } as any,
      }),
    ).toThrow("claims key is invalid");
  });
});
