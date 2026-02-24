import { GuardhouseClient } from "../client";
import { GuardhouseError } from "../config";

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
    },
  });
}

function getCallHeaders(fetchMock: any, callIndex: number): Headers {
  const requestInit = fetchMock.mock.calls[callIndex]?.[1] as
    | RequestInit
    | undefined;
  return new Headers(requestInit?.headers);
}

const validCodeVerifier = "a".repeat(43);

describe("GuardhouseClient", () => {
  const originalFetchDescriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    "fetch",
  );
  const originalWindowDescriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    "window",
  );
  const originalNavigatorDescriptor = Object.getOwnPropertyDescriptor(
    globalThis,
    "navigator",
  );

  afterEach(() => {
    jest.restoreAllMocks();

    if (originalFetchDescriptor) {
      Object.defineProperty(globalThis, "fetch", originalFetchDescriptor);
    }

    if (originalWindowDescriptor) {
      Object.defineProperty(globalThis, "window", originalWindowDescriptor);
    } else {
      delete (globalThis as Record<string, unknown>)["window"];
    }

    if (originalNavigatorDescriptor) {
      Object.defineProperty(
        globalThis,
        "navigator",
        originalNavigatorDescriptor,
      );
    } else {
      delete (globalThis as Record<string, unknown>)["navigator"];
    }
  });

  it("joins base URL and endpoint with exactly one slash", async () => {
    const fetchMock = jest
      .fn()
      .mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });

    await client.fetch("connect/userinfo");
    await client.fetch("/connect/userinfo");

    expect(fetchMock).toHaveBeenNthCalledWith(
      1,
      "https://auth.example.com/connect/userinfo",
      expect.any(Object),
    );
    expect(fetchMock).toHaveBeenNthCalledWith(
      2,
      "https://auth.example.com/connect/userinfo",
      expect.any(Object),
    );
  });

  it("rejects insecure non-localhost HTTP authorities", () => {
    expect(
      () =>
        new GuardhouseClient({
          authority: "http://auth.example.com",
          clientId: "client-id",
        }),
    ).toThrow(GuardhouseError);

    try {
      new GuardhouseClient({
        authority: "http://auth.example.com",
        clientId: "client-id",
      });
    } catch (error) {
      const clientError = error as GuardhouseError;
      expect(clientError.code).toBe("INSECURE_AUTHORITY");
    }
  });

  it("rejects client_secret usage in browser-like runtimes", () => {
    Object.defineProperty(globalThis, "window", {
      value: {},
      configurable: true,
      writable: true,
    });
    Object.defineProperty(globalThis, "navigator", {
      value: { product: "Gecko" },
      configurable: true,
      writable: true,
    });

    expect(
      () =>
        new GuardhouseClient({
          authority: "https://auth.example.com",
          clientId: "client-id",
          clientSecret: "client-secret",
        }),
    ).toThrow(GuardhouseError);

    try {
      new GuardhouseClient({
        authority: "https://auth.example.com",
        clientId: "client-id",
        clientSecret: "client-secret",
      });
    } catch (error) {
      const clientError = error as GuardhouseError;
      expect(clientError.code).toBe("INSECURE_CLIENT_SECRET_USAGE");
    }
  });

  it("allows loopback HTTP authorities for development", () => {
    expect(
      () =>
        new GuardhouseClient({
          authority: "http://localhost:3000",
          clientId: "client-id",
        }),
    ).not.toThrow();
    expect(
      () =>
        new GuardhouseClient({
          authority: "http://127.0.0.1:8080",
          clientId: "client-id",
        }),
    ).not.toThrow();
    expect(
      () =>
        new GuardhouseClient({
          authority: "http://10.0.2.2:3000",
          clientId: "client-id",
        }),
    ).not.toThrow();
  });

  it("rejects private-network HTTP authorities that are not loopback", () => {
    expect(
      () =>
        new GuardhouseClient({
          authority: "http://192.168.1.23:3000",
          clientId: "client-id",
        }),
    ).toThrow(GuardhouseError);
  });

  it("blocks absolute endpoints outside configured authority", async () => {
    const fetchMock = jest
      .fn()
      .mockImplementation(() => Promise.resolve(jsonResponse({ ok: true })));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      clientSecret: "client-secret",
    });

    await expect(
      client.fetch("https://evil.example.com/connect/userinfo"),
    ).rejects.toBeInstanceOf(GuardhouseError);

    await expect(
      client.fetch("https://evil.example.com/connect/userinfo"),
    ).rejects.toMatchObject({
      code: "UNSAFE_ENDPOINT_URL",
    });

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("uses configurable endpoints and authenticates confidential-client calls", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "access",
          token_type: "Bearer",
          expires_in: 3600,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "access-2",
          token_type: "Bearer",
          expires_in: 3600,
        }),
      )
      .mockResolvedValueOnce(jsonResponse({ sub: "user-1" }))
      .mockResolvedValueOnce(jsonResponse({ active: true }))
      .mockResolvedValueOnce(jsonResponse({}));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      clientSecret: "client-secret",
      tokenEndpoint: "oauth/token",
      userInfoEndpoint: "/oidc/userinfo",
      introspectionEndpoint: "https://auth.example.com/oauth2/introspect",
      revocationEndpoint: "oauth/revoke",
    });

    await client.exchangeCodeForTokens(
      "code",
      validCodeVerifier,
      "https://app.example.com/callback",
    );
    await client.refreshToken("refresh-token");
    await client.getUserInfo("access-token");
    await client.introspectToken("access-token");
    await client.revokeToken("access-token");

    expect(fetchMock.mock.calls[0][0]).toBe(
      "https://auth.example.com/oauth/token",
    );
    expect(fetchMock.mock.calls[1][0]).toBe(
      "https://auth.example.com/oauth/token",
    );
    expect(fetchMock.mock.calls[2][0]).toBe(
      "https://auth.example.com/oidc/userinfo",
    );
    expect(fetchMock.mock.calls[3][0]).toBe(
      "https://auth.example.com/oauth2/introspect",
    );
    expect(fetchMock.mock.calls[4][0]).toBe(
      "https://auth.example.com/oauth/revoke",
    );

    const tokenHeaders = getCallHeaders(fetchMock, 0);
    const refreshHeaders = getCallHeaders(fetchMock, 1);
    const userInfoHeaders = getCallHeaders(fetchMock, 2);
    const introspectionHeaders = getCallHeaders(fetchMock, 3);
    const revocationHeaders = getCallHeaders(fetchMock, 4);
    const expectedAuth =
      "Basic " +
      Buffer.from(
        `${encodeURIComponent("client-id")}:${encodeURIComponent("client-secret")}`,
        "utf8",
      ).toString("base64");

    const tokenBody = new URLSearchParams(
      fetchMock.mock.calls[0][1]?.body as string,
    );
    const refreshBody = new URLSearchParams(
      fetchMock.mock.calls[1][1]?.body as string,
    );
    const introspectionBody = new URLSearchParams(
      fetchMock.mock.calls[3][1]?.body as string,
    );
    const revocationBody = new URLSearchParams(
      fetchMock.mock.calls[4][1]?.body as string,
    );

    expect(tokenHeaders.get("Authorization")).toBe(expectedAuth);
    expect(refreshHeaders.get("Authorization")).toBe(expectedAuth);
    expect(userInfoHeaders.get("Authorization")).toBe("Bearer access-token");
    expect(introspectionHeaders.get("Authorization")).toBe(expectedAuth);
    expect(revocationHeaders.get("Authorization")).toBe(expectedAuth);
    expect(tokenBody.get("client_id")).toBeNull();
    expect(refreshBody.get("client_id")).toBeNull();
    expect(introspectionBody.get("client_id")).toBeNull();
    expect(revocationBody.get("client_id")).toBeNull();
    expect(revocationBody.get("token_type_hint")).toBe("access_token");
  });

  it("sanitizes reserved keys in token request params", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "access",
          token_type: "Bearer",
          expires_in: 3600,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "access-2",
          token_type: "Bearer",
          expires_in: 3600,
        }),
      );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      clientSecret: "client-secret",
    });

    await client.exchangeCodeForTokens(
      "good-code",
      validCodeVerifier,
      "https://app.example.com/callback",
      {
        grant_type: "evil",
        code: "evil-code",
        client_id: "evil-client",
        client_secret: "evil-secret",
        redirect_uri: "https://evil.example.com/callback",
        code_verifier: validCodeVerifier,
        custom_exchange: "ok",
      },
    );

    await client.refreshToken("good-refresh", {
      grant_type: "evil",
      refresh_token: "evil-refresh",
      client_id: "evil-client",
      client_secret: "evil-secret",
      code: "evil-code",
      redirect_uri: "https://evil.example.com/callback",
      custom_refresh: "ok",
    });

    const exchangeBody = new URLSearchParams(
      fetchMock.mock.calls[0][1]?.body as string,
    );
    expect(exchangeBody.get("grant_type")).toBe("authorization_code");
    expect(exchangeBody.get("code")).toBe("good-code");
    expect(exchangeBody.get("redirect_uri")).toBe(
      "https://app.example.com/callback",
    );
    expect(exchangeBody.get("client_id")).toBeNull();
    expect(exchangeBody.get("client_secret")).toBeNull();
    expect(exchangeBody.get("code_verifier")).toBe(validCodeVerifier);
    expect(exchangeBody.get("custom_exchange")).toBe("ok");

    const refreshBody = new URLSearchParams(
      fetchMock.mock.calls[1][1]?.body as string,
    );
    expect(refreshBody.get("grant_type")).toBe("refresh_token");
    expect(refreshBody.get("refresh_token")).toBe("good-refresh");
    expect(refreshBody.get("client_id")).toBeNull();
    expect(refreshBody.get("client_secret")).toBeNull();
    expect(refreshBody.get("custom_refresh")).toBe("ok");
  });

  it("includes client_id for public-client token requests", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "access",
          token_type: "Bearer",
          expires_in: 3600,
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "access-2",
          token_type: "Bearer",
          expires_in: 3600,
        }),
      )
      .mockResolvedValueOnce(jsonResponse({ active: true }))
      .mockResolvedValueOnce(jsonResponse({}));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "public-client",
    });

    await client.exchangeCodeForTokens(
      "good-code",
      validCodeVerifier,
      "https://app.example.com/callback",
    );
    await client.refreshToken("good-refresh");
    await client.introspectToken("access-token");
    await client.revokeToken("access-token");

    const tokenHeaders = getCallHeaders(fetchMock, 0);
    const refreshHeaders = getCallHeaders(fetchMock, 1);
    const exchangeBody = new URLSearchParams(
      fetchMock.mock.calls[0][1]?.body as string,
    );
    const refreshBody = new URLSearchParams(
      fetchMock.mock.calls[1][1]?.body as string,
    );
    const introspectionBody = new URLSearchParams(
      fetchMock.mock.calls[2][1]?.body as string,
    );
    const revocationBody = new URLSearchParams(
      fetchMock.mock.calls[3][1]?.body as string,
    );

    expect(tokenHeaders.get("Authorization")).toBeNull();
    expect(refreshHeaders.get("Authorization")).toBeNull();
    expect(exchangeBody.get("client_id")).toBe("public-client");
    expect(refreshBody.get("client_id")).toBe("public-client");
    expect(introspectionBody.get("client_id")).toBe("public-client");
    expect(revocationBody.get("client_id")).toBe("public-client");
    expect(revocationBody.get("token_type_hint")).toBe("access_token");
  });

  it("rejects token responses that escalate scopes", async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(
      jsonResponse({
        access_token: "access",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "read write admin",
      }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "public-client",
      scope: "read write",
    });

    await expect(
      client.exchangeCodeForTokens(
        "good-code",
        validCodeVerifier,
        "https://app.example.com/callback",
      ),
    ).rejects.toMatchObject({
      code: "SCOPE_ESCALATION_DETECTED",
    });
  });

  it("rejects token responses that narrow requested scopes by default", async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(
      jsonResponse({
        access_token: "access",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "read",
      }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "public-client",
      scope: "read write",
    });

    await expect(
      client.exchangeCodeForTokens(
        "good-code",
        validCodeVerifier,
        "https://app.example.com/callback",
      ),
    ).rejects.toMatchObject({
      code: "SCOPE_NARROWING_DETECTED",
    });
  });

  it("allows scope narrowing when explicitly configured", async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(
      jsonResponse({
        access_token: "access",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "read",
      }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "public-client",
      scope: "read write",
      allowScopeNarrowing: true,
    });

    await expect(
      client.exchangeCodeForTokens(
        "good-code",
        validCodeVerifier,
        "https://app.example.com/callback",
      ),
    ).resolves.toMatchObject({
      access_token: "access",
    });
  });

  it("returns null data for empty successful responses", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(new Response(null, { status: 204 }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    const response = await client.fetch("/connect/revoke", { method: "POST" });

    expect(response.status).toBe(204);
    expect(response.data).toBeNull();
  });

  it("returns structured fallback for non-JSON error bodies", async () => {
    const fetchMock = jest.fn().mockResolvedValue(
      new Response("<html><body>Bad Gateway from proxy</body></html>", {
        status: 502,
        headers: {
          "Content-Type": "text/html",
        },
      }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await expect(client.fetch("/connect/userinfo")).rejects.toMatchObject({
      code: "server_error",
      statusCode: 502,
    });
  });

  it("supports application/problem+json error responses", async () => {
    const fetchMock = jest.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          type: "about:blank",
          title: "Bad Request",
          detail: "Invalid token",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/problem+json",
          },
        },
      ),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await expect(client.fetch("/connect/userinfo")).rejects.toMatchObject({
      statusCode: 400,
    });
  });

  it("preserves original network error via cause", async () => {
    const networkError = new Error("getaddrinfo ENOTFOUND auth.example.com");
    const fetchMock = jest.fn().mockRejectedValue(networkError);

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await expect(client.fetch("/connect/userinfo")).rejects.toMatchObject({
      code: "NETWORK_ERROR",
      cause: networkError,
    });
  });

  it("omits User-Agent header in standard browser environments", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ sub: "user-1" }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });
    Object.defineProperty(globalThis, "window", {
      value: {},
      configurable: true,
      writable: true,
    });
    Object.defineProperty(globalThis, "navigator", {
      value: { product: "Gecko" },
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await client.getUserInfo("access-token");

    const headers = getCallHeaders(fetchMock, 0);
    expect(headers.get("User-Agent")).toBeNull();
  });

  it("encodes unicode client credentials safely in basic auth", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ active: true }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "cli-ent",
      clientSecret: "p@ss-😀",
    });

    await client.introspectToken("access-token");

    const headers = getCallHeaders(fetchMock, 0);
    const expectedAuth =
      "Basic " +
      Buffer.from(
        `${encodeURIComponent("cli-ent")}:${encodeURIComponent("p@ss-😀")}`,
        "utf8",
      ).toString("base64");

    expect(headers.get("Authorization")).toBe(expectedAuth);
  });

  it("normalizes custom header casing with Headers API", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ sub: "user-1" }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await client.fetch("/connect/userinfo", {
      headers: {
        "content-type": "application/custom+json",
        ACCEPT: "application/problem+json",
      },
    });

    const headers = getCallHeaders(fetchMock, 0);
    expect(headers.get("Content-Type")).toBe("application/custom+json");
    expect(headers.get("Accept")).toBe("application/problem+json");
  });

  it("attaches DPoP proof and uses DPoP auth scheme when configured", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ sub: "user-1" }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      dpopProofFactory: () => "dpop-proof-jwt",
    });

    await client.getUserInfo("access-token");

    const headers = getCallHeaders(fetchMock, 0);
    expect(headers.get("DPoP")).toBe("dpop-proof-jwt");
    expect(headers.get("Authorization")).toBe("DPoP access-token");
  });

  it("rejects oversized authorization headers", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ sub: "user-1" }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      maxAuthorizationHeaderBytes: 64,
    });

    await expect(client.getUserInfo("a".repeat(200))).rejects.toMatchObject({
      code: "HEADER_TOO_LARGE",
    });

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards AbortSignal to fetch", async () => {
    const fetchMock = jest.fn().mockImplementation(
      (_input, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          const signal = init?.signal;

          if (!signal) {
            reject(new Error("missing signal"));
            return;
          }

          signal.addEventListener(
            "abort",
            () => {
              reject(new Error("aborted"));
            },
            { once: true },
          );
        }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const controller = new AbortController();
    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    const requestPromise = client.fetch("/connect/userinfo", {
      signal: controller.signal,
    });

    await Promise.resolve();

    const forwardedSignal = fetchMock.mock.calls[0][1]?.signal as
      | AbortSignal
      | undefined;

    expect(forwardedSignal).toBeDefined();

    controller.abort();
    await expect(requestPromise).rejects.toMatchObject({
      code: "NETWORK_ERROR",
    });
  });

  it("times out requests when requestTimeoutMs is exceeded", async () => {
    const fetchMock = jest.fn().mockImplementation(
      (input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((resolve, reject) => {
          void input;
          void resolve;

          const signal = init?.signal;

          if (!signal) {
            return;
          }

          signal.addEventListener(
            "abort",
            () => {
              reject(new Error("aborted"));
            },
            { once: true },
          );
        }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      requestTimeoutMs: 10,
    });

    await expect(client.fetch("/connect/userinfo")).rejects.toMatchObject({
      code: "REQUEST_TIMEOUT",
    });
  });

  it("throws when GET request has a body", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ sub: "user-1" }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await expect(
      client.fetch("/connect/userinfo", {
        method: "GET",
        body: "token=abc",
      }),
    ).rejects.toMatchObject({
      code: "INVALID_REQUEST",
    });

    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("adds token_type_hint for revocation when provided", async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({}));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await client.revokeToken("access-token", "refresh_token");

    const body = new URLSearchParams(
      fetchMock.mock.calls[0][1]?.body as string,
    );
    expect(body.get("token_type_hint")).toBe("refresh_token");
  });

  it("stores sanitized session state without refresh token value", async () => {
    const persisted: Record<string, string> = {};
    const storage = {
      getItem: jest.fn(async (key: string) => persisted[key] ?? null),
      setItem: jest.fn(async (key: string, value: string) => {
        persisted[key] = value;
      }),
      removeItem: jest.fn(async (key: string) => {
        delete persisted[key];
      }),
    };

    const fetchMock = jest.fn().mockResolvedValueOnce(
      jsonResponse({
        access_token: "access",
        token_type: "Bearer",
        expires_in: 3600,
        refresh_token: "refresh-value",
        scope: "read",
      }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      scope: "read",
      storage,
    });

    await client.exchangeCodeForTokens(
      "good-code",
      validCodeVerifier,
      "https://app.example.com/callback",
    );

    const session = await client.getSessionState();
    expect(session).toMatchObject({
      accessToken: "access",
      hasRefreshToken: true,
    });

    const persistedValues = Object.values(persisted).join(" ");
    expect(persistedValues.includes("refresh-value")).toBe(false);
  });

  it("clears local session on silent authentication interaction errors", async () => {
    const persisted: Record<string, string> = {};
    const storage = {
      getItem: jest.fn(async (key: string) => persisted[key] ?? null),
      setItem: jest.fn(async (key: string, value: string) => {
        persisted[key] = value;
      }),
      removeItem: jest.fn(async (key: string) => {
        delete persisted[key];
      }),
    };

    const fetchMock = jest.fn().mockResolvedValueOnce(
      jsonResponse({
        access_token: "access",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "read",
      }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      scope: "read",
      storage,
    });

    await client.exchangeCodeForTokens(
      "good-code",
      validCodeVerifier,
      "https://app.example.com/callback",
    );

    await expect(
      client.handleSilentAuthenticationError(
        "interaction_required",
        "User interaction is required",
      ),
    ).rejects.toMatchObject({
      code: "SILENT_AUTH_INTERACTION_REQUIRED",
    });

    expect(await client.getSessionState()).toBeNull();
    expect(storage.removeItem).toHaveBeenCalled();
  });

  it("validates OAuth callback state and returns parsed callback", async () => {
    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    const callback = await client.validateOAuthCallback(
      "https://app.example.com/callback?code=abc&state=state-callback-123456",
      "state-callback-123456",
    );

    expect(callback.code).toBe("abc");
    expect(callback.state).toBe("state-callback-123456");
  });

  it("clears session when silent callback requires interaction", async () => {
    const persisted: Record<string, string> = {};
    const storage = {
      getItem: jest.fn(async (key: string) => persisted[key] ?? null),
      setItem: jest.fn(async (key: string, value: string) => {
        persisted[key] = value;
      }),
      removeItem: jest.fn(async (key: string) => {
        delete persisted[key];
      }),
    };

    const fetchMock = jest.fn().mockResolvedValueOnce(
      jsonResponse({
        access_token: "access",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "read",
      }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      scope: "read",
      storage,
    });

    await client.exchangeCodeForTokens(
      "good-code",
      validCodeVerifier,
      "https://app.example.com/callback",
    );

    await expect(
      client.validateOAuthCallback(
        "https://app.example.com/callback?error=interaction_required&error_description=Need%20login&state=state-callback-654321",
        "state-callback-654321",
        "none",
      ),
    ).rejects.toMatchObject({
      code: "SILENT_AUTH_INTERACTION_REQUIRED",
    });

    expect(await client.getSessionState()).toBeNull();
  });

  it("clears local session when refresh fails with invalid_grant", async () => {
    const persisted: Record<string, string> = {};
    const storage = {
      getItem: jest.fn(async (key: string) => persisted[key] ?? null),
      setItem: jest.fn(async (key: string, value: string) => {
        persisted[key] = value;
      }),
      removeItem: jest.fn(async (key: string) => {
        delete persisted[key];
      }),
    };

    const fetchMock = jest
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          access_token: "access",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "read",
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          {
            error: "invalid_grant",
            error_description: "Refresh token expired",
          },
          400,
        ),
      );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      scope: "read",
      storage,
    });

    await client.exchangeCodeForTokens(
      "good-code",
      validCodeVerifier,
      "https://app.example.com/callback",
    );

    await expect(client.refreshToken("refresh-value")).rejects.toMatchObject({
      code: "invalid_grant",
    });

    expect(await client.getSessionState()).toBeNull();
  });

  it("requires initial access token for dynamic registration", async () => {
    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await expect(client.registerClient({}, "")).rejects.toMatchObject({
      code: "INVALID_REQUEST",
    });
  });

  it("sends authenticated dynamic registration request", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ client_id: "registered-client" }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    const metadata = {
      client_name: "My App",
      redirect_uris: ["https://app.example.com/callback"],
    };

    const response = await client.registerClient(
      metadata,
      "initial-access-token",
    );

    expect(response.client_id).toBe("registered-client");
    const headers = getCallHeaders(fetchMock, 0);
    expect(headers.get("Authorization")).toBe("Bearer initial-access-token");
  });

  it("fails clickjacking protection check when headers are missing", async () => {
    const fetchMock = jest.fn().mockResolvedValue(
      new Response("<html>authorize</html>", {
        status: 200,
        headers: {
          "Content-Type": "text/html",
        },
      }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await expect(
      client.assertAuthorizationPageClickjackingProtection(),
    ).rejects.toMatchObject({
      code: "AUTH_PAGE_CLICKJACKING_RISK",
    });
  });

  it("passes clickjacking protection check when frame headers are present", async () => {
    const fetchMock = jest.fn().mockResolvedValue(
      new Response("<html>authorize</html>", {
        status: 200,
        headers: {
          "Content-Type": "text/html",
          "X-Frame-Options": "DENY",
          "Content-Security-Policy":
            "default-src 'self'; frame-ancestors 'none'",
        },
      }),
    );

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await expect(
      client.assertAuthorizationPageClickjackingProtection(),
    ).resolves.toMatchObject({
      protected: true,
      xFrameOptions: "DENY",
      frameAncestorsPolicy: "frame-ancestors 'none'",
    });
  });

  it("validates UserInfo subject against expected id_token subject", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ sub: "user-2" }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await expect(
      client.getUserInfo("access-token", "user-1"),
    ).rejects.toMatchObject({
      code: "USERINFO_SUBJECT_MISMATCH",
    });
  });

  it("builds secure logout URL and validates redirect allowlist", () => {
    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      allowedPostLogoutRedirectUris: ["https://app.example.com/logout"],
    });

    const logoutUrl = client.buildLogoutUrl({
      postLogoutRedirectUri: "https://app.example.com/logout",
      idTokenHint: "id-token-hint",
      state: "logout-state",
    });

    const parsed = new URL(logoutUrl);
    expect(parsed.pathname).toBe("/connect/endsession");
    expect(parsed.searchParams.get("post_logout_redirect_uri")).toBe(
      "https://app.example.com/logout",
    );
    expect(parsed.searchParams.get("id_token_hint")).toBe("id-token-hint");
    expect(parsed.searchParams.get("state")).toBe("logout-state");
  });

  it("rejects unsafe post logout redirect URIs", () => {
    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      allowedPostLogoutRedirectUris: ["https://app.example.com/logout"],
    });

    expect(() =>
      client.buildLogoutUrl({
        postLogoutRedirectUri: "https://evil.example/logout",
      }),
    ).toThrow("allowedPostLogoutRedirectUris");
  });

  it("rejects id_token_hint on non-HTTPS authorities", () => {
    const client = new GuardhouseClient({
      authority: "http://localhost:3000",
      clientId: "client-id",
    });

    expect(() =>
      client.buildLogoutUrl({
        idTokenHint: "id-token-hint",
      }),
    ).toThrow("id_token_hint can only be used with HTTPS authorities");
  });

  it("discovers OIDC metadata only from configured authority", async () => {
    const fetchMock = jest
      .fn()
      .mockResolvedValue(jsonResponse({ issuer: "https://auth.example.com" }));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    await expect(client.discoverOpenIdConfiguration()).resolves.toMatchObject({
      issuer: "https://auth.example.com",
    });

    await expect(
      client.discoverOpenIdConfiguration(
        "https://evil.example/.well-known/openid-configuration",
      ),
    ).rejects.toMatchObject({
      code: "UNSAFE_ENDPOINT_URL",
    });
  });

  it("opens popup with noopener/noreferrer protections", () => {
    const popupRef: { opener?: unknown } = { opener: {} };
    const openMock = jest.fn().mockReturnValue(popupRef);

    Object.defineProperty(globalThis, "window", {
      value: { open: openMock },
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    client.openAuthorizationPopup("https://auth.example.com/connect/authorize");

    expect(openMock).toHaveBeenCalled();
    const calledFeatures = openMock.mock.calls[0][2] as string;
    expect(calledFeatures.includes("noopener")).toBe(true);
    expect(calledFeatures.includes("noreferrer")).toBe(true);
    expect(popupRef.opener).toBeNull();
  });

  it("enforces user interaction checks for sensitive operations", async () => {
    const fetchMock = jest.fn().mockResolvedValue(jsonResponse({}));

    Object.defineProperty(globalThis, "fetch", {
      value: fetchMock,
      configurable: true,
      writable: true,
    });

    Object.defineProperty(globalThis, "navigator", {
      value: { userActivation: { isActive: false } },
      configurable: true,
      writable: true,
    });

    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      requireUserInteractionForSensitiveOperations: true,
    });

    await expect(client.revokeToken("access-token")).rejects.toMatchObject({
      code: "USER_INTERACTION_REQUIRED",
    });
  });

  it("provides secure defaults for sensitive input attributes", () => {
    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

    const otpAttributes = client.getSecureInputAttributes("otp");
    expect(otpAttributes.autocomplete).toBe("off");
    expect(otpAttributes.inputmode).toBe("numeric");

    const passwordAttributes = client.getSecureInputAttributes("password");
    expect(passwordAttributes.autocomplete).toBe("new-password");
  });

  it("limits repeated silent authentication attempts", async () => {
    const client = new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      maxSilentAuthAttempts: 2,
    });

    await expect(
      client.handleSilentAuthenticationError("interaction_required"),
    ).rejects.toMatchObject({
      code: "SILENT_AUTH_INTERACTION_REQUIRED",
    });

    await expect(
      client.handleSilentAuthenticationError("login_required"),
    ).rejects.toMatchObject({
      code: "SILENT_AUTH_INTERACTION_REQUIRED",
    });

    await expect(
      client.handleSilentAuthenticationError("interaction_required"),
    ).rejects.toMatchObject({
      code: "SILENT_AUTH_RETRY_LIMIT_EXCEEDED",
    });
  });

  it("warns when global fetch is unavailable", () => {
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    const infoSpy = jest.spyOn(console, "info").mockImplementation(() => {});

    Object.defineProperty(globalThis, "fetch", {
      value: undefined,
      configurable: true,
      writable: true,
    });

    new GuardhouseClient({
      authority: "https://auth.example.com",
      clientId: "client-id",
      debug: true,
    });

    expect(
      warnSpy.mock.calls.some((call) =>
        call.some(
          (arg) =>
            typeof arg === "string" &&
            arg.includes("Global fetch API is unavailable"),
        ),
      ),
    ).toBe(true);

    infoSpy.mockRestore();
  });
});
