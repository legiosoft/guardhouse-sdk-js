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
