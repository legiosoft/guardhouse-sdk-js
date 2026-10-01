import { GuardhouseClient } from "../client";
import { sanitizeOAuthCallbackUrl } from "../auth";
import type { OidcIdentityEvidence } from "../token";

class StorageTestClient extends GuardhouseClient {
  clearPersistedSessionIfUnchanged(
    expected: string | null | undefined,
  ): Promise<void> {
    return this.clearSessionStateIfUnchanged(expected);
  }

  persistTokens(accessToken: string): Promise<void> {
    const generation = this.beginSessionOperation();
    return this.cacheSessionState(
      {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid",
      },
      generation,
    );
  }
}

function jsonResponse(
  data: unknown,
  status = 200,
  statusText?: string,
): Response {
  return new Response(JSON.stringify(data), {
    status,
    ...(statusText === undefined ? {} : { statusText }),
    headers: { "Content-Type": "application/json" },
  });
}

const discovery = {
  issuer: "https://auth.example.com/",
  authorization_endpoint: "https://auth.example.com/connect/authorize",
  token_endpoint: "https://auth.example.com/connect/token",
  end_session_endpoint: "https://auth.example.com/connect/logout",
  pushed_authorization_request_endpoint: "https://auth.example.com/connect/par",
  authorization_response_iss_parameter_supported: true,
};

describe("GuardhouseClient v2 trust boundaries", () => {
  afterEach(() => jest.restoreAllMocks());

  it("creates and restores an issuer/client-bound request with repeated resources", async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => jsonResponse(discovery));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const created = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback?tenant=one",
      scope: "openid profile",
      resource: ["https://api.example.com/a", "https://api.example.com/b"],
      requiredAcrValues: ["urn:mfa"],
      requiredAmrValues: ["otp"],
    });
    const url = new URL(created.authorizationUrl);
    expect(url.searchParams.getAll("resource")).toEqual([
      "https://api.example.com/a",
      "https://api.example.com/b",
    ]);
    expect(url.searchParams.get("audience")).toBeNull();
    expect(
      client.restoreAuthorizationTransaction(
        JSON.parse(JSON.stringify(created.transaction)),
      ),
    ).toMatchObject({
      version: 2,
      issuer: "https://auth.example.com/",
      clientId: "client-id",
    });
  });

  it("validates only transaction-bound code callbacks and sanitizes fixed query URLs", async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => jsonResponse(discovery));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const { transaction } = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback?tenant=one",
      scope: "openid",
      audience: "https://api.example.com",
    });
    const result = await client.validateOAuthCallback(
      {
        mode: "query",
        url: `https://app.example.com/callback?tenant=one&code=code-1&state=${transaction.state}&iss=${encodeURIComponent(transaction.issuer)}`,
      },
      transaction,
    );
    expect(result).toMatchObject({
      type: "authorization_code",
      code: "code-1",
      sanitizedUrl: "https://app.example.com/callback?tenant=one",
    });
  });

  it("accepts only same-client, one-use validated callback evidence", async () => {
    const fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input) => {
        if (String(input).includes(".well-known/openid-configuration")) {
          return jsonResponse(discovery);
        }
        return jsonResponse({
          access_token: "access-token",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "profile",
        });
      });
    const firstClient = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const secondClient = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const { transaction } = await firstClient.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "profile",
      audience: "https://api.example.com",
    });

    await expect(
      firstClient.exchangeAuthorizationCode({
        type: "authorization_code",
        code: "forged-code",
        state: transaction.state,
        sanitizedUrl: transaction.redirectUri,
      } as never),
    ).rejects.toMatchObject({ code: "INVALID_CALLBACK_EVIDENCE" });

    const callback = await firstClient.validateOAuthCallback(
      {
        mode: "query",
        url: `https://app.example.com/callback?code=valid-code&state=${transaction.state}&iss=${encodeURIComponent(transaction.issuer)}`,
      },
      transaction,
    );
    if (callback.type !== "authorization_code") {
      throw new Error("Expected an authorization-code callback");
    }

    await expect(
      secondClient.exchangeAuthorizationCode(callback),
    ).rejects.toMatchObject({ code: "INVALID_CALLBACK_EVIDENCE" });
    await expect(
      firstClient.exchangeAuthorizationCode(callback),
    ).resolves.toMatchObject({ mode: "oauth2" });
    await expect(
      firstClient.exchangeAuthorizationCode(callback),
    ).rejects.toMatchObject({ code: "INVALID_CALLBACK_EVIDENCE" });

    expect(
      fetchMock.mock.calls.filter(([input]) =>
        String(input).includes("/connect/token"),
      ),
    ).toHaveLength(1);
  });

  it("consumes validated callback evidence before a failed token request", async () => {
    const fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input) => {
        if (String(input).includes(".well-known/openid-configuration")) {
          return jsonResponse(discovery);
        }
        throw new Error("network unavailable");
      });
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const { transaction } = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "profile",
      audience: "https://api.example.com",
    });
    const callback = await client.validateOAuthCallback(
      {
        mode: "query",
        url: `https://app.example.com/callback?code=valid-code&state=${transaction.state}&iss=${encodeURIComponent(transaction.issuer)}`,
      },
      transaction,
    );
    if (callback.type !== "authorization_code") {
      throw new Error("Expected an authorization-code callback");
    }

    await expect(
      client.exchangeAuthorizationCode(callback),
    ).rejects.toBeDefined();
    await expect(
      client.exchangeAuthorizationCode(callback),
    ).rejects.toMatchObject({ code: "INVALID_CALLBACK_EVIDENCE" });

    expect(
      fetchMock.mock.calls.filter(([input]) =>
        String(input).includes("/connect/token"),
      ),
    ).toHaveLength(1);
  });

  it("rejects duplicate and front-channel token callback parameters", async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => jsonResponse(discovery));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const first = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid",
      audience: "https://api.example.com",
    });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?code=a&code=b&state=${first.transaction.state}`,
        },
        first.transaction,
      ),
    ).rejects.toThrow("duplicate");

    const second = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid",
      audience: "https://api.example.com",
    });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?code=a&access_token=front&state=${second.transaction.state}`,
        },
        second.transaction,
      ),
    ).rejects.toMatchObject({ code: "UNSUPPORTED_CALLBACK_RESPONSE" });
  });

  it("validates the complete callback before consuming state", async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => jsonResponse(discovery));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const { transaction } = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid",
      audiencePolicy: "oidc-optional",
    });
    const issuer = encodeURIComponent(transaction.issuer);

    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?code=&state=${transaction.state}&iss=${issuer}`,
        },
        transaction,
      ),
    ).rejects.toMatchObject({ code: "INVALID_CALLBACK_RESPONSE" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?code=valid-code&error_description=orphaned&state=${transaction.state}&iss=${issuer}`,
        },
        transaction,
      ),
    ).rejects.toMatchObject({ code: "INVALID_CALLBACK_RESPONSE" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?code=valid-code&state=${transaction.state}&iss=${issuer}`,
        },
        transaction,
      ),
    ).resolves.toMatchObject({
      type: "authorization_code",
      code: "valid-code",
    });

    const errorTransaction = (
      await client.createAuthorizationRequest({
        redirectUri: "https://app.example.com/callback",
        scope: "openid",
        audiencePolicy: "oidc-optional",
      })
    ).transaction;
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?error=&state=${errorTransaction.state}&iss=${issuer}`,
        },
        errorTransaction,
      ),
    ).rejects.toMatchObject({ code: "INVALID_CALLBACK_RESPONSE" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?error=access_denied&state=${errorTransaction.state}&iss=${issuer}`,
        },
        errorTransaction,
      ),
    ).resolves.toMatchObject({ type: "error", error: "access_denied" });
  });

  it("rejects wrong issuer, redirect collisions, mixed channels, and expired transactions", async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => jsonResponse(discovery));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const created = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback?a=x%26b%3Dy",
      scope: "openid",
      audiencePolicy: "oidc-optional",
    });
    const { transaction } = created;

    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?a=x%26b%3Dy&code=code&state=${transaction.state}&iss=${encodeURIComponent("https://evil.example.com/")}`,
        },
        transaction,
      ),
    ).rejects.toMatchObject({ code: "ISSUER_VALIDATION_FAILED" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?a=x&b=y&code=code&state=${transaction.state}&iss=${encodeURIComponent(transaction.issuer)}`,
        },
        transaction,
      ),
    ).rejects.toMatchObject({ code: "REDIRECT_URI_MISMATCH" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?a=x%26b%3Dy&code=code&state=${transaction.state}&iss=${encodeURIComponent(transaction.issuer)}#error=access_denied`,
        },
        transaction,
      ),
    ).rejects.toMatchObject({ code: "INVALID_CALLBACK_RESPONSE" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?a=x%26b%3Dy&code=code&state=${transaction.state}&iss=${encodeURIComponent(transaction.issuer)}`,
        },
        transaction,
      ),
    ).resolves.toMatchObject({ type: "authorization_code" });

    const expired = {
      ...created.transaction,
      createdAt: Date.now() - 120_000,
      expiresAt: Date.now() - 1,
    };
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://app.example.com/callback?a=x%26b%3Dy&code=code&state=${transaction.state}`,
        },
        expired,
      ),
    ).rejects.toMatchObject({ code: "INVALID_AUTHORIZATION_TRANSACTION" });
  });

  it("matches redirect schemes, authorities, credentials, and ordered query tuples exactly", async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => jsonResponse(discovery));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const native = await client.createAuthorizationRequest({
      redirectUri: "com.guardhouse.app://callback/oauth?item=one&item=two",
      scope: "openid",
      audiencePolicy: "oidc-optional",
    });
    const nativeIssuer = encodeURIComponent(native.transaction.issuer);

    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `evil.scheme://attacker/oauth?item=one&item=two&code=code&state=${native.transaction.state}&iss=${nativeIssuer}`,
        },
        native.transaction,
      ),
    ).rejects.toMatchObject({ code: "REDIRECT_URI_MISMATCH" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `com.guardhouse.app://attacker/oauth?item=one&item=two&code=code&state=${native.transaction.state}&iss=${nativeIssuer}`,
        },
        native.transaction,
      ),
    ).rejects.toMatchObject({ code: "REDIRECT_URI_MISMATCH" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `evil.scheme://callback/oauth?item=one&item=two&code=code&state=${native.transaction.state}&iss=${nativeIssuer}`,
        },
        native.transaction,
      ),
    ).rejects.toMatchObject({ code: "REDIRECT_URI_MISMATCH" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `com.guardhouse.app://callback/oauth?item=two&item=one&code=code&state=${native.transaction.state}&iss=${nativeIssuer}`,
        },
        native.transaction,
      ),
    ).rejects.toMatchObject({ code: "REDIRECT_URI_MISMATCH" });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `com.guardhouse.app://callback/oauth?item=one&item=two&code=code&state=${native.transaction.state}&iss=${nativeIssuer}`,
        },
        native.transaction,
      ),
    ).resolves.toMatchObject({ type: "authorization_code" });

    const web = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid",
      audiencePolicy: "oidc-optional",
    });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "query",
          url: `https://user@app.example.com/callback?code=code&state=${web.transaction.state}&iss=${encodeURIComponent(web.transaction.issuer)}`,
        },
        web.transaction,
      ),
    ).rejects.toMatchObject({ code: "REDIRECT_URI_MISMATCH" });
    expect(
      sanitizeOAuthCallbackUrl(
        "https://user:secret@app.example.com/callback?code=secret&state=value",
      ),
    ).toBe("https://app.example.com/callback");
  });

  it("accepts RFC 8707 URNs and rejects relative or fragment-bearing resources", async () => {
    const fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input, init) => {
        if (String(input).includes(".well-known/openid-configuration")) {
          return jsonResponse(discovery);
        }
        expect(String(init?.body)).toContain(
          "resource=urn%3Aexample%3Apayments",
        );
        return jsonResponse({
          access_token: "service-token",
          token_type: "Bearer",
          expires_in: 3600,
        });
      });
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      clientSecret: "secret",
    });

    const created = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid",
      resource: "urn:example:payments",
    });
    expect(created).toHaveProperty("transaction.requestedResources", [
      "urn:example:payments",
    ]);
    expect(() =>
      client.restoreAuthorizationTransaction({
        ...created.transaction,
        requestedResources: ["/relative"],
      }),
    ).toThrow(
      expect.objectContaining({ code: "INVALID_AUTHORIZATION_TRANSACTION" }),
    );
    await expect(
      client.createAuthorizationRequest({
        redirectUri: "https://app.example.com/callback",
        scope: "openid",
        resource: "/relative",
      }),
    ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    await expect(
      client.requestClientCredentialsToken({
        resource: "https://api.example.com/#fragment",
      }),
    ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    await expect(
      client.requestClientCredentialsToken({
        resource: "urn:example:payments",
      }),
    ).resolves.toMatchObject({ access_token: "service-token" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("supports bound form_post responses and sanitizes polluted callback URLs", async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => jsonResponse(discovery));
    const replaceState = jest.fn();
    Object.defineProperty(globalThis, "history", {
      value: { replaceState },
      configurable: true,
      writable: true,
    });
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const first = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid",
      audiencePolicy: "oidc-optional",
      responseMode: "form_post",
    });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "form_post",
          url: "https://app.example.com/callback?code=pollution",
          body: new URLSearchParams({
            code: "valid-code",
            state: first.transaction.state,
            iss: first.transaction.issuer,
          }),
        },
        first.transaction,
      ),
    ).rejects.toMatchObject({ code: "INVALID_CALLBACK_RESPONSE" });
    expect(String(replaceState.mock.calls[0]?.[2])).not.toContain("code=");

    const second = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid",
      audiencePolicy: "oidc-optional",
      responseMode: "form_post",
    });
    await expect(
      client.validateOAuthCallback(
        {
          mode: "form_post",
          url: "https://app.example.com/callback",
          body: new URLSearchParams({
            code: "valid-code",
            state: second.transaction.state,
            iss: second.transaction.issuer,
          }),
        },
        second.transaction,
      ),
    ).resolves.toMatchObject({
      type: "authorization_code",
      code: "valid-code",
    });
  });

  it("decodes token responses from unknown and fails closed", async () => {
    jest.spyOn(globalThis, "fetch").mockResolvedValue(
      jsonResponse({
        access_token: "token",
        token_type: "Bearer",
        expires_in: "3600",
      }),
    );
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    await expect(
      client.refreshOAuthToken("refresh-token"),
    ).rejects.toMatchObject({
      code: "INVALID_TOKEN_RESPONSE",
    });
  });

  it("uses form encoding before Basic authentication encoding", async () => {
    const fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ active: false }));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client id",
      clientSecret: "s+ecret",
    });
    await expect(client.introspectToken("token")).resolves.toEqual({
      active: false,
    });
    const headers = new Headers(fetchMock.mock.calls[0]?.[1]?.headers);
    expect(headers.get("Authorization")).toBe(
      `Basic ${Buffer.from("client+id:s%2Becret", "utf8").toString("base64")}`,
    );
  });

  it("rejects forged identity objects before calling UserInfo", async () => {
    const fetchMock = jest.spyOn(globalThis, "fetch");
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    const forgedIdentity = {
      issuer: "https://auth.example.com/",
      clientId: "client-id",
      subject: "user-1",
      audiences: ["client-id"],
      authorizedParty: null,
      issuedAt: 1,
      expiresAt: 2,
      nonce: null,
      authTime: null,
      acr: null,
      amr: [],
      sessionId: null,
    } as unknown as OidcIdentityEvidence;

    await expect(
      client.getUserInfo("access-token", forgedIdentity),
    ).rejects.toMatchObject({ code: "INVALID_IDENTITY" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('rejects the string value active: "false" from introspection', async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ active: "false" }));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });

    await expect(client.introspectToken("token")).rejects.toMatchObject({
      code: "INVALID_INTROSPECTION_RESPONSE",
    });
  });

  it("rejects non-boolean introspection activity", async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ active: "false", sub: "attacker" }));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });

    await expect(client.introspectToken("opaque-token")).rejects.toMatchObject({
      code: "INVALID_INTROSPECTION_RESPONSE",
    });
  });

  it("never exposes response-controlled OAuth errors or status text", async () => {
    const echoedSecret = "sensitive_refresh_token_abc123";
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    const warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    jest
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(
        jsonResponse(
          { error: echoedSecret, error_description: echoedSecret },
          400,
          echoedSecret,
        ),
      );
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      clientSecret: "client-secret",
    });

    let caught: unknown;
    try {
      await client.introspectToken(echoedSecret);
    } catch (error) {
      caught = error;
    }

    expect(caught).toMatchObject({
      code: "server_error",
      message: "Request failed with status 400",
      statusCode: 400,
    });
    expect(String(caught)).not.toContain(echoedSecret);
    expect(
      JSON.stringify([...errorSpy.mock.calls, ...warnSpy.mock.calls]),
    ).not.toContain(echoedSecret);
  });

  it("fails before feature requests when discovery does not advertise PAR, DCR, or logout", async () => {
    const unsupportedDiscovery = {
      issuer: discovery.issuer,
      authorization_endpoint: discovery.authorization_endpoint,
      token_endpoint: discovery.token_endpoint,
      authorization_response_iss_parameter_supported: true,
    };
    const fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse(unsupportedDiscovery));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      discoveryCacheTtlMs: 60_000,
    });
    const { transaction } = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid",
      audiencePolicy: "oidc-optional",
    });

    await expect(
      client.createPushedAuthorizationRequest(transaction),
    ).rejects.toMatchObject({ code: "UNSUPPORTED_FEATURE", feature: "par" });
    await expect(
      client.registerClient(
        { redirect_uris: ["https://app.example.com/callback"] },
        "initial-access-token",
      ),
    ).rejects.toMatchObject({
      code: "UNSUPPORTED_FEATURE",
      feature: "dynamic_client_registration",
    });
    await expect(client.buildLogoutUrl()).rejects.toMatchObject({
      code: "UNSUPPORTED_FEATURE",
      feature: "logout",
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("binds PAR request URIs to one transaction and emits only the RFC parameters", async () => {
    const fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async (input) => {
        const url = String(input);
        if (url.includes(".well-known/openid-configuration")) {
          return jsonResponse({
            ...discovery,
            authorization_endpoint:
              "https://auth.example.com/connect/authorize?injected=1#fragment",
          });
        }
        if (url === discovery.pushed_authorization_request_endpoint) {
          return jsonResponse({
            request_uri: "urn:ietf:params:oauth:request_uri:one-use",
            expires_in: 90,
          });
        }
        throw new Error(`Unexpected request: ${url}`);
      });
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      discoveryCacheTtlMs: 60_000,
    });
    const { transaction } = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid profile",
      audience: "https://api.example.com",
    });
    const pushed = await client.createPushedAuthorizationRequest(transaction);
    const authorizationUrl = new URL(
      client.buildPushedAuthorizationUrl(pushed, transaction),
    );

    expect([...authorizationUrl.searchParams.keys()].sort()).toEqual([
      "client_id",
      "request_uri",
    ]);
    expect(authorizationUrl.searchParams.get("client_id")).toBe("client-id");
    expect(authorizationUrl.searchParams.get("request_uri")).toBe(
      pushed.requestUri,
    );
    expect(authorizationUrl.hash).toBe("");
    await expect(
      Promise.resolve().then(() =>
        client.buildPushedAuthorizationUrl(pushed, transaction),
      ),
    ).rejects.toMatchObject({ code: "PAR_REQUEST_URI_INVALID" });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("does not let PAR extensions override omitted transaction security parameters", async () => {
    const fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () => jsonResponse(discovery));
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      discoveryCacheTtlMs: 60_000,
    });
    const { transaction } = await client.createAuthorizationRequest({
      redirectUri: "https://app.example.com/callback",
      scope: "openid",
      audiencePolicy: "oidc-optional",
    });

    const attemptedOverrides: Array<Record<string, string>> = [
      { resource: "https://evil.example.com/api" },
      { audience: "https://evil.example.com/api" },
      { max_age: "0" },
    ];
    for (const additionalParameters of attemptedOverrides) {
      await expect(
        client.createPushedAuthorizationRequest(
          transaction,
          additionalParameters,
        ),
      ).rejects.toMatchObject({ code: "INVALID_REQUEST" });
    }

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("does not coalesce refreshes with different granted-scope contexts", async () => {
    let resolveResponse!: (response: Response) => void;
    const responsePromise = new Promise<Response>((resolve) => {
      resolveResponse = resolve;
    });
    jest.spyOn(globalThis, "fetch").mockReturnValue(responsePromise);
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });

    const first = client.refreshOAuthToken("same-refresh-token", {
      grantedScope: "openid",
    });
    await expect(
      client.refreshOAuthToken("same-refresh-token", {
        grantedScope: "openid admin",
      }),
    ).rejects.toMatchObject({ code: "REFRESH_OPERATION_CONFLICT" });

    resolveResponse(
      jsonResponse({
        access_token: "new-access-token",
        token_type: "Bearer",
        expires_in: 3600,
        scope: "openid",
      }),
    );
    await expect(first).resolves.toMatchObject({
      access_token: "new-access-token",
      scope: "openid",
    });
  });

  it("keeps refresh coalescing isolated to each client instance", async () => {
    const fetchMock = jest
      .spyOn(globalThis, "fetch")
      .mockImplementation(async () =>
        jsonResponse({
          access_token: "new-access-token",
          token_type: "Bearer",
          expires_in: 3600,
          scope: "openid",
        }),
      );
    const firstClient = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-a",
    });
    const secondClient = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-b",
    });

    await Promise.all([
      firstClient.refreshOAuthToken("shared-value", {
        grantedScope: "openid",
      }),
      secondClient.refreshOAuthToken("shared-value", {
        grantedScope: "openid",
      }),
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("fails closed when conditional storage removal retains stale state", async () => {
    const stale = JSON.stringify({ accessToken: "stale" });
    let value: string | null = stale;
    const storage = {
      getItem: jest.fn(async () => value),
      setItem: jest.fn(async (_key: string, next: string) => {
        value = next;
      }),
      removeItem: jest.fn(async () => undefined),
    };
    const client = new StorageTestClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      storage,
    });

    await expect(
      client.clearPersistedSessionIfUnchanged(stale),
    ).rejects.toMatchObject({ code: "SESSION_STORAGE_CLEAR_FAILED" });
  });

  it("fails closed when atomic removal reports false but retains the match", async () => {
    const stale = JSON.stringify({ accessToken: "stale" });
    const storage = {
      getItem: jest.fn(async () => stale),
      setItem: jest.fn(async () => undefined),
      removeItem: jest.fn(async () => undefined),
      compareAndRemoveItem: jest.fn(() => false),
    };
    const client = new StorageTestClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      storage,
    });

    await expect(
      client.clearPersistedSessionIfUnchanged(stale),
    ).rejects.toMatchObject({ code: "SESSION_STORAGE_CLEAR_FAILED" });
    expect(storage.removeItem).not.toHaveBeenCalled();
  });

  it("never deletes a newer record during conditional cleanup", async () => {
    const stale = JSON.stringify({ accessToken: "stale" });
    const newer = JSON.stringify({ accessToken: "newer" });
    let value: string | null = stale;
    const storage = {
      getItem: jest.fn(async () => value),
      setItem: jest.fn(async (_key: string, next: string) => {
        value = next;
      }),
      removeItem: jest.fn(async () => {
        value = newer;
      }),
    };
    const client = new StorageTestClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      storage,
    });

    await expect(
      client.clearPersistedSessionIfUnchanged(stale),
    ).resolves.toBeUndefined();
    expect(value).toBe(newer);
  });

  it("uses atomic compare-and-remove and preserves a newer restore record", async () => {
    const stale = "not-json";
    const newer = JSON.stringify({ accessToken: "newer" });
    let value: string | null = stale;
    let firstRead = true;
    const storage = {
      getItem: jest.fn(async () => {
        if (firstRead) {
          firstRead = false;
          const result = value;
          value = newer;
          return result;
        }
        return value;
      }),
      setItem: jest.fn(async (_key: string, next: string) => {
        value = next;
      }),
      removeItem: jest.fn(async () => {
        value = null;
      }),
      compareAndRemoveItem: jest.fn(
        async (_key: string, expectedValue: string) => {
          if (value !== expectedValue) return false;
          value = null;
          return true;
        },
      ),
    };
    const client = new StorageTestClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      storage,
    });

    await expect(client.getSessionState()).resolves.toBeNull();
    expect(value).toBe(newer);
    expect(storage.compareAndRemoveItem).toHaveBeenCalledWith(
      expect.any(String),
      stale,
    );
    expect(storage.removeItem).not.toHaveBeenCalled();
  });

  it("does not delete a newer record after a failed session write", async () => {
    const newer = JSON.stringify({ accessToken: "newer" });
    let value: string | null = null;
    const storage = {
      getItem: jest.fn(async () => value),
      setItem: jest.fn(async () => {
        value = newer;
        throw new Error("write failed after a concurrent replacement");
      }),
      removeItem: jest.fn(async () => {
        value = null;
      }),
      compareAndRemoveItem: jest.fn(
        async (_key: string, expectedValue: string) => {
          if (value !== expectedValue) return false;
          value = null;
          return true;
        },
      ),
    };
    const client = new StorageTestClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
      storage,
    });

    await expect(client.persistTokens("failed-token")).rejects.toMatchObject({
      code: "SESSION_STORAGE_WRITE_FAILED",
    });
    expect(value).toBe(newer);
    expect(storage.removeItem).not.toHaveBeenCalled();
  });

  it("serializes cleanup and newer writes across client instances sharing storage", async () => {
    const stale = JSON.stringify({ accessToken: "stale" });
    let value: string | null = stale;
    let signalRemovalStarted!: () => void;
    let allowRemoval!: () => void;
    const removalStarted = new Promise<void>((resolve) => {
      signalRemovalStarted = resolve;
    });
    const removalAllowed = new Promise<void>((resolve) => {
      allowRemoval = resolve;
    });
    const storage = {
      getItem: jest.fn(async () => value),
      setItem: jest.fn(async (_key: string, next: string) => {
        value = next;
      }),
      removeItem: jest.fn(async () => {
        signalRemovalStarted();
        await removalAllowed;
        value = null;
      }),
    };
    const config = {
      authority: "https://auth.example.com/",
      clientId: "client-id",
      sessionStorageKey: "shared-session",
      storage,
    };
    const clearingClient = new StorageTestClient(config);
    const writingClient = new StorageTestClient(config);

    const cleanup = clearingClient.clearPersistedSessionIfUnchanged(stale);
    await removalStarted;
    const newerWrite = writingClient.persistTokens("newer-access-token");
    allowRemoval();
    await Promise.all([cleanup, newerWrite]);

    expect(value).toContain("newer-access-token");
  });

  it("rejects cookie injection and insecure SameSite=None cookies", () => {
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });

    expect(() =>
      client.buildHostOnlyCookie("sid\r\nSet-Cookie", "value"),
    ).toThrow(expect.objectContaining({ code: "INVALID_COOKIE_NAME" }));
    expect(() =>
      client.buildHostOnlyCookie("sid", "value", {
        sameSite: "None",
        secure: false,
      }),
    ).toThrow(expect.objectContaining({ code: "INVALID_COOKIE_OPTIONS" }));
    expect(() =>
      client.buildHostOnlyCookie("sid", "value", { path: "/; Domain=evil" }),
    ).toThrow(expect.objectContaining({ code: "INVALID_COOKIE_OPTIONS" }));
  });

  it("accepts authoritative exact CSP without requiring X-Frame-Options", async () => {
    jest.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("ok", {
        status: 200,
        headers: {
          "Content-Security-Policy":
            "default-src 'self'; frame-ancestors 'none'",
        },
      }),
    );
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });
    await expect(
      client.assertAuthorizationPageClickjackingProtection(),
    ).resolves.toMatchObject({
      protected: true,
      frameAncestorsPolicy: "frame-ancestors 'none'",
    });
  });

  it("does not accept a frame-ancestors substring as clickjacking protection", async () => {
    jest.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("ok", {
        status: 200,
        headers: {
          "Content-Security-Policy":
            "default-src 'self'; frame-ancestors-report 'none'",
        },
      }),
    );
    const client = new GuardhouseClient({
      authority: "https://auth.example.com/",
      clientId: "client-id",
    });

    await expect(
      client.assertAuthorizationPageClickjackingProtection(),
    ).rejects.toMatchObject({ code: "AUTH_PAGE_CLICKJACKING_RISK" });
  });
});
