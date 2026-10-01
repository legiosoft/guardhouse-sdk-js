import { GuardhouseClient } from "../client";
import type { RefreshOAuthTokenOptions } from "../client/types";

const config = {
  authority: "https://refresh-scope.test/",
  clientId: "client",
  scope: "read write",
};
const tokens = {
  access_token: "access",
  refresh_token: "rotated",
  token_type: "Bearer",
  expires_in: 3600,
};
const response = (body: unknown) =>
  new Response(JSON.stringify(body), {
    headers: { "Content-Type": "application/json" },
  });

afterEach(() => jest.restoreAllMocks());

it("uses typed refresh parameters while keeping reserved extension parameters blocked", async () => {
  const fetch = jest
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(response(tokens));
  const client = new GuardhouseClient(config);
  const result = await client.refreshOAuthToken("refresh", {
    grantedScope: "read write",
    scope: "  read\tread ",
    audience: " urn:api ",
    requestParameters: {
      scope: "admin",
      audience: "urn:untrusted",
      resource: "urn:untrusted",
      grant_type: "client_credentials",
      client_id: "other",
      refresh_token: "other",
      client_secret: "other",
      code: "other",
      code_verifier: "other",
      redirect_uri: "https://other.test/",
      extension: "preserved",
    },
  });
  expect(
    Object.fromEntries(
      new URLSearchParams(fetch.mock.calls[0][1]?.body as string),
    ),
  ).toEqual({
    grant_type: "refresh_token",
    refresh_token: "refresh",
    client_id: "client",
    scope: "read",
    audience: "urn:api",
    extension: "preserved",
  });
  expect(result.scope).toBe("read");
  expect((await client.getSessionState())?.scope).toBe("read");
});

it("keeps existing callers without typed scope/audience unchanged", async () => {
  const fetch = jest
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(response(tokens));
  const client = new GuardhouseClient(config);
  const result = await client.refreshOAuthToken("refresh", {
    grantedScope: "read write",
    requestParameters: { scope: "admin", audience: "urn:untrusted" },
  });
  const body = new URLSearchParams(fetch.mock.calls[0][1]?.body as string);
  expect(body.has("scope")).toBe(false);
  expect(body.has("audience")).toBe(false);
  expect(result.scope).toBeUndefined();
});

it.each([
  [{ scope: "admin", grantedScope: "read write" }, "SCOPE_ESCALATION_DETECTED"],
  [{ scope: "Read", grantedScope: "read write" }, "SCOPE_ESCALATION_DETECTED"],
  [{ scope: "read" }, "INVALID_REQUEST"],
  [{ scope: "read", grantedScope: " " }, "INVALID_REQUEST"],
  [{ scope: "" }, "INVALID_REQUEST"],
  [{ scope: " \t " }, "INVALID_REQUEST"],
  [
    { scope: "a".repeat(4097), grantedScope: "a".repeat(4097) },
    "INVALID_REQUEST",
  ],
  [{ audience: "a".repeat(4097) }, "INVALID_REQUEST"],
  [{ audience: " " }, "INVALID_REQUEST"],
  [{ scope: 12 }, "INVALID_REQUEST"],
] as const)(
  "rejects invalid typed refresh parameters before HTTP (case %#)",
  async (options, code) => {
    const fetch = jest.spyOn(globalThis, "fetch");
    const client = new GuardhouseClient(config);
    await expect(
      client.refreshOAuthToken("refresh", options as RefreshOAuthTokenOptions),
    ).rejects.toMatchObject({ code });
    expect(fetch).not.toHaveBeenCalled();
  },
);

it("still rejects returned scopes beyond the explicit request even when within the original grant", async () => {
  jest
    .spyOn(globalThis, "fetch")
    .mockResolvedValue(response({ ...tokens, scope: "read write" }));
  const client = new GuardhouseClient(config);
  await expect(
    client.refreshOAuthToken("refresh", {
      grantedScope: "read write",
      scope: "read",
    }),
  ).rejects.toMatchObject({ code: "SCOPE_ESCALATION_DETECTED" });
  expect(await client.getSessionState()).toBeNull();
});

it.each(["scope", "audience"] as const)(
  "does not coalesce different typed refresh %s values",
  async (field) => {
    let release!: (response: Response) => void;
    const pending = new Promise<Response>((resolve) => {
      release = resolve;
    });
    const fetch = jest.spyOn(globalThis, "fetch").mockReturnValue(pending);
    const client = new GuardhouseClient(config);
    const options = {
      grantedScope: "read write",
      scope: "read write",
      audience: "urn:api",
    };
    const first = client.refreshOAuthToken("refresh", options);
    await expect(
      client.refreshOAuthToken("refresh", {
        ...options,
        [field]: field === "scope" ? "read" : "urn:other",
      }),
    ).rejects.toMatchObject({ code: "REFRESH_OPERATION_CONFLICT" });
    release(response(tokens));
    await expect(first).resolves.toHaveProperty("scope", "read write");
    expect(fetch).toHaveBeenCalledTimes(1);
  },
);
