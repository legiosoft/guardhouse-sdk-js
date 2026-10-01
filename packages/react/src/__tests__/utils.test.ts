import {
  verifyIdToken as verifyCoreIdToken,
  type VerifiedIdToken,
} from "@guardhouse/core";
import {
  SessionStorageAdapter,
  getCurrentReturnTo,
  normalizeReturnTo,
  removeQueryParams,
  validateIdToken,
} from "../utils";

jest.mock("@guardhouse/core", () => ({
  verifyIdToken: jest.fn(),
}));

const mockedVerifyIdToken = jest.mocked(verifyCoreIdToken);

describe("SessionStorageAdapter atomic comparisons", () => {
  const values = new Map<string, string>();

  beforeEach(() => {
    values.clear();
    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {},
    });
    Object.defineProperty(globalThis, "sessionStorage", {
      configurable: true,
      value: {
        getItem: (key: string) => values.get(key) ?? null,
        setItem: (key: string, value: string) => values.set(key, value),
        removeItem: (key: string) => values.delete(key),
      },
    });
  });

  afterEach(() => {
    Reflect.deleteProperty(globalThis, "window");
    Reflect.deleteProperty(globalThis, "sessionStorage");
  });

  it("performs the comparison and removal synchronously", () => {
    const adapter = new SessionStorageAdapter();
    values.set("session", "old");

    expect(adapter.compareAndRemoveItem("session", "old")).toBe(true);
    expect(values.has("session")).toBe(false);

    values.set("session", "newer");
    expect(adapter.compareAndRemoveItem("session", "old")).toBe(false);
    expect(values.get("session")).toBe("newer");
  });

  it("performs the comparison and replacement synchronously", () => {
    const adapter = new SessionStorageAdapter();
    values.set("session", "old");

    expect(adapter.compareAndSetItem("session", "old", "refreshed")).toBe(true);
    expect(values.get("session")).toBe("refreshed");

    values.set("session", "newer");
    expect(adapter.compareAndSetItem("session", "old", "stale")).toBe(false);
    expect(values.get("session")).toBe("newer");
  });
});

describe("validateIdToken", () => {
  it("delegates to cryptographic core verification and returns its payload", async () => {
    const payload = {
      sub: "user-1",
      iss: "https://tenant.guardhouse.test",
      aud: "react-client",
      nonce: "nonce-1",
      exp: 2_000_000_000,
      iat: 1_700_000_000,
    };
    mockedVerifyIdToken.mockResolvedValue({
      payload,
      header: { alg: "RS256", kid: "key-1" },
      identity: {
        issuer: "https://tenant.guardhouse.test",
        clientId: "react-client",
        subject: "user-1",
        audiences: ["react-client"],
        authorizedParty: null,
        issuedAt: 1_700_000_000,
        expiresAt: 2_000_000_000,
        nonce: "nonce-1",
        authTime: null,
        acr: null,
        amr: [],
        sessionId: null,
      },
    } as unknown as VerifiedIdToken);

    await expect(
      validateIdToken(
        "signed-id-token",
        "nonce-1",
        "https://tenant.guardhouse.test",
        "react-client",
      ),
    ).resolves.toBe(payload);
    expect(mockedVerifyIdToken).toHaveBeenCalledWith("signed-id-token", {
      authority: "https://tenant.guardhouse.test",
      clientId: "react-client",
      purpose: "authorization_code",
      nonce: "nonce-1",
    });
  });
});

describe("redirect URL safety", () => {
  let currentUrl: URL;
  let replaceState: jest.Mock;

  beforeEach(() => {
    currentUrl = new URL("https://app.test/orders?status=open#current-section");
    replaceState = jest.fn((_state, _title, value: string) => {
      currentUrl = new URL(value, currentUrl);
    });

    Object.defineProperty(globalThis, "window", {
      configurable: true,
      value: {
        location: {
          get href() {
            return currentUrl.toString();
          },
          get origin() {
            return currentUrl.origin;
          },
          get pathname() {
            return currentUrl.pathname;
          },
          get search() {
            return currentUrl.search;
          },
          get hash() {
            return currentUrl.hash;
          },
        },
        history: {
          state: null,
          replaceState,
        },
      },
    });
  });

  afterEach(() => {
    Reflect.deleteProperty(globalThis, "window");
  });

  it("preserves path, query, and fragment as a same-origin relative return target", () => {
    expect(getCurrentReturnTo()).toBe("/orders?status=open#current-section");
    expect(
      normalizeReturnTo("https://app.test/orders?status=open#current-section"),
    ).toBe("/orders?status=open#current-section");
  });

  it.each([
    "https://evil.test/steal",
    "//evil.test/steal",
    "https://user@app.test/private",
    "/\\evil.test/steal",
    "/safe\u0000unsafe",
  ])("rejects unsafe return target %s", (returnTo) => {
    expect(() => normalizeReturnTo(returnTo)).toThrow(/returnTo/);
  });

  it("removes OAuth parameters from both channels without dropping application state", () => {
    currentUrl = new URL(
      "https://app.test/callback?code=abc&state=oauth-state&tab=profile#state=fragment-state&access_token=forged&section=billing",
    );

    removeQueryParams();

    expect(replaceState).toHaveBeenCalledTimes(1);
    expect(currentUrl.toString()).toBe(
      "https://app.test/callback?tab=profile#section=billing",
    );
  });

  it("applies the same lexical return-target checks during SSR", () => {
    Reflect.deleteProperty(globalThis, "window");

    expect(normalizeReturnTo("/orders?status=open#current")).toBe(
      "/orders?status=open#current",
    );
    expect(() => normalizeReturnTo("//evil.test/steal")).toThrow(/returnTo/);
    expect(() => normalizeReturnTo("/\\evil.test/steal")).toThrow(/returnTo/);
    expect(() => normalizeReturnTo("/safe\u0000unsafe")).toThrow(/returnTo/);
  });
});
