import { generatePKCE, OAuthPKCEManager } from "../pkce";

describe("pkce secure helpers", () => {
  it("generates S256 PKCE pair", async () => {
    const pair = await generatePKCE();

    expect(pair.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(pair.codeChallenge.length).toBeGreaterThan(20);
  });

  it("stores and consumes code_verifier using one-time handles", async () => {
    const manager = new OAuthPKCEManager();
    const verifier = "a".repeat(43);
    const handle = await manager.stashCodeVerifier(verifier);

    expect(typeof handle).toBe("string");
    expect(handle.length).toBeGreaterThan(10);

    expect(manager.consumeCodeVerifier(handle)).toBe(verifier);
    expect(() => manager.consumeCodeVerifier(handle)).toThrow(
      "already consumed",
    );
  });

  it("rejects invalid code_verifier values", async () => {
    const manager = new OAuthPKCEManager();

    await expect(manager.stashCodeVerifier("short")).rejects.toThrow(
      "codeVerifier must be 43-128",
    );
  });

  it("expires verifier handles based on TTL", async () => {
    const nowSpy = jest.spyOn(Date, "now");

    try {
      const manager = new OAuthPKCEManager({ codeVerifierTtlMs: 10 });

      nowSpy.mockReturnValue(1_000);
      const handle = await manager.stashCodeVerifier("a".repeat(43));

      nowSpy.mockReturnValue(1_020);
      expect(() => manager.consumeCodeVerifier(handle)).toThrow(
        "already consumed",
      );
    } finally {
      nowSpy.mockRestore();
    }
  });

  it("evicts the oldest verifier when capacity is exceeded", async () => {
    const manager = new OAuthPKCEManager({ maxStoredCodeVerifiers: 1 });

    const firstHandle = await manager.stashCodeVerifier("a".repeat(43));
    const secondHandle = await manager.stashCodeVerifier("b".repeat(43));

    expect(() => manager.consumeCodeVerifier(firstHandle)).toThrow(
      "already consumed",
    );
    expect(manager.consumeCodeVerifier(secondHandle)).toBe("b".repeat(43));
  });
});
