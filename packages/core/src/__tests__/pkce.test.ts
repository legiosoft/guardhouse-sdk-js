import { consumeCodeVerifier, generatePKCE, stashCodeVerifier } from "../pkce";

describe("pkce secure helpers", () => {
  it("generates S256 PKCE pair", async () => {
    const pair = await generatePKCE();

    expect(pair.codeVerifier.length).toBeGreaterThanOrEqual(43);
    expect(pair.codeChallenge.length).toBeGreaterThan(20);
  });

  it("stores and consumes code_verifier using one-time handles", async () => {
    const verifier = "a".repeat(43);
    const handle = await stashCodeVerifier(verifier);

    expect(typeof handle).toBe("string");
    expect(handle.length).toBeGreaterThan(10);

    expect(consumeCodeVerifier(handle)).toBe(verifier);
    expect(() => consumeCodeVerifier(handle)).toThrow("already consumed");
  });

  it("rejects invalid code_verifier values", async () => {
    await expect(stashCodeVerifier("short")).rejects.toThrow(
      "codeVerifier must be 43-128",
    );
  });
});
