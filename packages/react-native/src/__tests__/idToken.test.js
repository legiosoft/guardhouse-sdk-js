const mockVerify = jest.fn();
const mockVerifierConstructor = jest.fn().mockImplementation(() => ({
  verify: mockVerify,
}));

jest.mock("@guardhouse/core", () => ({
  OidcIdTokenVerifier: mockVerifierConstructor,
}));

const {
  IdTokenValidator,
  createRedirectUriDescriptor,
  matchesRedirectUri,
} = require("../utils/idToken");

describe("React Native ID-token validation", () => {
  beforeEach(() => {
    mockVerify.mockReset();
    mockVerifierConstructor.mockClear();
  });

  it("fails closed when insecure claims-only validation is requested", () => {
    expect(
      () =>
        new IdTokenValidator({
          authority: "https://auth.example.com",
          clientId: "mobile-client",
          allowInsecureIdTokenValidation: true,
        }),
    ).toThrow("no longer supported");
    expect(mockVerifierConstructor).not.toHaveBeenCalled();
  });

  it("delegates cryptographic and authentication-policy checks to Core", async () => {
    const verifiedIdToken = {
      header: { alg: "RS256", kid: "key-1" },
      payload: { sub: "user-1" },
      identity: { subject: "user-1" },
    };
    mockVerify.mockResolvedValueOnce(verifiedIdToken);

    const validator = new IdTokenValidator({
      authority: "https://auth.example.com/tenant",
      clientId: "mobile-client",
      jwksUri: "https://keys.example.com/jwks",
      requiredAcrValues: ["urn:mfa", "urn:mfa"],
      requiredAmrValues: ["pwd", " pwd "],
    });

    await expect(validator.validate("signed-token", " nonce ")).resolves.toBe(
      verifiedIdToken,
    );
    expect(mockVerifierConstructor).toHaveBeenCalledWith({
      authority: "https://auth.example.com/tenant",
      clientId: "mobile-client",
      jwksUri: "https://keys.example.com/jwks",
    });
    expect(mockVerify).toHaveBeenCalledWith("signed-token", {
      purpose: "authorization_code",
      nonce: "nonce",
      requiredAcrValues: ["urn:mfa"],
      requiredAmrValues: ["pwd"],
    });
  });

  it("requires a nonce for authorization ID-token validation", async () => {
    const validator = new IdTokenValidator({
      authority: "https://auth.example.com",
      clientId: "mobile-client",
    });

    await expect(validator.validate("signed-token", " ")).rejects.toThrow(
      "nonce is required",
    );
    expect(mockVerify).not.toHaveBeenCalled();
  });

  it("matches the configured redirect target without trusting query input", () => {
    const expected = createRedirectUriDescriptor(
      "com.example.guardhouse://callback",
    );

    expect(
      matchesRedirectUri(
        "com.example.guardhouse://callback?code=abc&state=state",
        expected,
      ),
    ).toBe(true);
    expect(
      matchesRedirectUri(
        "com.attacker.guardhouse://callback?code=abc",
        expected,
      ),
    ).toBe(false);
    expect(matchesRedirectUri("not a URL", expected)).toBe(false);
  });
});
