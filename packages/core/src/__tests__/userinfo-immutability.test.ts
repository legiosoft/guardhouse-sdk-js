import { GuardhouseClientBase } from "../client/base-client";

class UserInfoDecoderHarness extends GuardhouseClientBase {
  decode(value: unknown) {
    return this.decodeUserInfoResponse(value);
  }
}

describe("UserInfo response immutability", () => {
  const createDecoder = () =>
    new UserInfoDecoderHarness({
      authority: "https://auth.example.com",
      clientId: "client-id",
    });

  it("returns a detached, deeply frozen JSON snapshot", () => {
    const source = {
      sub: "user-123",
      roles: ["user"],
      scopes: ["profile"],
      preferences: {
        colors: ["blue"],
      },
    };

    const user = createDecoder().decode(source);
    source.roles.push("admin");
    source.preferences.colors.push("red");

    expect(user.roles).toEqual(["user"]);
    expect(user.preferences).toEqual({ colors: ["blue"] });
    expect(Object.isFrozen(user)).toBe(true);
    expect(Object.isFrozen(user.roles)).toBe(true);
    expect(Object.isFrozen(user.preferences)).toBe(true);
    expect(
      Object.isFrozen(
        (user.preferences as { readonly colors: readonly string[] }).colors,
      ),
    ).toBe(true);
  });

  it.each([
    { sub: "user-123", roles: "admin" },
    { sub: "user-123", scopes: ["profile", 42] },
    { sub: "user-123", extension: Number.POSITIVE_INFINITY },
    { sub: "user-123", extension: () => undefined },
  ])("rejects malformed typed or non-JSON claims", (response) => {
    expect(() => createDecoder().decode(response)).toThrow();
  });

  it("rejects cyclic extension claims", () => {
    const response: Record<string, unknown> = { sub: "user-123" };
    response["self"] = response;

    expect(() => createDecoder().decode(response)).toThrow("cyclic claim");
  });
});
