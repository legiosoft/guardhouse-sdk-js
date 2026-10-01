import { createGuardhouseLogger } from "../debug";

describe("debug credential redaction", () => {
  afterEach(() => jest.restoreAllMocks());

  it.each([
    ["Bearer " + "credential".repeat(1000), "[REDACTED]"],
    ["header." + "credential".repeat(1000) + ".signature", "[REDACTED]"],
    ["refresh_token=" + "credential".repeat(1000), "refresh_token=[REDACTED]"],
    [
      "https://issuer.test/logout?id_token_hint=" + "credential".repeat(1000),
      "https://issuer.test/logout?id_token_hint=[REDACTED]",
    ],
  ])(
    "redacts a credential before shortening a long log message",
    (input, expected) => {
      const output = jest.spyOn(console, "error").mockImplementation(() => {});
      createGuardhouseLogger("test", true).error(new Error(input));
      expect(output.mock.calls[0]?.[1]).toMatchObject({ message: expected });
    },
  );
});
