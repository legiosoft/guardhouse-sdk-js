import { GuardhouseError, isTransientAuthError } from "../config";

describe("authentication availability error classification", () => {
  it.each([
    ["NETWORK_ERROR", undefined, undefined, true],
    ["REQUEST_TIMEOUT", undefined, undefined, true],
    ["OIDC_METADATA_REQUEST_FAILED", undefined, true, true],
    ["OIDC_METADATA_REQUEST_FAILED", 429, undefined, true],
    ["OIDC_METADATA_REQUEST_FAILED", 408, undefined, true],
    ["server_error", 503, undefined, true],
    ["temporarily_unavailable", 400, undefined, true],
    ["server_error", 401, undefined, false],
    ["OIDC_METADATA_REQUEST_FAILED", undefined, undefined, false],
    ["OIDC_METADATA_REQUEST_FAILED", 404, undefined, false],
    ["invalid_grant", 503, true, false],
    ["invalid_token", 503, true, false],
    ["ID_TOKEN_VALIDATION_FAILED", 503, true, false],
    ["USERINFO_SUBJECT_MISMATCH", 503, true, false],
    ["OIDC_DISCOVERY_FAILED", undefined, true, false],
  ] as const)(
    "classifies %s / %s / %s as transient=%s",
    (code, statusCode, retryable, expected) => {
      expect(
        isTransientAuthError(
          new GuardhouseError("failure", code, { statusCode, retryable }),
        ),
      ).toBe(expected);
    },
  );

  it("does not classify arbitrary exceptions or nested causes as transient", () => {
    expect(isTransientAuthError(new TypeError("offline"))).toBe(false);
    expect(
      isTransientAuthError(
        new GuardhouseError("bad signature", "ID_TOKEN_VALIDATION_FAILED", {
          cause: new GuardhouseError("offline", "NETWORK_ERROR"),
        }),
      ),
    ).toBe(false);
  });
});
