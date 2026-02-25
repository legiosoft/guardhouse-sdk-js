import { timingSafeEqual, validateAndNormalizeRedirectUri } from "../security";

import type {
  FrontChannelLogoutValidationOptions,
  RedirectResponse,
} from "./types";

export function validateFrontChannelLogoutRequest(
  requestUrl: string,
  options: FrontChannelLogoutValidationOptions,
): { issuer: string; sessionId?: string } {
  let parsed: URL;

  try {
    parsed = new URL(requestUrl);
  } catch {
    try {
      parsed = new URL(requestUrl, "http://localhost");
    } catch {
      throw new Error("Invalid logout request URL format");
    }
  }

  const issuer = parsed.searchParams.get("iss")?.trim();
  const sessionId = parsed.searchParams.get("sid")?.trim();

  if (!issuer) {
    throw new Error("Front-channel logout request is missing issuer (iss)");
  }

  if (issuer !== options.expectedIssuer.trim()) {
    throw new Error("Front-channel logout issuer validation failed");
  }

  if (options.expectedSessionId) {
    const expectedSessionId = options.expectedSessionId.trim();

    if (!sessionId) {
      throw new Error(
        "Front-channel logout request is missing session ID (sid)",
      );
    }

    if (!timingSafeEqual(sessionId, expectedSessionId)) {
      throw new Error("Front-channel logout session validation failed");
    }
  }

  return {
    issuer,
    sessionId,
  };
}

/**
 * @security If redirectUrl originates from untrusted input, always provide
 * allowedUris to prevent open redirect vulnerabilities.
 */
export function createLocationHeaderRedirect(
  redirectUrl: string,
  allowedUris?: string[],
): RedirectResponse {
  const validatedRedirect = validateAndNormalizeRedirectUri(redirectUrl);

  if (allowedUris) {
    const validatedHref = new URL(validatedRedirect).href;
    const normalizedAllowedUris = new Set(
      allowedUris.map(
        (uri) => new URL(validateAndNormalizeRedirectUri(uri)).href,
      ),
    );

    if (!normalizedAllowedUris.has(validatedHref)) {
      throw new Error("redirectUrl is not included in allowedUris");
    }
  }

  return {
    statusCode: 302,
    headers: {
      Location: validatedRedirect,
      "Cache-Control": "no-store",
      Pragma: "no-cache",
      Expires: "0",
    },
  };
}
