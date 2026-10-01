import { timingSafeEqual, validateAndNormalizeRedirectUri } from "../security";

import type {
  FrontChannelLogoutValidationOptions,
  RedirectResponse,
} from "./types";
import { canonicalizeIssuer } from "./transaction";

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

  const issuers = parsed.searchParams.getAll("iss");
  const sessionIds = parsed.searchParams.getAll("sid");
  if (issuers.length > 1 || sessionIds.length > 1) {
    throw new Error("Front-channel logout request contains duplicate parameters");
  }
  const issuer = issuers[0];
  const sessionId = sessionIds[0];

  if (!issuer) {
    throw new Error("Front-channel logout request is missing issuer (iss)");
  }

  let canonicalIssuer: string;
  let expectedIssuer: string;
  try {
    canonicalIssuer = canonicalizeIssuer(issuer);
    expectedIssuer = canonicalizeIssuer(options.expectedIssuer);
  } catch {
    throw new Error("Front-channel logout issuer validation failed");
  }
  if (canonicalIssuer !== expectedIssuer) {
    throw new Error("Front-channel logout issuer validation failed");
  }

  if (options.expectedSessionId) {
    const expectedSessionId = options.expectedSessionId;

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
    issuer: canonicalIssuer,
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
