import type { AuthUrlOptions } from "./types";
import { createGuardhouseLogger } from "./debug";

function withNonEmptyParams(
  url: URL,
  params: Record<string, string | number | undefined>,
): void {
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") {
      continue;
    }
    url.searchParams.set(key, String(value));
  }
}

/**
 * Generate an OAuth 2.0 authorization URL.
 */
export function generateAuthUrl(options: AuthUrlOptions): string {
  const {
    authority,
    clientId,
    redirectUri,
    responseType = "code",
    scope = "openid profile email",
    debug,
    state,
    codeChallenge,
    codeChallengeMethod = "S256",
    nonce,
    prompt,
    audience,
    responseMode,
    maxAge,
    extraParams,
  } = options;

  const logger = createGuardhouseLogger("Auth", debug);

  logger.debug("Generating authorization URL", {
    authority,
    redirectUri,
    responseType,
    hasCodeChallenge: Boolean(codeChallenge),
    scope,
  });

  try {
    const url = new URL(authority);
    const basePath = url.pathname.replace(/\/+$/, "");
    url.pathname = `${basePath}/connect/authorize`;
    url.search = "";

    withNonEmptyParams(url, {
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: responseType,
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallenge ? codeChallengeMethod : undefined,
      nonce,
      prompt,
      audience,
      response_mode: responseMode,
      max_age: maxAge,
    });

    if (extraParams) {
      withNonEmptyParams(url, extraParams);
    }

    const authorizationUrl = url.toString();

    logger.debug("Generated authorization URL", {
      queryParamCount: Array.from(url.searchParams.keys()).length,
      hasExtraParams: Boolean(extraParams),
    });

    return authorizationUrl;
  } catch (error) {
    logger.error("Failed to generate authorization URL", {
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
}
