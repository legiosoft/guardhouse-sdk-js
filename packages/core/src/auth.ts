import type { AuthUrlOptions } from "./types";

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

  return url.toString();
}
