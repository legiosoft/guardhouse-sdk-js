import type { AuthUrlOptions } from "./types";
import { createGuardhouseLogger } from "./debug";

type ErrorWithCauseConstructor = new (
  message?: string,
  options?: { cause?: unknown },
) => Error;

const ErrorWithCause = Error as unknown as ErrorWithCauseConstructor;

const RESERVED_AUTH_PARAM_KEYS = new Set([
  "client_id",
  "redirect_uri",
  "response_type",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "prompt",
  "audience",
  "response_mode",
  "max_age",
]);

function isAuthorizationCodeResponseType(responseType: string): boolean {
  return responseType
    .trim()
    .split(/\s+/)
    .some((value) => value === "code");
}

function isImplicitResponseType(responseType: string): boolean {
  return responseType
    .trim()
    .split(/\s+/)
    .some((value) => value === "token");
}

function isOpenIdScope(scope: string): boolean {
  return scope
    .trim()
    .split(/\s+/)
    .some((value) => value.toLowerCase() === "openid");
}

function sanitizeExtraParams(
  extraParams: Record<string, string | number | null | undefined>,
): {
  safeParams: Record<string, string | number | null | undefined>;
  blockedKeys: string[];
} {
  const safeParams: Record<string, string | number | null | undefined> = {};
  const blockedKeys: string[] = [];

  for (const [key, value] of Object.entries(extraParams)) {
    if (RESERVED_AUTH_PARAM_KEYS.has(key)) {
      blockedKeys.push(key);
      continue;
    }

    safeParams[key] = value;
  }

  return { safeParams, blockedKeys };
}

function withNonEmptyParams(
  url: URL,
  params: Record<string, string | number | null | undefined>,
): void {
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") {
      continue;
    }
    url.searchParams.set(key, String(value));
  }
}

function isLikelyUrlPolyfillIssue(error: unknown): boolean {
  if (error instanceof ReferenceError) {
    return error.message.includes("URL");
  }

  if (error instanceof TypeError) {
    const message = error.message.toLowerCase();

    return (
      message.includes("searchparams") ||
      message.includes("url is not a constructor") ||
      message.includes("failed to construct 'url'") ||
      message.includes('failed to construct "url"') ||
      message.includes("evaluating 'url.searchparams'")
    );
  }

  return false;
}

/**
 * Generate an OAuth 2.0 authorization URL.
 */
export function generateAuthUrl(options: AuthUrlOptions): string {
  if (!options || typeof options !== "object") {
    throw new Error("options is required");
  }

  const {
    authority,
    authorizationEndpoint,
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

  try {
    if (typeof authority !== "string" || authority.trim() === "") {
      throw new Error("authority is required");
    }

    if (typeof clientId !== "string" || clientId.trim() === "") {
      throw new Error("clientId is required");
    }

    if (typeof redirectUri !== "string" || redirectUri.trim() === "") {
      throw new Error("redirectUri is required");
    }

    if (isAuthorizationCodeResponseType(responseType) && !codeChallenge) {
      throw new Error(
        "codeChallenge is required when responseType includes 'code'",
      );
    }

    if (isImplicitResponseType(responseType)) {
      logger.warn(
        "The Implicit Flow (response_type=token) is deprecated in OAuth 2.1 due to security risks. Please use the Authorization Code flow with PKCE instead.",
      );
    }

    if (codeChallengeMethod.trim().toLowerCase() === "plain") {
      logger.warn(
        "codeChallengeMethod 'plain' is insecure. Use 'S256' to reduce interception risk.",
      );
    }

    if (
      isOpenIdScope(scope) &&
      (typeof nonce !== "string" || nonce.trim() === "")
    ) {
      logger.warn(
        "OIDC scope includes 'openid' but nonce is missing. Provide a nonce to reduce token replay risk.",
      );
    }

    if (typeof state !== "string" || state.trim() === "") {
      logger.warn(
        "OAuth state parameter is missing. Provide a random state value to protect against CSRF attacks.",
      );
    }

    logger.debug("Generating authorization URL", {
      authority,
      authorizationEndpoint,
      redirectUri,
      responseType,
      hasCodeChallenge: Boolean(codeChallenge),
      scope,
    });

    let url: URL;

    if (authorizationEndpoint) {
      if (/^https?:\/\//i.test(authorizationEndpoint)) {
        url = new URL(authorizationEndpoint);
      } else {
        const baseUrl = new URL(authority);
        const basePath = baseUrl.pathname.replace(/\/+$/, "");
        const endpointPath = authorizationEndpoint.replace(/^\/+/, "");

        baseUrl.pathname = `${basePath}/${endpointPath}`;
        url = baseUrl;
      }
    } else {
      url = new URL(authority);
    }

    if (url.protocol !== "https:" && url.protocol !== "http:") {
      throw new Error("Authority must use an http or https protocol.");
    }

    if (!authorizationEndpoint) {
      const basePath = url.pathname.replace(/\/+$/, "");
      url.pathname = `${basePath}/connect/authorize`;
    }

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
      const { safeParams, blockedKeys } = sanitizeExtraParams(extraParams);

      if (blockedKeys.length > 0) {
        logger.warn("Ignoring reserved OAuth keys in extraParams", {
          blockedKeys,
        });
      }

      withNonEmptyParams(url, safeParams);
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

    if (isLikelyUrlPolyfillIssue(error)) {
      throw new ErrorWithCause(
        "Global URL API is unavailable. In React Native, install and import 'react-native-url-polyfill/auto' before using generateAuthUrl.",
        { cause: error },
      );
    }

    throw error;
  }
}
