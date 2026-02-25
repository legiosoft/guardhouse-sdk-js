import type { AuthUrlOptions } from "../types";
import { createGuardhouseLogger } from "../debug";
import {
  enforceNonSpoofableHostname,
  enforceSecureHttpUrl,
  isUnsafeObjectKey,
  sanitizeUrlForLogs,
  validateAndNormalizeRedirectUri,
} from "../security";

import {
  ACR_VALUE_PATTERN,
  AUTH_PARAM_KEY_PATTERN,
  CLAIMS_KEY_PATTERN,
  LOGIN_HINT_PATTERN,
  MAX_ACR_VALUE_COUNT,
  MAX_AUTH_EXTRA_PARAM_KEY_LENGTH,
  MAX_AUTH_EXTRA_PARAM_VALUE_LENGTH,
  MAX_CLAIMS_DEPTH,
  MAX_CLAIMS_KEYS,
  MAX_UI_LOCALE_COUNT,
  PROMPT_PATTERN,
  REDIRECT_LIKE_PARAM_KEYS,
  REQUEST_URI_PATTERN,
  RESERVED_AUTH_PARAM_KEYS,
  STATE_TOKEN_PATTERN,
  UI_LOCALE_PATTERN,
} from "./constants";

type ErrorWithCauseConstructor = new (
  message?: string,
  options?: { cause?: unknown },
) => Error;

const ErrorWithCause = Error as unknown as ErrorWithCauseConstructor;

function normalizeParamKey(key: string): string {
  return key.trim().toLowerCase();
}

function normalizeSpaceDelimitedValues(
  input: string | string[] | undefined,
): string[] {
  if (input === undefined) {
    return [];
  }

  if (Array.isArray(input)) {
    return input
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
  }

  return input
    .trim()
    .split(/\s+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function normalizeRequestUri(
  requestUri: string | undefined,
): string | undefined {
  if (requestUri === undefined) {
    return undefined;
  }

  const normalizedRequestUri = requestUri.trim();
  if (!normalizedRequestUri) {
    return undefined;
  }

  if (!REQUEST_URI_PATTERN.test(normalizedRequestUri)) {
    throw new Error(
      "requestUri must use https://, http://localhost, or a PAR urn:ietf:params:oauth:request_uri value",
    );
  }

  return normalizedRequestUri;
}

function normalizeAcrValues(
  acrValues: string | string[] | undefined,
): string | undefined {
  const values = normalizeSpaceDelimitedValues(acrValues);
  if (values.length === 0) {
    return undefined;
  }

  if (values.length > MAX_ACR_VALUE_COUNT) {
    throw new Error(
      `acrValues must contain no more than ${MAX_ACR_VALUE_COUNT} values`,
    );
  }

  for (const value of values) {
    if (!ACR_VALUE_PATTERN.test(value)) {
      throw new Error(`acrValues contains invalid value: "${value}"`);
    }
  }

  return values.join(" ");
}

function normalizeUiLocales(
  uiLocales: string | string[] | undefined,
): string | undefined {
  const values = normalizeSpaceDelimitedValues(uiLocales);
  if (values.length === 0) {
    return undefined;
  }

  if (values.length > MAX_UI_LOCALE_COUNT) {
    throw new Error(
      `uiLocales must contain no more than ${MAX_UI_LOCALE_COUNT} values`,
    );
  }

  for (const locale of values) {
    if (!UI_LOCALE_PATTERN.test(locale)) {
      throw new Error(`uiLocales contains invalid locale: "${locale}"`);
    }
  }

  return values.join(" ");
}

function normalizeLoginHint(loginHint: string | undefined): string | undefined {
  if (typeof loginHint !== "string") {
    return undefined;
  }

  const normalizedLoginHint = loginHint.trim();
  if (!normalizedLoginHint) {
    return undefined;
  }

  if (!LOGIN_HINT_PATTERN.test(normalizedLoginHint)) {
    throw new Error("loginHint contains unsafe characters");
  }

  return normalizedLoginHint;
}

function scopeContains(scope: string, value: string): boolean {
  return scope
    .trim()
    .split(/\s+/)
    .some((entry) => entry.toLowerCase() === value.toLowerCase());
}

function validateClaimsValue(
  value: unknown,
  depth: number,
  state: { keyCount: number },
): void {
  if (depth > MAX_CLAIMS_DEPTH) {
    throw new Error("claims object exceeds maximum depth");
  }

  if (
    value === null ||
    typeof value === "boolean" ||
    typeof value === "number" ||
    typeof value === "string"
  ) {
    return;
  }

  if (Array.isArray(value)) {
    if (value.length > 32) {
      throw new Error("claims array exceeds maximum size");
    }

    for (const entry of value) {
      validateClaimsValue(entry, depth + 1, state);
    }
    return;
  }

  if (typeof value !== "object") {
    throw new Error("claims contains unsupported value type");
  }

  for (const [key, entryValue] of Object.entries(value)) {
    if (!CLAIMS_KEY_PATTERN.test(key)) {
      throw new Error(`claims key is invalid: "${key}"`);
    }

    state.keyCount += 1;
    if (state.keyCount > MAX_CLAIMS_KEYS) {
      throw new Error("claims object contains too many keys");
    }

    validateClaimsValue(entryValue, depth + 1, state);
  }
}

function normalizeClaimsParameter(claims: unknown): string | undefined {
  if (claims === undefined) {
    return undefined;
  }

  if (claims === null || typeof claims !== "object" || Array.isArray(claims)) {
    throw new Error("claims must be a JSON object");
  }

  const state = { keyCount: 0 };
  validateClaimsValue(claims, 0, state);

  const serialized = JSON.stringify(claims);
  if (!serialized || serialized.length > 4096) {
    throw new Error("claims payload exceeds maximum size");
  }

  return serialized;
}

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
  const safeParams = Object.create(null) as Record<
    string,
    string | number | null | undefined
  >;
  const blockedKeys: string[] = [];

  for (const [key, value] of Object.entries(extraParams)) {
    const trimmedKey = key.trim();

    if (!trimmedKey) {
      continue;
    }

    if (trimmedKey.length > MAX_AUTH_EXTRA_PARAM_KEY_LENGTH) {
      blockedKeys.push(key);
      continue;
    }

    const normalizedKey = normalizeParamKey(trimmedKey);

    if (isUnsafeObjectKey(trimmedKey)) {
      blockedKeys.push(key);
      continue;
    }

    if (RESERVED_AUTH_PARAM_KEYS.has(normalizedKey)) {
      blockedKeys.push(key);
      continue;
    }

    if (REDIRECT_LIKE_PARAM_KEYS.has(normalizedKey)) {
      blockedKeys.push(key);
      continue;
    }

    if (!AUTH_PARAM_KEY_PATTERN.test(trimmedKey)) {
      blockedKeys.push(key);
      continue;
    }

    if (
      typeof value === "string" &&
      value.length > MAX_AUTH_EXTRA_PARAM_VALUE_LENGTH
    ) {
      blockedKeys.push(key);
      continue;
    }

    safeParams[trimmedKey] = value;
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
    requestUri,
    responseType = "code",
    scope = "openid profile email",
    allowOfflineAccessScope = false,
    allowAuthorizationWithoutAudience = false,
    debug,
    state,
    codeChallenge,
    codeChallengeMethod = "S256",
    nonce,
    prompt,
    acrValues,
    uiLocales,
    loginHint,
    claims,
    audience,
    responseMode,
    formPostCsrfToken,
    maxAge,
    extraParams,
  } = options;

  const logger = createGuardhouseLogger("Auth", debug);

  try {
    if (typeof authority !== "string" || authority.trim() === "") {
      throw new Error("authority is required");
    }

    if (
      typeof authorizationEndpoint !== "string" ||
      authorizationEndpoint.trim() === ""
    ) {
      throw new Error("authorizationEndpoint is required");
    }

    if (typeof clientId !== "string" || clientId.trim() === "") {
      throw new Error("clientId is required");
    }

    if (typeof state !== "string" || state.trim() === "") {
      throw new Error(
        "state is required to protect against CSRF during OAuth redirects",
      );
    }

    const normalizedState = state.trim();
    if (!STATE_TOKEN_PATTERN.test(normalizedState)) {
      throw new Error(
        "state must be a high-entropy token (16-512 URL-safe characters)",
      );
    }

    const normalizedCodeChallengeMethod = codeChallengeMethod
      .trim()
      .toUpperCase();
    const authorityUrl = new URL(authority);
    enforceSecureHttpUrl(authorityUrl, "Authority");
    enforceNonSpoofableHostname(authorityUrl, "Authority");
    const validatedRedirectUri = validateAndNormalizeRedirectUri(redirectUri);
    const normalizedRequestUri = normalizeRequestUri(requestUri);

    if (
      isAuthorizationCodeResponseType(responseType) &&
      !codeChallenge &&
      !normalizedRequestUri
    ) {
      throw new Error(
        "codeChallenge is required when responseType includes 'code' unless requestUri is used",
      );
    }

    if (
      isAuthorizationCodeResponseType(responseType) &&
      normalizedCodeChallengeMethod !== "S256"
    ) {
      throw new Error("codeChallengeMethod must be 'S256'");
    }

    if (
      isOpenIdScope(scope) &&
      (typeof nonce !== "string" || nonce.trim() === "")
    ) {
      throw new Error("nonce is required when requesting the 'openid' scope");
    }

    const normalizedNonce =
      typeof nonce === "string" && nonce.trim() !== ""
        ? nonce.trim()
        : undefined;
    const normalizedPrompt =
      typeof prompt === "string" && prompt.trim() !== ""
        ? prompt
            .trim()
            .split(/\s+/)
            .map((value) => value.toLowerCase())
            .join(" ")
        : undefined;
    const promptValues = normalizedPrompt ? normalizedPrompt.split(/\s+/) : [];
    const normalizedResponseMode =
      typeof responseMode === "string" && responseMode.trim() !== ""
        ? responseMode.trim().toLowerCase()
        : undefined;
    const normalizedAcrValues = normalizeAcrValues(acrValues);
    const normalizedUiLocales = normalizeUiLocales(uiLocales);
    const normalizedLoginHint = normalizeLoginHint(loginHint);
    const normalizedClaims = normalizeClaimsParameter(claims);
    const normalizedMaxAge =
      maxAge === undefined
        ? undefined
        : Number.isInteger(maxAge) && maxAge >= 0
          ? maxAge
          : (() => {
              throw new Error("maxAge must be a non-negative integer");
            })();

    if (normalizedPrompt) {
      if (promptValues.includes("none") && promptValues.length > 1) {
        throw new Error(
          'prompt value "none" must not be combined with other prompt values',
        );
      }

      if (!PROMPT_PATTERN.test(normalizedPrompt)) {
        throw new Error("prompt contains unsupported values");
      }
    }

    if (normalizedMaxAge !== undefined && promptValues.includes("none")) {
      throw new Error(
        "maxAge cannot be used with prompt='none' because it requires user interaction.",
      );
    }

    if (normalizedResponseMode === "form_post") {
      if (
        typeof formPostCsrfToken !== "string" ||
        formPostCsrfToken.trim() === ""
      ) {
        throw new Error(
          "formPostCsrfToken is required when responseMode is 'form_post'",
        );
      }
    }

    if (scopeContains(scope, "offline_access") && !allowOfflineAccessScope) {
      throw new Error(
        "offline_access scope requires explicit allowOfflineAccessScope=true",
      );
    }

    const requestedAudience =
      typeof audience === "string" && audience.trim() !== ""
        ? audience.trim()
        : typeof extraParams?.resource === "string" &&
            extraParams.resource.trim() !== ""
          ? extraParams.resource.trim()
          : undefined;

    if (
      isAuthorizationCodeResponseType(responseType) &&
      !requestedAudience &&
      !normalizedRequestUri &&
      !allowAuthorizationWithoutAudience
    ) {
      throw new Error(
        "audience or resource is required to request resource-specific access tokens unless requestUri is used or allowAuthorizationWithoutAudience=true",
      );
    }

    if (isImplicitResponseType(responseType)) {
      logger.warn(
        "The Implicit Flow (response_type=token) is deprecated in OAuth 2.1 due to security risks. Please use the Authorization Code flow with PKCE instead.",
      );
    }

    logger.debug("Generating authorization URL", {
      authority: sanitizeUrlForLogs(authority),
      authorizationEndpoint: sanitizeUrlForLogs(authorizationEndpoint),
      redirectUri: sanitizeUrlForLogs(validatedRedirectUri),
      responseType,
      hasRequestUri: Boolean(normalizedRequestUri),
      hasCodeChallenge: Boolean(codeChallenge),
      scope,
    });

    let url: URL;

    if (/^https?:\/\//i.test(authorizationEndpoint)) {
      url = new URL(authorizationEndpoint);
      enforceSecureHttpUrl(url, "authorizationEndpoint");
      enforceNonSpoofableHostname(url, "authorizationEndpoint");
    } else {
      const basePath = authorityUrl.pathname.replace(/\/+$/, "");
      const endpointPath = authorizationEndpoint.replace(/^\/+/, "");

      authorityUrl.pathname = `${basePath}/${endpointPath}`;
      url = authorityUrl;
    }

    enforceSecureHttpUrl(url, "Authority");
    enforceNonSpoofableHostname(url, "Authority");

    if (normalizedRequestUri) {
      withNonEmptyParams(url, {
        client_id: clientId.trim(),
        response_type: responseType,
        state: normalizedState,
        request_uri: normalizedRequestUri,
        prompt: normalizedPrompt,
        response_mode: normalizedResponseMode,
      });
    } else {
      withNonEmptyParams(url, {
        client_id: clientId.trim(),
        redirect_uri: validatedRedirectUri,
        response_type: responseType,
        scope,
        state: normalizedState,
        code_challenge: codeChallenge,
        code_challenge_method: codeChallenge
          ? normalizedCodeChallengeMethod
          : undefined,
        nonce: normalizedNonce,
        prompt: normalizedPrompt,
        acr_values: normalizedAcrValues,
        ui_locales: normalizedUiLocales,
        login_hint: normalizedLoginHint,
        claims: normalizedClaims,
        audience: requestedAudience,
        response_mode: normalizedResponseMode,
        max_age: normalizedMaxAge,
        guardhouse_form_post_csrf:
          normalizedResponseMode === "form_post"
            ? formPostCsrfToken?.trim()
            : undefined,
      });
    }

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
