import type { AuthUrlOptions } from "./types";
import { createGuardhouseLogger } from "./debug";
import {
  enforceNonSpoofableHostname,
  enforceSecureHttpUrl,
  isUnsafeObjectKey,
  sanitizeUrlForLogs,
  timingSafeEqual,
  validateRedirectUri,
} from "./security";

type ErrorWithCauseConstructor = new (
  message?: string,
  options?: { cause?: unknown },
) => Error;

const ErrorWithCause = Error as unknown as ErrorWithCauseConstructor;

const RESERVED_AUTH_PARAM_KEYS = new Set([
  "client_id",
  "redirect_uri",
  "request_uri",
  "response_type",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "prompt",
  "acr_values",
  "ui_locales",
  "login_hint",
  "claims",
  "audience",
  "response_mode",
  "max_age",
  "guardhouse_form_post_csrf",
]);

const REDIRECT_LIKE_PARAM_KEYS = new Set([
  "redirect",
  "redirect_to",
  "return_to",
  "returnurl",
  "next",
  "continue",
  "url",
  "destination",
  "callback",
  "callback_url",
  "post_login_redirect",
  "post_auth_redirect",
]);

const AUTH_PARAM_KEY_PATTERN = /^[A-Za-z0-9._~-]+$/;
const STATE_TOKEN_PATTERN = /^[A-Za-z0-9._~-]{16,512}$/;
const REQUEST_URI_PATTERN = /^[A-Za-z][A-Za-z0-9+.-]*:[^\s]{1,2048}$/;
const ACR_VALUE_PATTERN = /^[A-Za-z0-9._:/-]{1,128}$/;
const UI_LOCALE_PATTERN = /^[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$/;
const LOGIN_HINT_PATTERN = /^[^\s<>"'`]{1,256}$/;
const CLAIMS_KEY_PATTERN = /^[A-Za-z0-9_:.\-]{1,64}$/;
const MAX_TRACKED_STATE_TOKENS = 1024;
const MAX_AUTH_EXTRA_PARAM_KEY_LENGTH = 128;
const MAX_AUTH_EXTRA_PARAM_VALUE_LENGTH = 4096;
const MAX_STATE_BINDINGS = 1024;
const MAX_UI_LOCALE_COUNT = 10;
const MAX_ACR_VALUE_COUNT = 10;
const MAX_CLAIMS_DEPTH = 5;
const MAX_CLAIMS_KEYS = 128;
const SILENT_AUTH_ERROR_CODES = new Set([
  "interaction_required",
  "login_required",
  "consent_required",
  "account_selection_required",
]);
const OAUTH_CALLBACK_SENSITIVE_KEYS = new Set([
  "code",
  "state",
  "error",
  "error_description",
  "error_uri",
  "access_token",
  "id_token",
  "refresh_token",
  "token_type",
  "expires_in",
  "scope",
  "session_state",
]);
const AUTHORIZATION_URL_SENSITIVE_KEYS = new Set([
  "state",
  "nonce",
  "code_challenge",
  "code_challenge_method",
  "id_token_hint",
  "guardhouse_form_post_csrf",
]);
const UNSAFE_FRAGMENT_VALUE_PATTERN = /<|>|javascript:|data:/i;
const MAX_CALLBACK_URL_LENGTH = 8192;
const consumedStateTokens: string[] = [];
const consumedStateSet = new Set<string>();
const stateBindingVault = new Map<string, string>();
const stateBindingOrder: string[] = [];

export interface OAuthCallbackResult {
  code?: string;
  state?: string;
  error?: string;
  errorDescription?: string;
  errorUri?: string;
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
  tokenType?: string;
  expiresIn?: number;
  scope?: string;
  params: Record<string, string>;
  sanitizedUrl: string;
}

export interface FrontChannelLogoutValidationOptions {
  expectedIssuer: string;
  expectedSessionId?: string;
}

export interface RedirectResponse {
  statusCode: 302;
  headers: {
    Location: string;
    "Cache-Control": string;
  };
}

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
    throw new Error("requestUri must be an absolute URI without spaces");
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

function bytesToBase64Url(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes)
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");
  }

  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  if (typeof btoa !== "function") {
    throw new Error("Base64 encoding is unavailable in this environment");
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

function createStateBindingHandle(): string {
  const webCrypto = globalThis.crypto;

  if (!webCrypto || typeof webCrypto.getRandomValues !== "function") {
    throw new Error("Secure random generator is unavailable for state binding");
  }

  const randomBytes = new Uint8Array(18);
  webCrypto.getRandomValues(randomBytes);

  return bytesToBase64Url(randomBytes);
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

export function validateAndConsumeState(
  expectedState: string,
  returnedState: string,
): void {
  const logger = createGuardhouseLogger("Auth");
  const normalizedExpectedState = expectedState.trim();
  const normalizedReturnedState = returnedState.trim();

  if (!normalizedExpectedState || !normalizedReturnedState) {
    logger.error("OAuth state validation failed", {
      reason: "missing_expected_or_returned_state",
      hasExpectedState: Boolean(normalizedExpectedState),
      hasReturnedState: Boolean(normalizedReturnedState),
    });
    throw new Error("Expected and returned OAuth state are both required");
  }

  if (consumedStateSet.has(normalizedExpectedState)) {
    logger.error("OAuth state validation failed", {
      reason: "replayed_state_detected",
    });
    throw new Error("OAuth state was already used and cannot be reused");
  }

  if (!timingSafeEqual(normalizedExpectedState, normalizedReturnedState)) {
    logger.error("OAuth state validation failed", {
      reason: "state_mismatch",
      expectedLength: normalizedExpectedState.length,
      returnedLength: normalizedReturnedState.length,
    });
    throw new Error("OAuth state mismatch");
  }

  consumedStateTokens.push(normalizedExpectedState);
  consumedStateSet.add(normalizedExpectedState);

  if (consumedStateTokens.length > MAX_TRACKED_STATE_TOKENS) {
    const evicted = consumedStateTokens.shift();
    if (evicted) {
      consumedStateSet.delete(evicted);
    }
  }
}

export function stashExpectedState(expectedState: string): string {
  const normalizedState = expectedState.trim();

  if (!STATE_TOKEN_PATTERN.test(normalizedState)) {
    throw new Error("expectedState must be a valid high-entropy state token");
  }

  const handle = createStateBindingHandle();
  stateBindingVault.set(handle, normalizedState);
  stateBindingOrder.push(handle);

  if (stateBindingOrder.length > MAX_STATE_BINDINGS) {
    const evictedHandle = stateBindingOrder.shift();
    if (evictedHandle) {
      stateBindingVault.delete(evictedHandle);
    }
  }

  return handle;
}

export function consumeStateBinding(
  stateHandle: string,
  returnedState: string,
): void {
  const normalizedHandle = stateHandle.trim();
  const expectedState = stateBindingVault.get(normalizedHandle);

  if (!expectedState) {
    throw new Error("State handle is invalid or has already been consumed");
  }

  stateBindingVault.delete(normalizedHandle);

  const orderIndex = stateBindingOrder.indexOf(normalizedHandle);
  if (orderIndex >= 0) {
    stateBindingOrder.splice(orderIndex, 1);
  }

  validateAndConsumeState(expectedState, returnedState);
}

export function validateFormPostCsrfToken(
  expectedToken: string,
  actualToken: string,
): void {
  const normalizedExpected = expectedToken.trim();
  const normalizedActual = actualToken.trim();

  if (!normalizedExpected || !normalizedActual) {
    throw new Error("Both expected and actual CSRF tokens are required");
  }

  if (!timingSafeEqual(normalizedExpected, normalizedActual)) {
    throw new Error("form_post CSRF token validation failed");
  }
}

export function validateFrontChannelLogoutRequest(
  requestUrl: string,
  options: FrontChannelLogoutValidationOptions,
): { issuer: string; sessionId?: string } {
  const parsed = new URL(requestUrl);
  const issuer = parsed.searchParams.get("iss")?.trim();
  const sessionId = parsed.searchParams.get("sid")?.trim();

  if (!issuer) {
    throw new Error("Front-channel logout request is missing issuer (iss)");
  }

  if (!timingSafeEqual(issuer, options.expectedIssuer.trim())) {
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

export function isSilentAuthenticationError(errorCode: string): boolean {
  return SILENT_AUTH_ERROR_CODES.has(errorCode.trim());
}

function mergeCallbackParams(url: URL): URLSearchParams {
  const merged = new URLSearchParams();
  const seenKeys = new Set<string>();

  const appendUnique = (params: URLSearchParams): void => {
    const keys = new Set(params.keys());

    for (const key of keys) {
      const values = params.getAll(key);
      const normalizedKey = key.toLowerCase();

      if (values.length > 1 || seenKeys.has(normalizedKey)) {
        throw new Error(
          `OAuth callback contains duplicate parameter values for "${key}"`,
        );
      }

      const value = values[0] ?? "";
      merged.set(key, value);
      seenKeys.add(normalizedKey);
    }
  };

  appendUnique(url.searchParams);

  const rawHash = url.hash.replace(/^#/, "");
  const hasParamLikeHash = rawHash.includes("=") || rawHash.includes("&");

  if (hasParamLikeHash) {
    const hashParams = new URLSearchParams(rawHash);
    for (const value of hashParams.values()) {
      if (UNSAFE_FRAGMENT_VALUE_PATTERN.test(value)) {
        throw new Error("OAuth callback fragment contains unsafe content");
      }
    }

    appendUnique(hashParams);
  }

  return merged;
}

export function sanitizeOAuthCallbackUrl(callbackUrl: string): string {
  const url = new URL(callbackUrl);

  for (const key of OAUTH_CALLBACK_SENSITIVE_KEYS) {
    url.searchParams.delete(key);
  }

  const rawHash = url.hash.replace(/^#/, "");
  const hasParamLikeHash = rawHash.includes("=") || rawHash.includes("&");

  if (hasParamLikeHash) {
    const hashParams = new URLSearchParams(rawHash);
    for (const key of OAUTH_CALLBACK_SENSITIVE_KEYS) {
      hashParams.delete(key);
    }

    const sanitizedHash = hashParams.toString();
    url.hash = sanitizedHash ? `#${sanitizedHash}` : "";
  }

  return url.toString();
}

export function sanitizeAuthorizationUrlForHistory(authUrl: string): string {
  const parsed = new URL(authUrl);

  for (const key of AUTHORIZATION_URL_SENSITIVE_KEYS) {
    parsed.searchParams.delete(key);
  }

  return parsed.toString();
}

export function createLocationHeaderRedirect(
  redirectUrl: string,
): RedirectResponse {
  const validatedRedirect = validateRedirectUri(redirectUrl).toString();

  return {
    statusCode: 302,
    headers: {
      Location: validatedRedirect,
      "Cache-Control": "no-store",
    },
  };
}

export function parseOAuthCallbackUrl(
  callbackUrl: string,
): OAuthCallbackResult {
  if (typeof callbackUrl !== "string" || callbackUrl.trim() === "") {
    throw new Error("callbackUrl is required");
  }

  if (callbackUrl.length > MAX_CALLBACK_URL_LENGTH) {
    throw new Error("callbackUrl exceeds maximum supported length");
  }

  const parsedUrl = new URL(callbackUrl);
  const mergedParams = mergeCallbackParams(parsedUrl);

  const params = Object.create(null) as Record<string, string>;
  mergedParams.forEach((value, key) => {
    if (isUnsafeObjectKey(key)) {
      throw new Error(`OAuth callback contains unsafe parameter key "${key}"`);
    }

    params[key] = value;
  });

  const expiresInRaw = mergedParams.get("expires_in");
  let expiresIn: number | undefined;
  if (expiresInRaw !== null && expiresInRaw !== "") {
    const parsedExpiresIn = Number(expiresInRaw);
    if (!Number.isFinite(parsedExpiresIn) || parsedExpiresIn < 0) {
      throw new Error("OAuth callback contains an invalid expires_in value");
    }
    expiresIn = parsedExpiresIn;
  }

  return {
    code: mergedParams.get("code") ?? undefined,
    state: mergedParams.get("state") ?? undefined,
    error: mergedParams.get("error") ?? undefined,
    errorDescription: mergedParams.get("error_description") ?? undefined,
    errorUri: mergedParams.get("error_uri") ?? undefined,
    accessToken: mergedParams.get("access_token") ?? undefined,
    idToken: mergedParams.get("id_token") ?? undefined,
    refreshToken: mergedParams.get("refresh_token") ?? undefined,
    tokenType: mergedParams.get("token_type") ?? undefined,
    expiresIn,
    scope: mergedParams.get("scope") ?? undefined,
    params,
    sanitizedUrl: sanitizeOAuthCallbackUrl(callbackUrl),
  };
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
    const validatedRedirectUri = validateRedirectUri(redirectUri).toString();
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
      const promptValues = normalizedPrompt.split(/\s+/);
      if (promptValues.includes("none") && promptValues.length > 1) {
        throw new Error(
          'prompt value "none" must not be combined with other prompt values',
        );
      }
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
      authorizationEndpoint: authorizationEndpoint
        ? sanitizeUrlForLogs(authorizationEndpoint)
        : undefined,
      redirectUri: sanitizeUrlForLogs(validatedRedirectUri),
      responseType,
      hasRequestUri: Boolean(normalizedRequestUri),
      hasCodeChallenge: Boolean(codeChallenge),
      scope,
    });

    let url: URL;

    if (authorizationEndpoint) {
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
    } else {
      url = authorityUrl;
    }

    enforceSecureHttpUrl(url, "Authority");
    enforceNonSpoofableHostname(url, "Authority");

    if (!authorizationEndpoint) {
      const basePath = url.pathname.replace(/\/+$/, "");
      url.pathname = `${basePath}/connect/authorize`;
    }

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
