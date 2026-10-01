import { GuardhouseError } from "../config";
import { generateAuthUrl } from "../auth";
import type {
  AuthorizationTransaction,
  CreatedAuthorizationRequest,
  CreateAuthorizationRequestOptions,
} from "../auth";
import { generateNonce, generatePKCE, generateState } from "../pkce";
import {
  enforceNonSpoofableHostname,
  enforceSecureHttpUrl,
  isUnsafeObjectKey,
  sanitizeUrlForLogs,
  timingSafeEqual,
  validateAndNormalizeRedirectUri,
  validateRedirectUri,
  validateResourceIndicator,
} from "../security";

import {
  DISCOVERY_ENDPOINT_KEYS,
  MAX_TOKEN_PARAM_KEY_LENGTH,
  MAX_TOKEN_PARAM_VALUE_LENGTH,
  SAFE_COOKIE_NAME_PATTERN,
  TOKEN_PARAM_KEY_PATTERN,
} from "./constants";
import { GuardhouseClientToken } from "./token-client";
import type {
  AccountLinkingContext,
  AuthorizationPageProtectionResult,
  DynamicClientRegistrationResponse,
  HomeRealmDiscoveryResult,
  LogoutRequest,
  OpenIdConfiguration,
  PostMessageTarget,
  PushedAuthorizationRequest,
  SecureCookieOptions,
} from "./types";

const FORBIDDEN_REDIRECT_URI_CHARS = new Set([
  "<",
  ">",
  '"',
  "'",
  "`",
  "\\",
  "\r",
  "\n",
]);
const LOGOUT_STATE_PATTERN = /^[A-Za-z0-9_-]+$/;
const PAR_TRANSACTION_BOUND_PARAMETER_KEYS = new Set([
  "client_id",
  "response_type",
  "redirect_uri",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
  "nonce",
  "response_mode",
  "audience",
  "resource",
  "prompt",
  "max_age",
  "acr_values",
  "request",
  "request_uri",
]);

export class GuardhouseClientAdvanced extends GuardhouseClientToken {
  private readonly discoveryCacheContext = new Map<
    string,
    { authority: string; clientId: string }
  >();
  private latestDiscoveryMetadata: OpenIdConfiguration | null = null;
  private readonly pushedAuthorizationBindings = new Map<
    string,
    { state: string; expiresAt: number; authorizationEndpoint: string }
  >();

  private decodeDiscoveryMetadata(value: unknown): OpenIdConfiguration {
    const data = this.requireRecord(
      value,
      "Discovery response",
      "INVALID_DISCOVERY_RESPONSE",
    );
    if (typeof data["issuer"] !== "string" || data["issuer"].trim() === "") {
      throw new GuardhouseError(
        "Discovery response must contain issuer",
        "INVALID_DISCOVERY_RESPONSE",
      );
    }
    for (const key of DISCOVERY_ENDPOINT_KEYS) {
      if (
        data[key] !== undefined &&
        (typeof data[key] !== "string" || data[key].trim() === "")
      ) {
        throw new GuardhouseError(
          `Discovery metadata field ${key} is invalid`,
          "INVALID_DISCOVERY_RESPONSE",
        );
      }
    }
    for (const key of [
      "authorization_response_iss_parameter_supported",
      "request_parameter_supported",
      "request_uri_parameter_supported",
      "require_request_uri_registration",
    ]) {
      if (data[key] !== undefined && typeof data[key] !== "boolean") {
        throw new GuardhouseError(
          `Discovery metadata field ${key} is invalid`,
          "INVALID_DISCOVERY_RESPONSE",
        );
      }
    }
    for (const key of [
      "response_types_supported",
      "response_modes_supported",
      "grant_types_supported",
      "scopes_supported",
      "code_challenge_methods_supported",
    ]) {
      const field = data[key];
      if (
        field !== undefined &&
        (!Array.isArray(field) ||
          field.some((entry) => typeof entry !== "string"))
      ) {
        throw new GuardhouseError(
          `Discovery metadata field ${key} is invalid`,
          "INVALID_DISCOVERY_RESPONSE",
        );
      }
    }
    return Object.freeze({ ...data }) as OpenIdConfiguration;
  }

  private requireDiscoveredEndpoint(
    metadata: OpenIdConfiguration,
    key: string,
    feature: string,
  ): string {
    const endpoint = metadata[key];
    if (typeof endpoint !== "string" || endpoint.trim() === "") {
      throw new GuardhouseError(
        `The configured issuer does not advertise ${key}`,
        "UNSUPPORTED_FEATURE",
        { feature },
      );
    }
    return endpoint;
  }

  async createAuthorizationRequest(
    options: CreateAuthorizationRequestOptions,
  ): Promise<CreatedAuthorizationRequest> {
    if (!options || typeof options !== "object") {
      throw new GuardhouseError(
        "Authorization request options are required",
        "INVALID_REQUEST",
      );
    }
    const redirectUri = validateAndNormalizeRedirectUri(options.redirectUri);
    const scope = this.requireNonEmptyString(options.scope, "scope");
    const responseMode = options.responseMode ?? "query";
    if (responseMode !== "query" && responseMode !== "form_post") {
      throw new GuardhouseError(
        "responseMode must be query or form_post",
        "INVALID_REQUEST",
      );
    }
    if (
      options.maxAgeSeconds !== undefined &&
      (!Number.isInteger(options.maxAgeSeconds) || options.maxAgeSeconds < 0)
    ) {
      throw new GuardhouseError(
        "maxAgeSeconds must be a non-negative integer",
        "INVALID_REQUEST",
      );
    }

    const unvalidatedResources =
      options.resource === undefined
        ? []
        : typeof options.resource === "string"
          ? [options.resource]
          : [...options.resource];
    if (unvalidatedResources.length > 16) {
      throw new GuardhouseError(
        "resource must contain no more than 16 values",
        "INVALID_REQUEST",
      );
    }
    let requestedResources: string[];
    try {
      requestedResources = unvalidatedResources.map((resource) =>
        validateResourceIndicator(resource),
      );
    } catch (error) {
      throw new GuardhouseError(
        error instanceof Error
          ? error.message
          : "resource values must be absolute URIs without fragments",
        "INVALID_REQUEST",
        { cause: error },
      );
    }
    const normalizeAssuranceValues = (
      values: readonly string[] | undefined,
      fieldName: string,
    ): readonly string[] => {
      if (values === undefined) return Object.freeze([]);
      if (
        !Array.isArray(values) ||
        values.length > 16 ||
        values.some(
          (value) =>
            typeof value !== "string" ||
            value.trim() === "" ||
            value.length > 128 ||
            !/^[A-Za-z0-9._:/-]+$/.test(value),
        )
      ) {
        throw new GuardhouseError(
          `${fieldName} contains invalid values`,
          "INVALID_REQUEST",
        );
      }
      return Object.freeze(values.map((value) => value.trim()));
    };
    const requiredAcrValues = normalizeAssuranceValues(
      options.requiredAcrValues,
      "requiredAcrValues",
    );
    const requiredAmrValues = normalizeAssuranceValues(
      options.requiredAmrValues,
      "requiredAmrValues",
    );

    let applicationState = options.applicationState;
    if (applicationState !== undefined) {
      try {
        const serialized = JSON.stringify(applicationState);
        if (serialized === undefined || serialized.length > 65_536) {
          throw new Error(
            "application state is not serializable or is too large",
          );
        }
        applicationState = JSON.parse(serialized) as unknown;
      } catch (error) {
        throw new GuardhouseError(
          "applicationState must be JSON-serializable and no larger than 64 KiB",
          "INVALID_REQUEST",
          { cause: error },
        );
      }
    }

    const metadata = await this.discoverOpenIdConfiguration();
    const authorizationEndpoint = metadata["authorization_endpoint"];
    if (
      typeof authorizationEndpoint !== "string" ||
      authorizationEndpoint.trim() === ""
    ) {
      throw new GuardhouseError(
        "Discovery metadata does not advertise an authorization endpoint",
        "AUTHORIZATION_ENDPOINT_UNSUPPORTED",
      );
    }

    const [{ codeVerifier, codeChallenge }, state, nonce] = await Promise.all([
      generatePKCE(),
      generateState(),
      generateNonce(),
    ]);
    const createdAt = Date.now();
    const transaction: AuthorizationTransaction = Object.freeze({
      version: 2,
      issuer: this.issuer,
      clientId: this.config.clientId.trim(),
      redirectUri,
      state,
      codeVerifier,
      codeChallenge,
      nonce,
      requestedScope: scope,
      requestedAudience: options.audience?.trim() || undefined,
      requestedResources: Object.freeze(
        [...requestedResources],
      ),
      requiredAcrValues,
      requiredAmrValues,
      prompt: options.prompt?.trim() || undefined,
      maxAgeSeconds: options.maxAgeSeconds,
      responseMode,
      applicationState,
      createdAt,
      expiresAt: createdAt + 10 * 60 * 1000,
      issRequired:
        metadata["authorization_response_iss_parameter_supported"] === true,
    });

    const authorizationUrl = new URL(
      generateAuthUrl({
        authority: this.issuer,
        authorizationEndpoint,
        clientId: this.config.clientId,
        redirectUri,
        scope,
        allowOfflineAccessScope: options.allowOfflineAccessScope,
        allowAuthorizationWithoutAudience:
          options.audiencePolicy === "oidc-optional",
        responseType: "code",
        state,
        codeChallenge,
        codeChallengeMethod: "S256",
        nonce,
        prompt: transaction.prompt,
        acrValues: [...transaction.requiredAcrValues],
        audience: transaction.requestedAudience,
        resource: transaction.requestedResources,
        responseMode,
        maxAge: transaction.maxAgeSeconds,
      }),
    );
    return { authorizationUrl: authorizationUrl.toString(), transaction };
  }

  getSecureInputAttributes(
    inputKind: "otp" | "mfa" | "password" = "otp",
  ): Record<string, string> {
    const attributes: Record<string, string> = {
      autocomplete: "off",
      autocapitalize: "off",
      autocorrect: "off",
      spellcheck: "false",
    };

    if (inputKind === "otp" || inputKind === "mfa") {
      attributes["inputmode"] = "numeric";
      attributes["maxlength"] = "12";
    }

    if (inputKind === "password") {
      attributes["autocomplete"] = "new-password";
    }

    return attributes;
  }

  buildHostOnlyCookie(
    name: string,
    value: string,
    options: SecureCookieOptions = {},
  ): string {
    const normalizedName = this.requireNonEmptyString(name, "cookie name");
    const normalizedValue = this.requireNonEmptyString(value, "cookie value");

    if (!SAFE_COOKIE_NAME_PATTERN.test(normalizedName)) {
      throw new GuardhouseError(
        "cookie name contains invalid characters",
        "INVALID_COOKIE_NAME",
      );
    }

    if (Object.prototype.hasOwnProperty.call(options, "domain")) {
      throw new GuardhouseError(
        "Domain attribute is not allowed for SDK-managed cookies; use host-only cookies",
        "UNSAFE_COOKIE_DOMAIN",
      );
    }

    const runtimeSecure = (options as { secure?: unknown }).secure;
    if (runtimeSecure !== undefined && typeof runtimeSecure !== "boolean") {
      throw new GuardhouseError(
        "secure must be a boolean",
        "INVALID_COOKIE_OPTIONS",
      );
    }
    const secure = runtimeSecure ?? true;
    const runtimeSameSite = (options as { sameSite?: unknown }).sameSite;
    if (runtimeSameSite !== undefined && typeof runtimeSameSite !== "string") {
      throw new GuardhouseError(
        "sameSite must be a string",
        "INVALID_COOKIE_OPTIONS",
      );
    }
    const sameSite = runtimeSameSite ?? "Lax";
    const runtimePath = (options as { path?: unknown }).path;
    if (runtimePath !== undefined && typeof runtimePath !== "string") {
      throw new GuardhouseError(
        "path must be a string",
        "INVALID_COOKIE_OPTIONS",
      );
    }
    const path = runtimePath?.trim() || "/";
    if (!/^(?:Strict|Lax|None)$/.test(sameSite)) {
      throw new GuardhouseError(
        "SameSite must be Strict, Lax, or None",
        "INVALID_COOKIE_OPTIONS",
      );
    }
    if (!path.startsWith("/") || /[^\x20-\x7E]|[;\\]/.test(path)) {
      throw new GuardhouseError(
        "Cookie path is invalid",
        "INVALID_COOKIE_OPTIONS",
      );
    }
    if (sameSite === "None" && !secure) {
      throw new GuardhouseError(
        "SameSite=None requires Secure",
        "INVALID_COOKIE_OPTIONS",
      );
    }
    if (normalizedName.startsWith("__Host-") && (!secure || path !== "/")) {
      throw new GuardhouseError(
        "__Host- cookies require Secure and Path=/",
        "INVALID_COOKIE_OPTIONS",
      );
    }

    const attributes = [
      `${normalizedName}=${encodeURIComponent(normalizedValue)}`,
      `Path=${path}`,
      `SameSite=${sameSite}`,
    ];

    if (secure) {
      attributes.push("Secure");
    }

    if (options.maxAgeSeconds !== undefined) {
      if (
        !Number.isSafeInteger(options.maxAgeSeconds) ||
        options.maxAgeSeconds < 0 ||
        options.maxAgeSeconds > 34_560_000
      ) {
        throw new GuardhouseError(
          "maxAgeSeconds must be a non-negative integer",
          "INVALID_COOKIE_OPTIONS",
        );
      }
      attributes.push(`Max-Age=${options.maxAgeSeconds}`);
    }

    return attributes.join("; ");
  }

  assertAccountLinkingPreconditions(context: AccountLinkingContext): void {
    this.assertRecentUserInteraction("Account linking");

    if (!context.primarySessionActive || !context.secondarySessionActive) {
      throw new GuardhouseError(
        "Both accounts must have active authenticated sessions before linking",
        "ACCOUNT_LINKING_REQUIRES_TWO_ACTIVE_SESSIONS",
      );
    }

    const primarySubject = this.requireNonEmptyString(
      context.primarySubject,
      "primarySubject",
    );
    const secondarySubject = this.requireNonEmptyString(
      context.secondarySubject,
      "secondarySubject",
    );

    if (timingSafeEqual(primarySubject, secondarySubject)) {
      throw new GuardhouseError(
        "Account linking subjects must be distinct identities",
        "INVALID_ACCOUNT_LINKING_SUBJECTS",
      );
    }
  }

  resolveHomeRealmIssuer(
    loginHint: string,
    trustedIssuersByDomain: Record<string, string>,
  ): HomeRealmDiscoveryResult {
    const normalizedLoginHint = this.requireNonEmptyString(
      loginHint,
      "loginHint",
    );
    const atIndex = normalizedLoginHint.lastIndexOf("@");

    if (atIndex <= 0 || atIndex === normalizedLoginHint.length - 1) {
      throw new GuardhouseError(
        "loginHint must be a valid email address",
        "INVALID_LOGIN_HINT",
      );
    }

    const domain = normalizedLoginHint.slice(atIndex + 1).toLowerCase();
    const trustedIssuer = trustedIssuersByDomain[domain];

    if (!trustedIssuer) {
      throw new GuardhouseError(
        `No trusted issuer is configured for domain ${domain}`,
        "UNTRUSTED_HOME_REALM_DOMAIN",
      );
    }

    let issuerUrl: URL;
    try {
      issuerUrl = new URL(trustedIssuer);
      enforceSecureHttpUrl(issuerUrl, "Home realm issuer");
      enforceNonSpoofableHostname(issuerUrl, "Home realm issuer");
    } catch (error) {
      throw new GuardhouseError(
        "Configured home realm issuer URL is invalid",
        "INVALID_HOME_REALM_ISSUER",
        { cause: error },
      );
    }

    return {
      emailDomain: domain,
      issuer: issuerUrl.toString(),
    };
  }

  async createPushedAuthorizationRequest(
    transactionValue: AuthorizationTransaction,
    additionalParameters: Readonly<Record<string, string>> = {},
  ): Promise<PushedAuthorizationRequest> {
    const transaction = this.restoreAuthorizationTransaction(transactionValue);
    if (
      !additionalParameters ||
      typeof additionalParameters !== "object" ||
      Array.isArray(additionalParameters)
    ) {
      throw new GuardhouseError(
        "additionalParameters must be an object",
        "INVALID_REQUEST",
      );
    }
    const body = new URLSearchParams({
      client_id: transaction.clientId,
      response_type: "code",
      redirect_uri: transaction.redirectUri,
      scope: transaction.requestedScope,
      state: transaction.state,
      code_challenge: transaction.codeChallenge,
      code_challenge_method: "S256",
      nonce: transaction.nonce,
      response_mode: transaction.responseMode,
    });
    if (transaction.requestedAudience) {
      body.set("audience", transaction.requestedAudience);
    }
    for (const resource of transaction.requestedResources) {
      body.append("resource", resource);
    }
    if (transaction.prompt) body.set("prompt", transaction.prompt);
    if (transaction.maxAgeSeconds !== undefined) {
      body.set("max_age", String(transaction.maxAgeSeconds));
    }
    if (transaction.requiredAcrValues.length > 0) {
      body.set("acr_values", transaction.requiredAcrValues.join(" "));
    }

    for (const [key, value] of Object.entries(additionalParameters)) {
      const normalizedKey = key.trim();
      const normalizedValue = value.trim();
      const normalizedKeyLower = normalizedKey.toLowerCase();

      if (!normalizedKey || !normalizedValue) {
        continue;
      }

      if (PAR_TRANSACTION_BOUND_PARAMETER_KEYS.has(normalizedKeyLower)) {
        throw new GuardhouseError(
          `Invalid PAR parameter: ${normalizedKey}`,
          "INVALID_REQUEST",
        );
      }

      if (isUnsafeObjectKey(normalizedKey)) {
        throw new GuardhouseError(
          `Invalid PAR parameter: ${normalizedKey}`,
          "INVALID_REQUEST",
        );
      }

      if (
        normalizedKey.length > MAX_TOKEN_PARAM_KEY_LENGTH ||
        normalizedValue.length > MAX_TOKEN_PARAM_VALUE_LENGTH ||
        !TOKEN_PARAM_KEY_PATTERN.test(normalizedKey)
      ) {
        throw new GuardhouseError(
          `Invalid PAR parameter: ${normalizedKey}`,
          "INVALID_REQUEST",
        );
      }

      body.set(normalizedKey, normalizedValue);
    }

    const metadata = await this.discoverOpenIdConfiguration();
    const discoveredParEndpoint = this.requireDiscoveredEndpoint(
      metadata,
      "pushed_authorization_request_endpoint",
      "par",
    );

    this.logger.debug("Submitting PAR request", {
      endpoint: sanitizeUrlForLogs(discoveredParEndpoint),
      params: this.sanitizeParBodyForLogs(body),
    });

    const response = await this.fetch(discoveredParEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      skipDpopProof: true,
    });

    const data = this.requireRecord(
      response.data,
      "PAR response",
      "INVALID_PAR_RESPONSE",
    );

    if (
      typeof data["request_uri"] !== "string" ||
      data["request_uri"].trim() === ""
    ) {
      throw new GuardhouseError(
        "PAR response does not include request_uri",
        "INVALID_PAR_RESPONSE",
      );
    }

    if (/\s/.test(data["request_uri"])) {
      throw new GuardhouseError(
        "PAR response contains invalid request_uri",
        "INVALID_PAR_RESPONSE",
      );
    }

    if (
      typeof data["expires_in"] !== "number" ||
      !Number.isInteger(data["expires_in"]) ||
      data["expires_in"] <= 0
    ) {
      throw new GuardhouseError(
        "PAR response contains invalid expires_in",
        "INVALID_PAR_RESPONSE",
      );
    }

    const requestUri = data["request_uri"];
    if (this.pushedAuthorizationBindings.has(requestUri)) {
      throw new GuardhouseError(
        "PAR request_uri was already issued",
        "PAR_REQUEST_URI_REPLAY",
      );
    }
    const expiresIn = data["expires_in"];
    const authorizationEndpoint = this.requireDiscoveredEndpoint(
      metadata,
      "authorization_endpoint",
      "authorization",
    );
    this.pushedAuthorizationBindings.set(requestUri, {
      state: body.get("state")!,
      expiresAt: Date.now() + expiresIn * 1000,
      authorizationEndpoint,
    });
    return {
      requestUri,
      expiresIn,
    } as PushedAuthorizationRequest;
  }

  buildPushedAuthorizationUrl(
    request: PushedAuthorizationRequest,
    transactionValue: AuthorizationTransaction,
  ): string {
    const transaction = this.restoreAuthorizationTransaction(transactionValue);
    const binding = this.pushedAuthorizationBindings.get(request.requestUri);
    if (!binding || binding.expiresAt <= Date.now()) {
      this.pushedAuthorizationBindings.delete(request.requestUri);
      throw new GuardhouseError(
        "PAR request_uri is unknown, expired, or already consumed",
        "PAR_REQUEST_URI_INVALID",
      );
    }
    if (binding.state !== transaction.state) {
      throw new GuardhouseError(
        "PAR request_uri is not bound to this authorization transaction",
        "PAR_TRANSACTION_MISMATCH",
      );
    }
    this.pushedAuthorizationBindings.delete(request.requestUri);
    const url = new URL(binding.authorizationEndpoint);
    url.search = "";
    url.hash = "";
    url.searchParams.set("client_id", this.config.clientId.trim());
    url.searchParams.set("request_uri", request.requestUri);
    return url.toString();
  }

  private buildLogoutUrlFromMetadata(request: LogoutRequest): string {
    const discoveredEndpoint =
      this.latestDiscoveryMetadata?.["end_session_endpoint"];
    if (
      typeof discoveredEndpoint !== "string" ||
      discoveredEndpoint.trim() === ""
    ) {
      throw new GuardhouseError(
        "The configured issuer does not advertise end_session_endpoint",
        "UNSUPPORTED_FEATURE",
        { feature: "logout" },
      );
    }
    const logoutEndpoint = discoveredEndpoint;
    const logoutUrl = new URL(this.buildRequestUrl(logoutEndpoint));

    if (request.postLogoutRedirectUri) {
      const validatedRedirect = validateAndNormalizeRedirectUri(
        request.postLogoutRedirectUri,
      );

      this.assertAllowedPostLogoutRedirect(validatedRedirect);
      logoutUrl.searchParams.set("post_logout_redirect_uri", validatedRedirect);
    }

    if (request.idTokenHint) {
      const originUrl = new URL(this.baseURL);

      if (originUrl.protocol !== "https:") {
        throw new GuardhouseError(
          "id_token_hint can only be used with HTTPS authorities",
          "INSECURE_ID_TOKEN_HINT_USAGE",
        );
      }

      logoutUrl.searchParams.set("id_token_hint", request.idTokenHint);
    }

    if (request.state) {
      const normalizedState = this.requireNonEmptyString(
        request.state,
        "state",
      );

      // Align logout state validation with the SDK's Base64URL-safe state
      // generation while still enforcing a strict, URI-safe allowlist.
      if (
        normalizedState.length > 128 ||
        !LOGOUT_STATE_PATTERN.test(normalizedState)
      ) {
        throw new GuardhouseError(
          "state must be 1-128 characters and contain only letters, numbers, hyphens, and underscores",
          "INVALID_REQUEST",
        );
      }

      logoutUrl.searchParams.set("state", normalizedState);
    }

    if (request.federated) {
      logoutUrl.searchParams.set("federated", "true");
    }

    return logoutUrl.toString();
  }

  async buildLogoutUrl(request: LogoutRequest = {}): Promise<string> {
    await this.discoverOpenIdConfiguration();
    return this.buildLogoutUrlFromMetadata(request);
  }

  async prepareSharedDeviceLogout(
    request: LogoutRequest = {},
  ): Promise<string> {
    const logoutUrl = await this.buildLogoutUrl({
      ...request,
      federated: request.federated ?? true,
    });
    await this.clearSessionState();
    return logoutUrl;
  }

  async discoverOpenIdConfiguration(
    discoveryEndpoint = "/.well-known/openid-configuration",
  ): Promise<OpenIdConfiguration> {
    const discoveryUrl = new URL(this.buildRequestUrl(discoveryEndpoint));
    const authorityUrl = new URL(this.baseURL);
    const cacheKey = discoveryUrl.toString();
    const cacheContext = {
      authority: this.issuer,
      clientId: this.config.clientId,
    };

    if (discoveryUrl.origin !== authorityUrl.origin) {
      throw new GuardhouseError(
        "Discovery endpoint must share the configured authority origin",
        "UNSAFE_DISCOVERY_URL",
      );
    }

    if (this.discoveryCacheTtlMs > 0) {
      const cachedEntry = this.discoveryCache.get(cacheKey);
      if (cachedEntry) {
        const cachedContext = this.discoveryCacheContext.get(cacheKey);
        const contextMatches =
          cachedContext?.authority === cacheContext.authority &&
          cachedContext.clientId === cacheContext.clientId;

        if (cachedEntry.expiresAt > Date.now() && contextMatches) {
          this.latestDiscoveryMetadata = { ...cachedEntry.data };
          return { ...cachedEntry.data };
        }

        this.discoveryCache.delete(cacheKey);
        this.discoveryCacheContext.delete(cacheKey);
      }
    }

    const response = await this.fetch(discoveryUrl.toString(), {
      method: "GET",
      skipAuthHeader: true,
      skipDpopProof: true,
      cacheMode: "no-store",
      headers: {
        "Cache-Control": "no-store",
        Pragma: "no-cache",
      },
    });

    const discoveryData = this.decodeDiscoveryMetadata(response.data);

    this.assertTrustedDiscoveryMetadata(discoveryData, authorityUrl);

    const issuer = discoveryData["issuer"];
    const normalizedIssuer =
      typeof issuer === "string" ? new URL(issuer).href : "";
    if (normalizedIssuer !== this.issuer) {
      throw new GuardhouseError(
        "Discovery issuer must exactly match configured authority",
        "ISSUER_AUTHORITY_MISMATCH",
      );
    }

    this.logger.debug("Fetched OIDC discovery metadata", {
      endpoint: sanitizeUrlForLogs(discoveryUrl.toString()),
      metadata: this.sanitizeDiscoveryMetadataForLogs(discoveryData),
      vendorSpecificKeysRedacted: Object.keys(discoveryData).filter((key) =>
        key.toLowerCase().startsWith("x-"),
      ).length,
    });

    if (this.discoveryCacheTtlMs > 0) {
      this.discoveryCache.set(cacheKey, {
        expiresAt: Date.now() + this.discoveryCacheTtlMs,
        data: discoveryData,
      });
      this.discoveryCacheContext.set(cacheKey, cacheContext);
    }

    this.latestDiscoveryMetadata = { ...discoveryData };

    return { ...discoveryData };
  }

  openAuthorizationPopup(
    authorizationUrl: string,
    popupName = "guardhouse_oauth_popup",
    popupFeatures = "width=500,height=700",
  ): unknown {
    const runtime = globalThis as typeof globalThis & {
      window?: {
        open?: (url?: string, target?: string, features?: string) => unknown;
      };
    };

    const openFn = runtime.window?.open;
    if (typeof openFn !== "function") {
      throw new GuardhouseError(
        "window.open is unavailable in this environment",
        "POPUP_UNAVAILABLE",
      );
    }

    const sanitizedFeatureTokens = popupFeatures
      .split(",")
      .map((token) => token.trim())
      .filter((token) => token.length > 0)
      .filter((token) => {
        const featureName = token.split("=")[0]?.trim().toLowerCase();
        return featureName !== "noopener" && featureName !== "noreferrer";
      });

    const featureSet = [
      ...sanitizedFeatureTokens,
      "noopener",
      "noreferrer",
    ].join(",");
    const popup = openFn(authorizationUrl, popupName, featureSet);

    if (typeof popup === "object" && popup !== null) {
      try {
        (popup as { opener?: unknown }).opener = null;
      } catch {
        // noop
      }
    }

    return popup;
  }

  private sanitizeDiscoveryMetadataForLogs(
    discoveryData: Record<string, unknown>,
  ): Record<string, string> {
    const safeMetadata: Record<string, string> = {};

    const issuer = discoveryData["issuer"];
    if (typeof issuer === "string" && issuer.trim() !== "") {
      safeMetadata["issuer"] = this.sanitizeDiscoveryUrlForLogs(issuer);
    }

    for (const key of DISCOVERY_ENDPOINT_KEYS) {
      const value = discoveryData[key];
      if (typeof value === "string" && value.trim() !== "") {
        safeMetadata[key] = this.sanitizeDiscoveryUrlForLogs(value);
      }
    }

    return safeMetadata;
  }

  private sanitizeDiscoveryUrlForLogs(urlValue: string): string {
    try {
      const parsed = new URL(urlValue);
      parsed.search = "";
      parsed.hash = "";
      parsed.username = "";
      parsed.password = "";
      return `${parsed.origin}${parsed.pathname}`;
    } catch {
      return "[REDACTED]";
    }
  }

  private sanitizeParBodyForLogs(
    body: URLSearchParams,
  ): Record<string, string> {
    const redactedParams: Record<string, string> = {};

    for (const [key, value] of body.entries()) {
      const normalizedKey = key.toLowerCase();
      if (
        normalizedKey.includes("secret") ||
        normalizedKey.includes("token") ||
        normalizedKey.includes("assertion") ||
        normalizedKey === "code_verifier"
      ) {
        redactedParams[key] = "[REDACTED]";
      } else {
        redactedParams[key] = value;
      }
    }

    return redactedParams;
  }

  postMessageToPopup(
    targetWindow: PostMessageTarget | null | undefined,
    message: unknown,
    targetOrigin: string,
  ): void {
    if (!targetWindow || typeof targetWindow.postMessage !== "function") {
      throw new GuardhouseError(
        "targetWindow must expose a postMessage function",
        "POPUP_UNAVAILABLE",
      );
    }

    const normalizedTargetOrigin =
      this.normalizePostMessageTargetOrigin(targetOrigin);

    targetWindow.postMessage(message, normalizedTargetOrigin);
  }

  async registerClient(
    metadata: Record<string, unknown>,
    initialAccessToken: string,
  ): Promise<DynamicClientRegistrationResponse> {
    this.assertRecentUserInteraction("Client registration");

    if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
      throw new GuardhouseError(
        "metadata must be a JSON object",
        "INVALID_CLIENT_METADATA",
      );
    }

    const normalizedInitialAccessToken = this.requireNonEmptyString(
      initialAccessToken,
      "initialAccessToken",
    );

    const { safeMetadata, blockedKeys } =
      this.sanitizeClientRegistrationMetadata(metadata);

    if (blockedKeys.length > 0) {
      this.logger.warn("Ignoring unsafe client metadata keys", {
        blockedKeys,
      });
    }

    const redirectUris = safeMetadata["redirect_uris"];
    if (Array.isArray(redirectUris)) {
      for (const redirectUri of redirectUris) {
        if (typeof redirectUri !== "string") {
          throw new GuardhouseError(
            "redirect_uris entries must be strings",
            "INVALID_CLIENT_METADATA",
          );
        }

        if (redirectUri !== redirectUri.trim()) {
          throw new GuardhouseError(
            "redirect_uris entries must not contain surrounding whitespace",
            "INVALID_CLIENT_METADATA",
          );
        }

        for (const character of redirectUri) {
          if (FORBIDDEN_REDIRECT_URI_CHARS.has(character)) {
            throw new GuardhouseError(
              "redirect_uris contains forbidden characters",
              "INVALID_CLIENT_METADATA",
            );
          }
        }

        validateRedirectUri(redirectUri);
      }
    }

    const metadataDocument = await this.discoverOpenIdConfiguration();
    const discoveredRegistrationEndpoint = this.requireDiscoveredEndpoint(
      metadataDocument,
      "registration_endpoint",
      "dynamic_client_registration",
    );
    const response = await this.fetch(discoveredRegistrationEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(safeMetadata),
      token: normalizedInitialAccessToken,
    });

    const registration = this.requireRecord(
      response.data,
      "Client registration response",
      "INVALID_REGISTRATION_RESPONSE",
    );
    if (
      typeof registration["client_id"] !== "string" ||
      registration["client_id"].trim() === ""
    ) {
      throw new GuardhouseError(
        "Client registration response must contain client_id",
        "INVALID_REGISTRATION_RESPONSE",
      );
    }
    for (const key of [
      "client_secret",
      "registration_access_token",
      "registration_client_uri",
    ] as const) {
      if (
        registration[key] !== undefined &&
        typeof registration[key] !== "string"
      ) {
        throw new GuardhouseError(
          `Client registration response field ${key} is invalid`,
          "INVALID_REGISTRATION_RESPONSE",
        );
      }
    }
    return { ...registration } as DynamicClientRegistrationResponse;
  }

  async assertAuthorizationPageClickjackingProtection(
    authorizationEndpoint = "/connect/authorize",
  ): Promise<AuthorizationPageProtectionResult> {
    const response = await this.fetch(authorizationEndpoint, {
      method: "GET",
      skipAuthHeader: true,
      skipDpopProof: true,
      headers: {
        Accept: "text/html,application/xhtml+xml",
      },
    });

    const xFrameOptions =
      response.headers.get("X-Frame-Options")?.trim() ?? undefined;
    const cspHeader =
      response.headers.get("Content-Security-Policy")?.trim() ?? undefined;
    const frameAncestorsPolicy = cspHeader
      ? this.getFrameAncestorsDirective(cspHeader)
      : undefined;

    const warnings: string[] = [];

    const validXFrameOptions =
      typeof xFrameOptions === "string" &&
      /^(?:DENY|SAMEORIGIN)$/i.test(xFrameOptions);
    if (frameAncestorsPolicy) {
      if (!/^frame-ancestors\s+'(?:none|self)'$/i.test(frameAncestorsPolicy)) {
        warnings.push(
          "CSP frame-ancestors directive is not an exact 'none' or 'self' policy",
        );
      }
    } else if (!validXFrameOptions) {
      warnings.push("No enforceable clickjacking policy was found");
    }

    if (warnings.length > 0) {
      this.logger.error(
        "Authorization page is missing anti-clickjacking headers",
        {
          endpoint: sanitizeUrlForLogs(
            this.buildRequestUrl(authorizationEndpoint),
          ),
          warnings,
        },
      );

      throw new GuardhouseError(
        "Authorization page protection check failed: missing clickjacking defense headers",
        "AUTH_PAGE_CLICKJACKING_RISK",
      );
    }

    return {
      protected: true,
      xFrameOptions,
      frameAncestorsPolicy,
      warnings,
    };
  }
}
