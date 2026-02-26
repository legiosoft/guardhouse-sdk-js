import { GuardhouseError } from "../config";
import {
  enforceNonSpoofableHostname,
  enforceSecureHttpUrl,
  isUnsafeObjectKey,
  sanitizeUrlForLogs,
  timingSafeEqual,
  validateAndNormalizeRedirectUri,
  validateRedirectUri,
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
  HomeRealmDiscoveryResult,
  LogoutRequest,
  PostMessageTarget,
  PushedAuthorizationRequestResult,
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

export class GuardhouseClientAdvanced extends GuardhouseClientToken {
  private readonly discoveryCacheContext = new Map<
    string,
    { authority: string; clientId: string }
  >();

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

    if (typeof options.domain === "string" && options.domain.trim() !== "") {
      throw new GuardhouseError(
        "Domain attribute is not allowed for SDK-managed cookies; use host-only cookies",
        "UNSAFE_COOKIE_DOMAIN",
      );
    }

    const secure = options.secure ?? true;
    const sameSite = options.sameSite ?? "Strict";
    const path = options.path?.trim() || "/";

    const attributes = [
      `${normalizedName}=${encodeURIComponent(normalizedValue)}`,
      `Path=${path}`,
      `SameSite=${sameSite}`,
    ];

    if (secure) {
      attributes.push("Secure");
    }

    if (
      options.maxAgeSeconds !== undefined &&
      Number.isInteger(options.maxAgeSeconds) &&
      options.maxAgeSeconds >= 0
    ) {
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
    params: Record<string, string>,
    parEndpoint = "/connect/par",
  ): Promise<PushedAuthorizationRequestResult> {
    if (!params || typeof params !== "object" || Array.isArray(params)) {
      throw new GuardhouseError("params must be an object", "INVALID_REQUEST");
    }

    const body = new URLSearchParams();

    for (const [key, value] of Object.entries(params)) {
      const normalizedKey = key.trim();
      const normalizedValue = value.trim();
      const normalizedKeyLower = normalizedKey.toLowerCase();

      if (!normalizedKey || !normalizedValue) {
        continue;
      }

      if (
        normalizedKeyLower === "request" ||
        normalizedKeyLower === "request_uri"
      ) {
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

    if (!this.config.clientSecret && !body.has("client_id")) {
      body.set("client_id", this.config.clientId);
    }

    this.logger.debug("Submitting PAR request", {
      endpoint: sanitizeUrlForLogs(this.buildRequestUrl(parEndpoint)),
      params: this.sanitizeParBodyForLogs(body),
    });

    const response = await this.fetch(parEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: body.toString(),
      skipDpopProof: true,
    });

    const data = response.data as {
      request_uri?: string;
      expires_in?: number;
    };

    if (
      typeof data?.request_uri !== "string" ||
      data.request_uri.trim() === ""
    ) {
      throw new GuardhouseError(
        "PAR response does not include request_uri",
        "PAR_ERROR",
      );
    }

    if (/\s/.test(data.request_uri)) {
      throw new GuardhouseError(
        "PAR response contains invalid request_uri",
        "PAR_ERROR",
      );
    }

    return {
      requestUri: data.request_uri,
      expiresIn:
        typeof data.expires_in === "number" ? data.expires_in : undefined,
    };
  }

  buildLogoutUrl(request: LogoutRequest = {}): string {
    const logoutEndpoint = request.logoutEndpoint || "/connect/logout";
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

      if (
        normalizedState.length > 128 ||
        !/^[A-Za-z0-9-]+$/.test(normalizedState)
      ) {
        throw new GuardhouseError(
          "state must be 1-128 characters and contain only letters, numbers, and hyphens",
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

  async prepareSharedDeviceLogout(
    request: LogoutRequest = {},
  ): Promise<string> {
    await this.clearSessionState();

    return this.buildLogoutUrl({
      ...request,
      federated: request.federated ?? true,
    });
  }

  async discoverOpenIdConfiguration(
    discoveryEndpoint = "/.well-known/openid-configuration",
  ): Promise<Record<string, unknown>> {
    const discoveryUrl = new URL(this.buildRequestUrl(discoveryEndpoint));
    const authorityUrl = new URL(this.baseURL);
    const cacheKey = discoveryUrl.toString();
    const cacheContext = {
      authority: this.baseURL,
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

    if (!response.data || typeof response.data !== "object") {
      throw new GuardhouseError(
        "Discovery response is invalid",
        "DISCOVERY_ERROR",
      );
    }

    const discoveryData = {
      ...(response.data as Record<string, unknown>),
    };

    this.assertTrustedDiscoveryMetadata(discoveryData, authorityUrl);

    const issuer = discoveryData["issuer"];
    const normalizedIssuer = typeof issuer === "string" ? issuer.trim() : "";
    if (normalizedIssuer !== this.baseURL) {
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
    registrationEndpoint = "/connect/register",
  ): Promise<Record<string, unknown>> {
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

    const response = await this.fetch(registrationEndpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(safeMetadata),
      token: normalizedInitialAccessToken,
    });

    if (!response.data || typeof response.data !== "object") {
      throw new GuardhouseError(
        "Client registration response is invalid",
        "REGISTRATION_ERROR",
      );
    }

    return response.data as Record<string, unknown>;
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

    if (!xFrameOptions) {
      warnings.push("X-Frame-Options header is missing");
    }

    if (!frameAncestorsPolicy) {
      warnings.push("CSP frame-ancestors directive is missing");
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
