import jwt from "jsonwebtoken";
import jwksClient, { JwksClient } from "jwks-rsa";
import { GuardhouseConstants } from "./constants";
import {
  GuardhouseResourceOptions,
  GuardhouseUser,
  ExpressRequest,
  ExpressResponse,
  ExpressNextFunction,
  ExpressMiddleware,
  TokenValidationMode,
  IntrospectionCredentialTransmission,
} from "./types";
import {
  buildClaimsFromIntrospection,
  createWWWAuthenticateHeader,
  validateHttpsUrl,
  validateTrustedAuthority,
  validateMaxTokenAge,
  generateCorrelationId,
  stripStackTrace,
  getTokenHash,
} from "./utils";
import { createNodeLogger } from "./debug";
import { GuardhouseClient, IntrospectionResponse } from "@guardhouse/core";

interface IntrospectionCacheEntry {
  result: IntrospectionResponse;
  expiresAt: number;
  tokenExp: number;
}

interface KeyCacheEntry {
  key: string;
  expiresAt: number;
}

export class GuardhouseResourceService {
  private jwksClient: JwksClient | null = null;
  private introspectionCache = new Map<string, IntrospectionCacheEntry>();
  private keyCache = new Map<string, KeyCacheEntry>();
  private jwksUri: string;
  private logger: ReturnType<typeof createNodeLogger>;

  constructor(private options: GuardhouseResourceOptions) {
    this.jwksUri = "";
    this.logger = createNodeLogger("Middleware", options.debug);

    this.logger.info("Initializing resource service", {
      authority: options.authority,
      audience: options.audience,
      validationMode: options.validationMode || "jwt_signature",
    });

    if (this.options.validationMode === "jwt_signature") {
      const normalizedAuthority = this.options.authority.replace(/\/+$/, "");
      this.jwksUri = `${normalizedAuthority}/${GuardhouseConstants.Endpoints.WellKnownJwks}`;

      validateHttpsUrl(this.jwksUri, "JWKS endpoint");

      if (this.options.requireHttpsMetadata !== false) {
        validateHttpsUrl(this.options.authority, "Authority URL");
      }

      if (this.options.validateIssuerSigningKey !== false) {
        try {
          validateTrustedAuthority(this.jwksUri, this.options.authority);
        } catch (error) {
          this.logger.warn("JWKS authority validation skipped", {
            error: String(error),
          });
        }
      }

      this.jwksClient = jwksClient({
        jwksUri: this.jwksUri,
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 10,
        timeout: GuardhouseConstants.Defaults.RequestTimeoutSeconds * 1000,
      });

      this.logger.debug("JWKS client initialized", {
        jwksUri: this.jwksUri,
      });
    }
  }

  private redactToken(token: string): string {
    if (!token || token.length < 12) {
      return "***";
    }

    return `${token.substring(0, 6)}...${token.substring(token.length - 6)}`;
  }

  private async getSigningKey(kid: string): Promise<string> {
    if (!this.jwksClient) {
      throw new Error("JWKS client not initialized");
    }

    if (!kid) {
      throw new Error("Token header missing required 'kid' parameter");
    }

    const cacheEntry = this.keyCache.get(kid);
    if (cacheEntry && cacheEntry.expiresAt > Date.now()) {
      this.logger.debug("Using cached signing key", {
        kid,
      });
      return cacheEntry.key;
    }

    this.logger.debug("Fetching signing key from JWKS", {
      kid,
      jwksUri: this.jwksUri,
    });

    return new Promise((resolve, reject) => {
      this.jwksClient!.getSigningKey(kid, (err, key) => {
        if (err) {
          this.logger.error("Failed to fetch signing key", {
            kid,
            error: String(err),
          });
          reject(new Error("Failed to fetch signing key from JWKS"));
        } else if (key) {
          const publicKey = key.getPublicKey();
          const cacheDuration =
            (this.options.jwksCacheDurationHours ??
              GuardhouseConstants.Defaults.JwksCacheDurationHours) *
            60 *
            60 *
            1000;

          this.keyCache.set(kid, {
            key: publicKey,
            expiresAt: Date.now() + cacheDuration,
          });

          this.logger.debug("Signing key fetched and cached", {
            kid,
            cacheDuration,
          });

          resolve(publicKey);
        } else {
          this.logger.warn("Signing key not found in JWKS response", {
            kid,
          });
          reject(new Error("Signing key not found in JWKS"));
        }
      });
    });
  }

  private validateTokenHeader(token: string): {
    alg: string;
    typ?: string;
    kid?: string;
  } {
    this.logger.debug("Validating token header", {
      token: this.redactToken(token),
    });

    const tokenParts = token.split(".");
    if (tokenParts.length !== 3) {
      throw new Error("Invalid token structure");
    }

    const headerPart = tokenParts[0];
    let header: any;

    try {
      header = JSON.parse(Buffer.from(headerPart, "base64").toString("utf-8"));
    } catch (error) {
      throw new Error("Failed to parse token header");
    }

    if (!header.alg) {
      throw new Error("Token header missing required 'alg' parameter");
    }

    return {
      alg: header.alg,
      typ: header.typ,
      kid: header.kid,
    };
  }

  private async validateJwtToken(token: string): Promise<GuardhouseUser> {
    this.logger.debug("Validating JWT token", {
      token: this.redactToken(token),
    });

    const { alg, typ, kid } = this.validateTokenHeader(token);

    if (alg === "none" || alg === "NONE") {
      throw new Error("Invalid algorithm: 'none' is not allowed");
    }

    if (
      typ &&
      this.options.tokenTypes &&
      !this.options.tokenTypes.includes(typ)
    ) {
      throw new Error(`Invalid token type: ${typ}`);
    }

    if (!kid) {
      throw new Error("Token header missing required 'kid' parameter");
    }

    const validAlgorithms = this.options.validAlgorithms || [
      GuardhouseConstants.Algorithms.RS256,
    ];

    if (!validAlgorithms.includes(alg)) {
      throw new Error(`Invalid algorithm: ${alg}`);
    }

    const signingKey = await this.getSigningKey(kid);

    const normalizedAuthority = this.options.authority?.endsWith("/")
      ? this.options.authority.slice(0, -1)
      : this.options.authority;

    const verified = jwt.verify(token, signingKey, {
      algorithms: [alg as jwt.Algorithm],
      audience:
        this.options.validateAudience !== false
          ? this.options.audience
          : undefined,
      clockTolerance: GuardhouseConstants.Defaults.ClockSkewMinutes * 60,
    });

    if (!verified || typeof verified === "string") {
      throw new Error("Token verification failed");
    }

    const payload = verified as any;

    if (this.options.validateIssuer !== false) {
      const normalizedIssuer = payload.iss?.endsWith("/")
        ? payload.iss.slice(0, -1)
        : payload.iss;

      if (normalizedIssuer !== normalizedAuthority) {
        throw new Error("Invalid issuer");
      }
    }

    if (this.options.validateAudience !== false) {
      const aud = payload.aud;
      if (Array.isArray(aud)) {
        if (!aud.includes(this.options.audience)) {
          throw new Error("Invalid audience");
        }
      } else if (aud !== this.options.audience) {
        throw new Error("Invalid audience");
      }
    }

    if (
      !payload.sub ||
      typeof payload.sub !== "string" ||
      payload.sub.length === 0
    ) {
      throw new Error("Token missing required 'sub' claim or subject is empty");
    }

    if (payload.azp && this.options.requireAzpMatch) {
      if (payload.azp !== this.options.audience) {
        throw new Error("Invalid authorized party");
      }
    }

    const now = Math.floor(Date.now() / 1000);
    const maxTokenAge =
      this.options.maxTokenAgeSeconds ||
      GuardhouseConstants.Defaults.MaxTokenAgeSeconds;

    if (payload.exp) {
      if (payload.exp <= now) {
        throw new Error("Token has expired");
      }
      validateMaxTokenAge(payload.exp, maxTokenAge);
    }

    if (
      payload.nbf &&
      payload.nbf > now + GuardhouseConstants.Defaults.ClockSkewMinutes * 60
    ) {
      throw new Error("Token not yet valid (nbf in future)");
    }

    if (
      payload.iat &&
      payload.iat > now + GuardhouseConstants.Defaults.ClockSkewMinutes * 60
    ) {
      throw new Error("Token issued in future (iat check failed)");
    }

    this.logger.debug("JWT token validated successfully", {
      subject: payload.sub,
      algorithm: alg,
      tokenType: typ,
    });

    return this.buildUserFromJwtPayload(payload);
  }

  private async introspectToken(token: string): Promise<GuardhouseUser> {
    this.logger.debug("Validating token via introspection", {
      token: this.redactToken(token),
    });

    if (
      !this.options.introspectionClientId ||
      !this.options.introspectionClientSecret
    ) {
      throw new Error("Introspection credentials not configured");
    }

    validateHttpsUrl(this.options.authority, "Introspection endpoint");

    const cacheKey = getTokenHash(token);
    const cached = this.introspectionCache.get(cacheKey);

    if (cached && cached.expiresAt > Date.now()) {
      this.logger.debug("Using cached introspection result", {
        tokenExp: cached.tokenExp,
      });
      return this.buildUserFromIntrospection(cached.result);
    }

    this.logger.debug("Requesting token introspection", {
      authority: this.options.authority,
      credentialMode:
        this.options.introspectionCredentialTransmission ||
        IntrospectionCredentialTransmission.BasicAuth,
    });

    const coreClientConfig: Record<string, unknown> = {
      authority: this.options.authority,
      clientId: this.options.introspectionClientId,
      clientSecret: this.options.introspectionClientSecret,
    };

    if (typeof this.options.debug === "boolean") {
      coreClientConfig.debug = this.options.debug;
    }

    const client = new GuardhouseClient(coreClientConfig as any);

    let introspectionResult: IntrospectionResponse;

    const useBasicAuth =
      this.options.introspectionCredentialTransmission ===
      IntrospectionCredentialTransmission.BasicAuth;

    if (useBasicAuth) {
      introspectionResult = await client.postForm<IntrospectionResponse>(
        `/${GuardhouseConstants.Endpoints.ConnectIntrospect}`,
        new URLSearchParams({
          token,
          token_type_hint: "access_token",
        }),
      );
    } else {
      introspectionResult = await client.postForm<IntrospectionResponse>(
        `/${GuardhouseConstants.Endpoints.ConnectIntrospect}`,
        new URLSearchParams({
          token,
          token_type_hint: "access_token",
          client_id: this.options.introspectionClientId,
          client_secret: this.options.introspectionClientSecret,
        }),
      );
    }

    if (!introspectionResult.active) {
      throw new Error("Token is not active");
    }

    if (
      introspectionResult.token_type &&
      this.options.tokenTypes &&
      !this.options.tokenTypes.includes(introspectionResult.token_type)
    ) {
      this.logger.warn("Rejecting token because token type is not allowed", {
        tokenType: introspectionResult.token_type,
      });
      throw new Error(`Invalid token type: ${introspectionResult.token_type}`);
    }

    if (
      introspectionResult.alg &&
      this.options.validAlgorithms &&
      !this.options.validAlgorithms.includes(introspectionResult.alg)
    ) {
      throw new Error(`Invalid algorithm: ${introspectionResult.alg}`);
    }

    if (introspectionResult.exp && this.options.validateLifetime !== false) {
      const now = Math.floor(Date.now() / 1000);
      if (introspectionResult.exp < now) {
        throw new Error("Token has expired");
      }
    }

    if (this.options.requiredScopes && introspectionResult.scope) {
      const tokenScopes = introspectionResult.scope.split(" ");
      const missingScopes = this.options.requiredScopes.filter(
        (s: string) => !tokenScopes.includes(s),
      );

      if (missingScopes.length > 0) {
        throw new Error(
          `Token missing required scopes: ${missingScopes.join(", ")}`,
        );
      }
    }

    if (this.options.introspectionCacheTtlSeconds) {
      const tokenExp = introspectionResult.exp || Date.now() + 3600;
      const now = Math.floor(Date.now() / 1000);
      const tokenRemaining = Math.max(0, tokenExp - now);
      const cacheTtl = Math.min(
        this.options.introspectionCacheTtlSeconds,
        tokenRemaining,
      );

      if (cacheTtl > 0) {
        this.introspectionCache.set(cacheKey, {
          result: introspectionResult,
          expiresAt: Date.now() + cacheTtl * 1000,
          tokenExp: tokenExp,
        });

        this.logger.debug("Cached introspection result", {
          cacheTtl,
          tokenExp,
        });
      }
    }

    this.logger.debug("Token introspection succeeded", {
      active: introspectionResult.active,
      subject: introspectionResult.sub,
      expiresAt: introspectionResult.exp,
    });

    return this.buildUserFromIntrospection(introspectionResult);
  }

  private buildUserFromJwtPayload(payload: any): GuardhouseUser {
    const roles = new Set<string>();

    if (payload.role) {
      if (Array.isArray(payload.role)) {
        payload.role.forEach((r: string) => roles.add(r));
      } else if (typeof payload.role === "string") {
        roles.add(payload.role);
      }
    }

    if (Array.isArray(payload.roles)) {
      payload.roles.forEach((r: string) => roles.add(r));
    } else if (typeof payload.roles === "string") {
      payload.roles.split(" ").forEach((r: string) => roles.add(r));
    }

    const user: GuardhouseUser = {
      sub: payload.sub,
      name: payload.name || payload.preferred_username || payload.username,
      username: payload.username,
      email: payload.email,
      roles: roles.size > 0 ? Array.from(roles) : undefined,
      scopes: payload.scope ? payload.scope.split(" ") : undefined,
      aud: Array.isArray(payload.aud) ? payload.aud : [payload.aud],
      iss: payload.iss,
      jti: payload.jti,
      exp: payload.exp,
      iat: payload.iat,
      nbf: payload.nbf,
      azp: payload.azp,
    };

    this.logger.debug("Built user claims from JWT payload", {
      subject: user.sub,
      roleCount: user.roles?.length || 0,
      scopeCount: user.scopes?.length || 0,
    });

    return user;
  }

  private buildUserFromIntrospection(
    result: IntrospectionResponse,
  ): GuardhouseUser {
    const claims = buildClaimsFromIntrospection(result);

    if (!claims.sub) {
      throw new Error("Introspection response missing required 'sub' claim");
    }

    const user: GuardhouseUser = {
      sub: claims.sub,
      name: claims.name,
      username: claims.username,
      email: claims.email,
      roles: claims.roles,
      scopes: claims.scopes,
      aud: claims.aud,
      iss: claims.iss,
      jti: claims.jti,
      exp: claims.exp,
      iat: claims.iat,
      nbf: claims.nbf,
      clientId: claims.clientId,
    };

    this.logger.debug("Built user claims from introspection", {
      subject: user.sub,
      roleCount: user.roles?.length || 0,
      scopeCount: user.scopes?.length || 0,
    });

    return user;
  }

  async validateToken(token: string): Promise<GuardhouseUser> {
    if (this.options.validationMode === "introspection") {
      this.logger.debug("Validating token via introspection");
      const user = await this.introspectToken(token);

      this.logger.debug("Token validation succeeded", {
        subject: user.sub,
        mode: "introspection",
      });

      return user;
    }

    this.logger.debug("Validating token via JWT signature");
    const user = await this.validateJwtToken(token);

    this.logger.debug("Token validation succeeded", {
      subject: user.sub,
      mode: "jwt_signature",
    });

    return user;
  }
}

export function guardhouseMiddleware(
  options: GuardhouseResourceOptions,
): ExpressMiddleware {
  const logger = createNodeLogger("Middleware", options.debug);

  const validationMode: TokenValidationMode =
    options.validationMode || "jwt_signature";
  const introspectionCredentialTransmission: IntrospectionCredentialTransmission =
    options.introspectionCredentialTransmission ||
    IntrospectionCredentialTransmission.BasicAuth;

  const opts: GuardhouseResourceOptions = {
    validationMode,
    validateIssuer:
      options.validateIssuer !== false
        ? GuardhouseConstants.Validation.ValidateIssuer
        : false,
    validateAudience:
      options.validateAudience !== false
        ? GuardhouseConstants.Validation.ValidateAudience
        : false,
    validateLifetime:
      options.validateLifetime !== false
        ? GuardhouseConstants.Validation.ValidateLifetime
        : false,
    validateIssuerSigningKey:
      options.validateIssuerSigningKey !== false
        ? GuardhouseConstants.Validation.ValidateIssuerSigningKey
        : false,
    jwksCacheDurationHours:
      options.jwksCacheDurationHours ||
      GuardhouseConstants.Defaults.JwksCacheDurationHours,
    jwksRefreshIntervalMinutes:
      options.jwksRefreshIntervalMinutes ||
      GuardhouseConstants.Defaults.JwksRefreshIntervalMinutes,
    introspectionCacheTtlSeconds:
      options.introspectionCacheTtlSeconds ||
      GuardhouseConstants.Defaults.IntrospectionCacheTtlSeconds,
    validAlgorithms: options.validAlgorithms || [
      GuardhouseConstants.Algorithms.RS256,
    ],
    tokenTypes: options.tokenTypes || [
      GuardhouseConstants.TokenTypes.Jwt,
      GuardhouseConstants.TokenTypes.AtJwt,
    ],
    introspectionCredentialTransmission,
    requireHttpsMetadata: options.requireHttpsMetadata,
    ...options,
  };

  if (opts.requireHttpsMetadata !== false) {
    validateHttpsUrl(opts.authority, "Authority URL");
  }

  const service = new GuardhouseResourceService(opts);

  logger.info("Guardhouse middleware initialized", {
    authority: opts.authority,
    audience: opts.audience,
    validationMode: opts.validationMode,
  });

  return async (
    req: ExpressRequest,
    res: ExpressResponse,
    next: ExpressNextFunction,
  ) => {
    const correlationId = generateCorrelationId();
    req.correlationId = correlationId;

    logger.debug(`Processing authentication request [${correlationId}]`, {
      hasAuthorizationHeader: Object.keys(req.headers).some(
        (key) => key.toLowerCase() === "authorization",
      ),
    });

    try {
      const authHeaders = Object.entries(req.headers)
        .filter(([key]) => key.toLowerCase() === "authorization")
        .flatMap(([, value]) => (Array.isArray(value) ? value : [value]))
        .filter((value) => value !== undefined && value !== null);

      if (authHeaders.length === 0) {
        logger.warn(`Missing authorization header [${correlationId}]`, {
          audience: opts.audience,
        });

        res
          .status(401)
          .setHeader(
            GuardhouseConstants.Headers.WwwAuthenticate,
            createWWWAuthenticateHeader(opts.audience),
          )
          .json({
            error: "unauthorized",
            error_description:
              GuardhouseConstants.ErrorMessages.MissingAuthorization,
            correlation_id: correlationId,
          });
        return;
      }

      if (authHeaders.length > 1) {
        logger.warn(
          `Multiple authorization headers supplied [${correlationId}]`,
        );

        res.status(400).json({
          error: "invalid_request",
          error_description: "Multiple authorization headers provided",
          correlation_id: correlationId,
        });
        return;
      }

      const authHeader = authHeaders[0];

      if (!authHeader || typeof authHeader !== "string") {
        logger.warn(`Invalid authorization header format [${correlationId}]`);

        res
          .status(401)
          .setHeader(
            GuardhouseConstants.Headers.WwwAuthenticate,
            createWWWAuthenticateHeader(opts.audience),
          )
          .json({
            error: "unauthorized",
            error_description:
              GuardhouseConstants.ErrorMessages.MissingAuthorization,
            correlation_id: correlationId,
          });
        return;
      }

      if (!authHeader.startsWith(GuardhouseConstants.Headers.BearerPrefix)) {
        logger.warn(`Authorization header is not Bearer [${correlationId}]`);

        res
          .status(401)
          .setHeader(
            GuardhouseConstants.Headers.WwwAuthenticate,
            createWWWAuthenticateHeader(opts.audience),
          )
          .json({
            error: "unauthorized",
            error_description: GuardhouseConstants.ErrorMessages.InvalidToken,
            correlation_id: correlationId,
          });
        return;
      }

      const token = authHeader
        .substring(GuardhouseConstants.Headers.BearerPrefix.length)
        .trim();

      logger.debug(`Bearer token extracted [${correlationId}]`, {
        tokenLength: token.length,
      });

      if (!token) {
        logger.warn(`Bearer token missing after prefix [${correlationId}]`);

        res
          .status(401)
          .setHeader(
            GuardhouseConstants.Headers.WwwAuthenticate,
            createWWWAuthenticateHeader(opts.audience),
          )
          .json({
            error: "unauthorized",
            error_description:
              GuardhouseConstants.ErrorMessages.MissingAuthorization,
            correlation_id: correlationId,
          });
        return;
      }

      if (token.length > GuardhouseConstants.Defaults.MaxTokenLengthBytes) {
        logger.warn(`Token exceeds maximum length [${correlationId}]`, {
          tokenLength: token.length,
          maxAllowed: GuardhouseConstants.Defaults.MaxTokenLengthBytes,
        });

        res.status(400).json({
          error: "invalid_request",
          error_description: "Token exceeds maximum allowed length",
          correlation_id: correlationId,
        });
        return;
      }

      const user = await service.validateToken(token);
      req.user = user;

      logger.debug(`Authentication succeeded [${correlationId}]`, {
        subject: user.sub,
      });

      next();
    } catch (error) {
      logger.warn(`Authentication failed [${correlationId}]`, {
        error: stripStackTrace(error as Error),
        authority: opts.authority,
        audience: opts.audience,
        clientId: opts.introspectionClientId,
      });

      res
        .status(401)
        .setHeader(
          GuardhouseConstants.Headers.WwwAuthenticate,
          createWWWAuthenticateHeader(opts.audience),
        )
        .json({
          error: "unauthorized",
          error_description: GuardhouseConstants.ErrorMessages.InvalidToken,
          correlation_id: correlationId,
        });
    }
  };
}
