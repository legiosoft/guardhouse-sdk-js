export const TokenValidationMode = {
  JwtSignature: "jwt_signature" as const,
  Introspection: "introspection" as const,
};

export type TokenValidationMode =
  (typeof TokenValidationMode)[keyof typeof TokenValidationMode];

export const IntrospectionCredentialTransmission = {
  BasicAuth: "basic_auth" as const,
  FormData: "form_data" as const,
};

export type IntrospectionCredentialTransmission =
  (typeof IntrospectionCredentialTransmission)[keyof typeof IntrospectionCredentialTransmission];

export interface GuardhouseClientOptions {
  authority: string;
  clientId: string;
  clientSecret: string;
  debug?: boolean;
  scope?: string;
  enableTokenCaching?: boolean;
  cacheExpirationBufferSeconds?: number;
  enableTokenRefresh?: boolean;
  requestTimeoutSeconds?: number;
  maxRetryAttempts?: number;
  enableHttpResilience?: boolean;
  introspectionClientId?: string;
  introspectionClientSecret?: string;
  introspectionCredentialTransmission?: IntrospectionCredentialTransmission;
}

export interface GuardhouseResourceOptions {
  authority: string;
  audience: string;
  debug?: boolean;
  validationMode?: TokenValidationMode;
  introspectionClientId?: string;
  introspectionClientSecret?: string;
  policyName?: string;
  validateIssuer?: boolean;
  validateAudience?: boolean;
  validateLifetime?: boolean;
  validateIssuerSigningKey?: boolean;
  requireHttpsMetadata?: boolean;
  jwksCacheDurationHours?: number;
  jwksRefreshIntervalMinutes?: number;
  introspectionCacheTtlSeconds?: number;
  introspectionCredentialTransmission?: IntrospectionCredentialTransmission;
  validAlgorithms?: string[];
  tokenTypes?: string[];
  maxTokenAgeSeconds?: number;
  requireAzpMatch?: boolean;
  requiredScopes?: string[];
  enableStrictMode?: boolean;
}

export interface GuardhouseUser {
  sub: string;
  name?: string;
  username?: string;
  email?: string;
  roles?: string[];
  scopes?: string[];
  aud?: string[];
  iss?: string;
  jti?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  clientId?: string;
  azp?: string;
  [key: string]: any;
}

export type ExpressRequest = {
  headers: {
    authorization?: string;
    [key: string]: any;
  };
  user?: GuardhouseUser;
  correlationId?: string;
  [key: string]: any;
};

export type ExpressResponse = {
  status: (code: number) => ExpressResponse;
  json: (data: any) => ExpressResponse;
  setHeader: (name: string, value: string) => ExpressResponse;
  [key: string]: any;
};

export type ExpressNextFunction = (error?: any) => void;

export type ExpressMiddleware = (
  req: ExpressRequest,
  res: ExpressResponse,
  next: ExpressNextFunction,
) => void | Promise<void>;

export interface SecurityValidationResult {
  valid: boolean;
  error?: string;
}
