export interface GuardhouseConfig {
  authority: string;
  clientId: string;
  clientSecret?: string;
  redirectUri?: string;
  scope?: string;
}

export interface User {
  sub: string;
  name?: string;
  email?: string;
  roles?: string[];
  scopes?: string[];
  [key: string]: any;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
}

export interface IntrospectionResponse {
  active: boolean;
  scope?: string;
  client_id?: string;
  username?: string;
  token_type?: string;
  alg?: string;
  sig?: string;
  exp?: number;
  iat?: number;
  nbf?: number;
  sub?: string;
  aud?: string;
  iss?: string;
  jti?: string;
  roles?: string;
  role?: string[];
}

export class GuardhouseError extends Error {
  constructor(
    message: string,
    public code?: string,
    public statusCode?: number,
  ) {
    super(message);
    this.name = "GuardhouseError";
  }
}

export interface AuthUrlOptions {
  authority: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  responseType?: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
  nonce?: string;
  prompt?: string;
  audience?: string;
  responseMode?: string;
  maxAge?: number;
  extraParams?: Record<string, string | number | undefined>;
}

export interface PKCEPair {
  codeVerifier: string;
  codeChallenge: string;
}
