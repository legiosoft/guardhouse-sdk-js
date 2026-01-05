import { GuardhouseConfig, GuardhouseError } from "./types";

export class GuardhouseClient {
  constructor(private config: GuardhouseConfig) {}

  async fetch<T>(url: string, options?: RequestInit): Promise<T> {
    const headers: HeadersInit = {
      "Content-Type": "application/json",
      ...options?.headers,
    };

    if (this.config.clientSecret) {
      const credentials = Buffer.from(
        `${this.config.clientId}:${this.config.clientSecret}`,
      ).toString("base64");
      (headers as Record<string, string>)["Authorization"] =
        `Basic ${credentials}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      });

      if (!response.ok) {
        const error = await response.text();
        throw new GuardhouseError(
          `Request failed: ${error}`,
          undefined,
          response.status,
        );
      }

      return (await response.json()) as T;
    } catch (error) {
      if (error instanceof GuardhouseError) {
        throw error;
      }
      throw new GuardhouseError(
        `Network error: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  async post<T>(url: string, data?: any): Promise<T> {
    return this.fetch<T>(url, {
      method: "POST",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async postForm<T>(url: string, data: Record<string, string>): Promise<T> {
    const params = new URLSearchParams(data);
    const headers: HeadersInit = {};

    if (this.config.clientSecret) {
      const credentials = Buffer.from(
        `${this.config.clientId}:${this.config.clientSecret}`,
      ).toString("base64");
      (headers as Record<string, string>)["Authorization"] =
        `Basic ${credentials}`;
    }

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          ...headers,
        },
        body: params.toString(),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new GuardhouseError(
          `Request failed: ${error}`,
          undefined,
          response.status,
        );
      }

      return (await response.json()) as T;
    } catch (error) {
      if (error instanceof GuardhouseError) {
        throw error;
      }
      throw new GuardhouseError(
        `Network error: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
}

export async function generateAuthUrl(options: {
  authority: string;
  clientId: string;
  redirectUri: string;
  scope?: string;
  responseType?: string;
  state?: string;
  codeChallenge?: string;
  codeChallengeMethod?: string;
}): Promise<string> {
  const url = new URL(`${options.authority}/connect/authorize`);
  url.searchParams.set("client_id", options.clientId);
  url.searchParams.set("redirect_uri", options.redirectUri);
  url.searchParams.set("response_type", options.responseType || "code");
  url.searchParams.set("scope", options.scope || "openid profile email");

  if (options.state) {
    url.searchParams.set("state", options.state);
  }

  if (options.codeChallenge) {
    url.searchParams.set("code_challenge", options.codeChallenge);
    url.searchParams.set(
      "code_challenge_method",
      options.codeChallengeMethod || "S256",
    );
  }

  return url.toString();
}

export async function generatePKCE(): Promise<{
  codeVerifier: string;
  codeChallenge: string;
}> {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const codeVerifier = base64UrlEncode(array);

  const encoder = new TextEncoder();
  const data = encoder.encode(codeVerifier);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const codeChallenge = base64UrlEncode(new Uint8Array(hash));

  return { codeVerifier, codeChallenge };
}

function base64UrlEncode(buffer: Uint8Array): string {
  let base64 = btoa(String.fromCharCode(...buffer));
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}

export type { AuthUrlOptions, PKCEPair } from "./types";
export {
  GuardhouseConfig,
  User,
  TokenResponse,
  IntrospectionResponse,
  GuardhouseError,
} from "./types";
