import { GuardhouseClient, TokenResponse } from "@guardhouse/core";
import { GuardhouseConstants } from "./constants";
import { GuardhouseClientOptions } from "./types";
import { generateCorrelationId, stripStackTrace } from "./utils";

interface CachedToken {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
}

const TokenLocks = new Map<string, Promise<CachedToken>>();

export class GuardhouseNodeClient {
  protected tokenCache: Map<string, CachedToken> = new Map();

  constructor(protected options: GuardhouseClientOptions) {}

  private getTokenCacheKey(): string {
    return `guardhouse_access_token_${this.options.clientId}`;
  }

  private isTokenExpired(
    token: CachedToken,
    bufferSeconds: number = 60,
  ): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now >= token.expiresAt - bufferSeconds;
  }

  private async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const existingLock = TokenLocks.get(key);
    if (existingLock) {
      return existingLock.then(() => fn());
    }

    const promise = fn()
      .finally(() => {
        TokenLocks.delete(key);
      })
      .catch((error) => {
        console.error(`Token acquisition failed [${key}]:`, {
          error: stripStackTrace(error as Error),
        });
        throw error;
      });

    TokenLocks.set(key, promise as any);
    return promise;
  }

  private logTokenRequest(): string {
    const correlationId = generateCorrelationId();
    console.info(`Token request initiated [${correlationId}]:`, {
      authority: this.options.authority,
      clientId: this.options.clientId,
      scope: this.options.scope,
    });
    return correlationId;
  }

  async getAccessToken(): Promise<string> {
    const cacheKey = this.getTokenCacheKey();
    const enableCaching = this.options.enableTokenCaching !== false;
    const bufferSeconds =
      this.options.cacheExpirationBufferSeconds ||
      GuardhouseConstants.Defaults.CacheExpirationBufferSeconds;

    if (enableCaching) {
      const cached = this.tokenCache.get(cacheKey);
      if (cached && !this.isTokenExpired(cached, bufferSeconds)) {
        return cached.accessToken;
      }
    }

    return this.withLock(cacheKey, async () => {
      if (enableCaching) {
        const cached = this.tokenCache.get(cacheKey);
        if (cached && !this.isTokenExpired(cached, bufferSeconds)) {
          return cached.accessToken;
        }
      }

      let tokenResponse: TokenResponse;

      if (this.options.enableTokenRefresh !== false) {
        const cached = this.tokenCache.get(cacheKey);
        if (cached && cached.refreshToken) {
          try {
            const correlationId = generateCorrelationId();
            console.info(`Token refresh attempt [${correlationId}]:`, {
              authority: this.options.authority,
              clientId: this.options.clientId,
            });

            tokenResponse = await this.refreshToken(cached.refreshToken);
            this.cacheToken(tokenResponse);
            return tokenResponse.access_token;
          } catch (error) {
            console.warn(`Failed to refresh token, requesting new token:`, {
              error: stripStackTrace(error as Error),
              authority: this.options.authority,
              clientId: this.options.clientId,
            });
          }
        }
      }

      const correlationId = this.logTokenRequest();
      tokenResponse = await this.requestToken();

      console.info(`Token request successful [${correlationId}]:`, {
        expires_in: tokenResponse.expires_in,
      });

      this.cacheToken(tokenResponse);
      return tokenResponse.access_token;
    });
  }

  async requestToken(): Promise<TokenResponse> {
    const client = new GuardhouseClient({
      authority: this.options.authority,
      clientId: this.options.clientId,
      clientSecret: this.options.clientSecret,
    });

    const scope =
      this.options.scope || GuardhouseConstants.Defaults.DefaultScope;

    try {
      const body = new URLSearchParams({
        grant_type: "client_credentials",
        scope,
      });

      console.log("\n🔵 DEBUG: Requesting token");
      console.log(
        "   URL:",
        `${this.options.authority}/${GuardhouseConstants.Endpoints.ConnectToken}`,
      );
      console.log("   Method: POST");
      console.log(
        "   Headers: Content-Type: application/x-www-form-urlencoded",
      );
      console.log("   Body:", Object.fromEntries(body.entries()));
      console.log("");

      const tokenResponse = await client.postForm<TokenResponse>(
        `/${GuardhouseConstants.Endpoints.ConnectToken}`,
        body,
      );

      console.log("\n🟢 DEBUG: Token response received");
      console.log("   Status: Success");
      console.log("   Response:", {
        access_token: tokenResponse.access_token.substring(0, 20) + "...",
        token_type: tokenResponse.token_type,
        expires_in: tokenResponse.expires_in,
        scope: tokenResponse.scope,
      });
      console.log("");

      return tokenResponse;
    } catch (error) {
      console.log("\n🔴 DEBUG: Token request failed");
      console.log("   Error:", error instanceof Error ? error.message : error);
      console.log("");

      const errorMessage = stripStackTrace(error as Error);
      throw new Error(
        `Failed to request token: ${errorMessage}. ` +
          `Please verify your Guardhouse credentials. ` +
          `Authority: ${this.options.authority}, ClientId: ${this.options.clientId}, Scope: ${scope}`,
      );
    }
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    const client = new GuardhouseClient({
      authority: this.options.authority,
      clientId: this.options.clientId,
      clientSecret: this.options.clientSecret,
    });

    try {
      const body = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      });
      const tokenResponse = await client.postForm<TokenResponse>(
        `/${GuardhouseConstants.Endpoints.ConnectToken}`,
        body,
      );

      return tokenResponse;
    } catch (error) {
      const errorMessage = stripStackTrace(error as Error);
      throw new Error(
        `Failed to refresh token: ${errorMessage}. ` +
          `Your refresh token may have expired.`,
      );
    }
  }

  async fetch<T>(url: string, options?: RequestInit): Promise<T> {
    let retryCount = 0;
    const maxRetries =
      this.options.maxRetryAttempts ||
      GuardhouseConstants.Defaults.MaxRetryAttempts;

    while (retryCount <= maxRetries) {
      const correlationId = generateCorrelationId();

      try {
        const accessToken = await this.getAccessToken();

        const response = await fetch(url, {
          ...options,
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
            "X-Correlation-ID": correlationId,
            ...options?.headers,
          },
        });

        if (response.status === 401 && retryCount === 0) {
          console.warn(`Received 401, clearing cache [${correlationId}]:`, {
            url: url.replace(/https?:\/\/[^\/]+/, "***"),
          });

          const cachedKey = this.getTokenCacheKey();
          this.tokenCache.delete(cachedKey);
          retryCount++;
          continue;
        }

        if (!response.ok) {
          const errorText = await response.text();
          console.warn(`Request failed [${correlationId}]:`, {
            status: response.status,
            url: url.replace(/https?:\/\/[^\/]+/, "***"),
            error: errorText.substring(0, 200),
          });
          throw new Error(`Request failed with status ${response.status}`);
        }

        console.info(`Request successful [${correlationId}]:`, {
          status: response.status,
          url: url.replace(/https?:\/\/[^\/]+/, "***"),
        });

        return (await response.json()) as T;
      } catch (error) {
        if (retryCount >= maxRetries) {
          throw error;
        }

        const delay = Math.pow(2, retryCount) * 1000;
        await new Promise((resolve) => setTimeout(resolve, delay));
        retryCount++;
      }
    }

    throw new Error("Max retry attempts reached");
  }

  async get<T>(url: string): Promise<T> {
    return this.fetch<T>(url, { method: "GET" });
  }

  async post<T>(url: string, data?: any): Promise<T> {
    return this.fetch<T>(url, {
      method: "POST",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async put<T>(url: string, data?: any): Promise<T> {
    return this.fetch<T>(url, {
      method: "PUT",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async delete<T>(url: string): Promise<T> {
    return this.fetch<T>(url, { method: "DELETE" });
  }

  async patch<T>(url: string, data?: any): Promise<T> {
    return this.fetch<T>(url, {
      method: "PATCH",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  private cacheToken(tokenResponse: TokenResponse): void {
    if (this.options.enableTokenCaching === false) {
      return;
    }

    const now = Math.floor(Date.now() / 1000);
    const bufferSeconds =
      this.options.cacheExpirationBufferSeconds ||
      GuardhouseConstants.Defaults.CacheExpirationBufferSeconds;
    const expiresAt = now + tokenResponse.expires_in - bufferSeconds;

    if (expiresAt > now) {
      const cachedToken: CachedToken = {
        accessToken: tokenResponse.access_token,
        refreshToken: tokenResponse.refresh_token,
        expiresAt,
      };

      this.tokenCache.set(this.getTokenCacheKey(), cachedToken);

      const timeout = (expiresAt - now) * 1000;
      setTimeout(() => {
        this.tokenCache.delete(this.getTokenCacheKey());
      }, timeout);

      console.debug(`Token cached:`, {
        expiresAt: new Date(expiresAt * 1000).toISOString(),
        bufferSeconds,
      });
    }
  }

  async clearCache(): Promise<void> {
    this.tokenCache.clear();
  }
}

export class GuardhouseAdminClient extends GuardhouseNodeClient {
  async deleteUser(userId: string): Promise<void> {
    const correlationId = generateCorrelationId();
    const auth = await this.getAccessToken();
    const url = `${this.options.authority}/api/users/${userId}`;

    try {
      const response = await fetch(url, {
        method: "DELETE",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${auth}`,
          "X-Correlation-ID": correlationId,
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.warn(`Delete user failed [${correlationId}]:`, {
          userId,
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to delete user`);
      }

      console.info(`User deleted successfully [${correlationId}]:`, {
        userId,
      });
    } catch (error) {
      throw stripStackTrace(error as Error);
    }
  }

  async getUser(userId: string): Promise<any> {
    const correlationId = generateCorrelationId();
    const auth = await this.getAccessToken();
    const url = `${this.options.authority}/api/users/${userId}`;

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${auth}`,
          "X-Correlation-ID": correlationId,
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.warn(`Get user failed [${correlationId}]:`, {
          userId,
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to get user`);
      }

      const data = await response.json();
      console.info(`User retrieved successfully [${correlationId}]:`, {
        userId,
      });
      return data;
    } catch (error) {
      throw stripStackTrace(error as Error);
    }
  }

  async listUsers(params?: {
    page?: number;
    pageSize?: number;
    search?: string;
  }): Promise<any> {
    const correlationId = generateCorrelationId();
    const auth = await this.getAccessToken();
    const searchParams = new URLSearchParams();
    if (params?.page) searchParams.set("page", params.page.toString());
    if (params?.pageSize)
      searchParams.set("pageSize", params.pageSize.toString());
    if (params?.search) searchParams.set("search", params.search);

    const queryString = searchParams.toString();
    const url = `${this.options.authority}/api/users${queryString ? `?${queryString}` : ""}`;

    try {
      const response = await fetch(url, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${auth}`,
          "X-Correlation-ID": correlationId,
        },
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.warn(`List users failed [${correlationId}]:`, {
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to list users`);
      }

      const data = await response.json();
      console.info(`Users listed successfully [${correlationId}]:`, {
        count: data.length,
      });
      return data;
    } catch (error) {
      throw stripStackTrace(error as Error);
    }
  }

  async createUser(userData: any): Promise<any> {
    const correlationId = generateCorrelationId();
    const auth = await this.getAccessToken();
    const url = `${this.options.authority}/api/users`;

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${auth}`,
          "X-Correlation-ID": correlationId,
        },
        body: JSON.stringify(userData),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.warn(`Create user failed [${correlationId}]:`, {
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to create user`);
      }

      const data = await response.json();
      console.info(`User created successfully [${correlationId}]:`, {
        userId: data.id,
      });
      return data;
    } catch (error) {
      throw stripStackTrace(error as Error);
    }
  }

  async updateUser(userId: string, userData: any): Promise<any> {
    const correlationId = generateCorrelationId();
    const auth = await this.getAccessToken();
    const url = `${this.options.authority}/api/users/${userId}`;

    try {
      const response = await fetch(url, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${auth}`,
          "X-Correlation-ID": correlationId,
        },
        body: JSON.stringify(userData),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.warn(`Update user failed [${correlationId}]:`, {
          userId,
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to update user`);
      }

      const data = await response.json();
      console.info(`User updated successfully [${correlationId}]:`, {
        userId,
      });
      return data;
    } catch (error) {
      throw stripStackTrace(error as Error);
    }
  }
}
