import { GuardhouseClient, TokenResponse } from "@guardhouse/core";
import { GuardhouseConstants } from "./constants";
import { GuardhouseClientOptions } from "./types";
import { createNodeLogger } from "./debug";
import { generateCorrelationId, stripStackTrace } from "./utils";

interface CachedToken {
  accessToken: string;
  refreshToken?: string;
  expiresAt: number;
}

const TokenLocks = new Map<string, Promise<CachedToken>>();

export class GuardhouseNodeClient {
  protected tokenCache: Map<string, CachedToken> = new Map();
  protected logger: ReturnType<typeof createNodeLogger>;

  constructor(protected options: GuardhouseClientOptions) {
    this.logger = createNodeLogger("Client", options.debug);
    this.logger.info("Initialized node client", {
      authority: options.authority,
      clientId: options.clientId,
      enableTokenCaching: options.enableTokenCaching !== false,
      enableTokenRefresh: options.enableTokenRefresh !== false,
    });
  }

  protected redactUrl(url: string): string {
    return url.replace(/https?:\/\/[^\/]+/, "***");
  }

  private getTokenCacheKey(): string {
    const cacheKey = `guardhouse_access_token_${this.options.clientId}`;

    this.logger.debug("Computed token cache key", {
      cacheKey,
    });

    return cacheKey;
  }

  private isTokenExpired(
    token: CachedToken,
    bufferSeconds: number = 60,
  ): boolean {
    const now = Math.floor(Date.now() / 1000);
    const expired = now >= token.expiresAt - bufferSeconds;

    this.logger.debug("Checked cached token expiration", {
      expired,
      expiresAt: token.expiresAt,
      now,
      bufferSeconds,
    });

    return expired;
  }

  private async withLock<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const existingLock = TokenLocks.get(key);
    if (existingLock) {
      this.logger.debug("Waiting for existing token lock", { key });
      return existingLock.then(() => fn());
    }

    this.logger.debug("Acquired token lock", { key });

    const promise = fn()
      .finally(() => {
        this.logger.debug("Releasing token lock", { key });
        TokenLocks.delete(key);
      })
      .catch((error) => {
        this.logger.error(`Token acquisition failed [${key}]`, {
          error: stripStackTrace(error as Error),
        });
        throw error;
      });

    TokenLocks.set(key, promise as any);
    return promise;
  }

  private logTokenRequest(): string {
    const correlationId = generateCorrelationId();
    this.logger.info(`Token request initiated [${correlationId}]`, {
      authority: this.options.authority,
      clientId: this.options.clientId,
      scope: this.options.scope,
    });
    return correlationId;
  }

  async getAccessToken(): Promise<string> {
    this.logger.debug("Requesting access token");

    const cacheKey = this.getTokenCacheKey();
    const enableCaching = this.options.enableTokenCaching !== false;
    const bufferSeconds =
      this.options.cacheExpirationBufferSeconds ||
      GuardhouseConstants.Defaults.CacheExpirationBufferSeconds;

    if (enableCaching) {
      const cached = this.tokenCache.get(cacheKey);
      if (cached && !this.isTokenExpired(cached, bufferSeconds)) {
        this.logger.debug("Using cached access token", {
          cacheKey,
        });
        return cached.accessToken;
      }

      this.logger.debug("Cached token not available or expired", {
        cacheKey,
      });
    }

    return this.withLock(cacheKey, async () => {
      if (enableCaching) {
        const cached = this.tokenCache.get(cacheKey);
        if (cached && !this.isTokenExpired(cached, bufferSeconds)) {
          this.logger.debug("Using cached token after lock acquisition", {
            cacheKey,
          });
          return cached.accessToken;
        }
      }

      let tokenResponse: TokenResponse;

      if (this.options.enableTokenRefresh !== false) {
        const cached = this.tokenCache.get(cacheKey);
        if (cached && cached.refreshToken) {
          try {
            const correlationId = generateCorrelationId();
            this.logger.info(`Token refresh attempt [${correlationId}]`, {
              authority: this.options.authority,
              clientId: this.options.clientId,
            });

            tokenResponse = await this.refreshToken(cached.refreshToken);
            this.cacheToken(tokenResponse);
            return tokenResponse.access_token;
          } catch (error) {
            this.logger.warn("Failed to refresh token, requesting new token", {
              error: stripStackTrace(error as Error),
              authority: this.options.authority,
              clientId: this.options.clientId,
            });
          }
        }
      }

      const correlationId = this.logTokenRequest();
      tokenResponse = await this.requestToken();

      this.logger.info(`Token request successful [${correlationId}]`, {
        expires_in: tokenResponse.expires_in,
      });

      this.cacheToken(tokenResponse);
      return tokenResponse.access_token;
    });
  }

  async requestToken(): Promise<TokenResponse> {
    this.logger.info("Requesting client credentials token", {
      authority: this.options.authority,
      clientId: this.options.clientId,
    });

    const coreClientConfig: Record<string, unknown> = {
      authority: this.options.authority,
      clientId: this.options.clientId,
      clientSecret: this.options.clientSecret,
    };

    if (typeof this.options.debug === "boolean") {
      coreClientConfig.debug = this.options.debug;
    }

    const client = new GuardhouseClient(coreClientConfig as any);

    const scope =
      this.options.scope || GuardhouseConstants.Defaults.DefaultScope;

    try {
      const body = new URLSearchParams({
        grant_type: "client_credentials",
        scope,
        client_id: this.options.clientId,
        client_secret: this.options.clientSecret,
      });

      const tokenResponse = await client.postForm<TokenResponse>(
        `/${GuardhouseConstants.Endpoints.ConnectToken}`,
        body,
        true,
      );

      this.logger.info("Client credentials token request succeeded", {
        expiresIn: tokenResponse.expires_in,
        hasRefreshToken: Boolean(tokenResponse.refresh_token),
      });

      return tokenResponse;
    } catch (error) {
      const errorMessage = stripStackTrace(error as Error);
      this.logger.error("Client credentials token request failed", {
        error: errorMessage,
      });
      throw new Error(
        `Failed to request token: ${errorMessage}. ` +
          `Please verify your Guardhouse credentials. ` +
          `Authority: ${this.options.authority}, ClientId: ${this.options.clientId}, Scope: ${scope}`,
      );
    }
  }

  async refreshToken(refreshToken: string): Promise<TokenResponse> {
    this.logger.info("Refreshing access token", {
      hasRefreshToken: Boolean(refreshToken),
    });

    const coreClientConfig: Record<string, unknown> = {
      authority: this.options.authority,
      clientId: this.options.clientId,
      clientSecret: this.options.clientSecret,
    };

    if (typeof this.options.debug === "boolean") {
      coreClientConfig.debug = this.options.debug;
    }

    const client = new GuardhouseClient(coreClientConfig as any);

    try {
      const body = new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      });
      const tokenResponse = await client.postForm<TokenResponse>(
        `/${GuardhouseConstants.Endpoints.ConnectToken}`,
        body,
      );

      this.logger.info("Access token refresh succeeded", {
        expiresIn: tokenResponse.expires_in,
      });

      return tokenResponse;
    } catch (error) {
      const errorMessage = stripStackTrace(error as Error);
      this.logger.error("Access token refresh failed", {
        error: errorMessage,
      });
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

    this.logger.debug("Starting authenticated request", {
      url: this.redactUrl(url),
      maxRetries,
      method: options?.method || "GET",
    });

    while (retryCount <= maxRetries) {
      const correlationId = generateCorrelationId();

      this.logger.debug(`Attempting request [${correlationId}]`, {
        retryCount,
        url: this.redactUrl(url),
        method: options?.method || "GET",
      });

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
          this.logger.warn(`Received 401, clearing cache [${correlationId}]`, {
            url: this.redactUrl(url),
          });

          const cachedKey = this.getTokenCacheKey();
          this.tokenCache.delete(cachedKey);
          retryCount++;
          continue;
        }

        if (!response.ok) {
          const errorText = await response.text();
          this.logger.warn(`Request failed [${correlationId}]`, {
            status: response.status,
            url: this.redactUrl(url),
            error: errorText.substring(0, 200),
          });
          throw new Error(`Request failed with status ${response.status}`);
        }

        this.logger.info(`Request successful [${correlationId}]`, {
          status: response.status,
          url: this.redactUrl(url),
        });

        return (await response.json()) as T;
      } catch (error) {
        if (retryCount >= maxRetries) {
          this.logger.error("Authenticated request failed after retries", {
            retryCount,
            url: this.redactUrl(url),
            error: stripStackTrace(error as Error),
          });
          throw error;
        }

        const delay = Math.pow(2, retryCount) * 1000;
        this.logger.warn("Retrying authenticated request", {
          retryCount,
          delay,
          url: this.redactUrl(url),
        });
        await new Promise((resolve) => setTimeout(resolve, delay));
        retryCount++;
      }
    }

    throw new Error("Max retry attempts reached");
  }

  async get<T>(url: string): Promise<T> {
    this.logger.debug("Executing GET request", {
      url: this.redactUrl(url),
    });
    return this.fetch<T>(url, { method: "GET" });
  }

  async post<T>(url: string, data?: any): Promise<T> {
    this.logger.debug("Executing POST request", {
      url: this.redactUrl(url),
      hasBody: Boolean(data),
    });
    return this.fetch<T>(url, {
      method: "POST",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async put<T>(url: string, data?: any): Promise<T> {
    this.logger.debug("Executing PUT request", {
      url: this.redactUrl(url),
      hasBody: Boolean(data),
    });
    return this.fetch<T>(url, {
      method: "PUT",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  async delete<T>(url: string): Promise<T> {
    this.logger.debug("Executing DELETE request", {
      url: this.redactUrl(url),
    });
    return this.fetch<T>(url, { method: "DELETE" });
  }

  async patch<T>(url: string, data?: any): Promise<T> {
    this.logger.debug("Executing PATCH request", {
      url: this.redactUrl(url),
      hasBody: Boolean(data),
    });
    return this.fetch<T>(url, {
      method: "PATCH",
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  private cacheToken(tokenResponse: TokenResponse): void {
    if (this.options.enableTokenCaching === false) {
      this.logger.debug("Skipping token cache because caching is disabled");
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
      const evictionTimer = setTimeout(() => {
        this.tokenCache.delete(this.getTokenCacheKey());
      }, timeout);

      (evictionTimer as unknown as { unref?: () => void }).unref?.();

      this.logger.debug("Token cached", {
        expiresAt: new Date(expiresAt * 1000).toISOString(),
        bufferSeconds,
      });
    } else {
      this.logger.warn(
        "Skipping cache because token would already be expired",
        {
          expiresIn: tokenResponse.expires_in,
          bufferSeconds,
        },
      );
    }
  }

  async clearCache(): Promise<void> {
    this.logger.info("Clearing in-memory token cache", {
      sizeBefore: this.tokenCache.size,
    });
    this.tokenCache.clear();
  }
}

export class GuardhouseAdminClient extends GuardhouseNodeClient {
  async deleteUser(userId: string): Promise<void> {
    const correlationId = generateCorrelationId();
    const auth = await this.getAccessToken();
    const url = `${this.options.authority}/api/users/${userId}`;

    this.logger.debug(`Deleting user [${correlationId}]`, {
      userId,
      url: this.redactUrl(url),
      hasAccessToken: Boolean(auth),
    });

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
        this.logger.warn(`Delete user failed [${correlationId}]`, {
          userId,
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to delete user`);
      }

      this.logger.info(`User deleted successfully [${correlationId}]`, {
        userId,
      });
    } catch (error) {
      throw new Error(stripStackTrace(error as Error));
    }
  }

  async getUser(userId: string): Promise<any> {
    const correlationId = generateCorrelationId();
    const auth = await this.getAccessToken();
    const url = `${this.options.authority}/api/users/${userId}`;

    this.logger.debug(`Getting user [${correlationId}]`, {
      userId,
      url: this.redactUrl(url),
      hasAccessToken: Boolean(auth),
    });

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
        this.logger.warn(`Get user failed [${correlationId}]`, {
          userId,
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to get user`);
      }

      const data = await response.json();
      this.logger.info(`User retrieved successfully [${correlationId}]`, {
        userId,
      });
      return data;
    } catch (error) {
      throw new Error(stripStackTrace(error as Error));
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

    this.logger.debug(`Listing users [${correlationId}]`, {
      url: this.redactUrl(url),
      hasAccessToken: Boolean(auth),
      hasSearch: Boolean(params?.search),
      page: params?.page,
      pageSize: params?.pageSize,
    });

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
        this.logger.warn(`List users failed [${correlationId}]`, {
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to list users`);
      }

      const data = await response.json();
      this.logger.info(`Users listed successfully [${correlationId}]`, {
        count: data.length,
      });
      return data;
    } catch (error) {
      throw new Error(stripStackTrace(error as Error));
    }
  }

  async createUser(userData: any): Promise<any> {
    const correlationId = generateCorrelationId();
    const auth = await this.getAccessToken();
    const url = `${this.options.authority}/api/users`;

    this.logger.debug(`Creating user [${correlationId}]`, {
      url: this.redactUrl(url),
      hasAccessToken: Boolean(auth),
      hasUserData: Boolean(userData),
    });

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
        this.logger.warn(`Create user failed [${correlationId}]`, {
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to create user`);
      }

      const data = await response.json();
      this.logger.info(`User created successfully [${correlationId}]`, {
        userId: data.id,
      });
      return data;
    } catch (error) {
      throw new Error(stripStackTrace(error as Error));
    }
  }

  async updateUser(userId: string, userData: any): Promise<any> {
    const correlationId = generateCorrelationId();
    const auth = await this.getAccessToken();
    const url = `${this.options.authority}/api/users/${userId}`;

    this.logger.debug(`Updating user [${correlationId}]`, {
      userId,
      url: this.redactUrl(url),
      hasAccessToken: Boolean(auth),
      hasUserData: Boolean(userData),
    });

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
        this.logger.warn(`Update user failed [${correlationId}]`, {
          userId,
          status: response.status,
          error: errorText.substring(0, 200),
        });
        throw new Error(`Failed to update user`);
      }

      const data = await response.json();
      this.logger.info(`User updated successfully [${correlationId}]`, {
        userId,
      });
      return data;
    } catch (error) {
      throw new Error(stripStackTrace(error as Error));
    }
  }
}
