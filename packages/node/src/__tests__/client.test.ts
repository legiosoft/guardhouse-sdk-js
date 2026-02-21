import { GuardhouseNodeClient, GuardhouseAdminClient } from "../client";

jest.mock("jsonwebtoken");

const mockFetch = global.fetch as jest.MockedFunction<typeof fetch>;

describe("GuardhouseNodeClient", () => {
  let client: GuardhouseNodeClient;
  const mockOptions = {
    authority: "https://auth.guardhouse.io",
    clientId: "test-client-id",
    clientSecret: "test-client-secret",
    scope: "api",
  };

  beforeEach(() => {
    jest.clearAllMocks();
    client = new GuardhouseNodeClient(mockOptions);
  });

  describe("constructor", () => {
    it("should initialize with options", () => {
      expect(client).toBeDefined();
    });

    it("should initialize token cache", () => {
      expect(client["tokenCache"]).toBeDefined();
      expect(client["tokenCache"] instanceof Map).toBe(true);
    });
  });

  describe("getAccessToken", () => {
    it("should request new token when cache is empty", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: "test-access-token",
          expires_in: 3600,
          refresh_token: "test-refresh-token",
        }),
        text: async () => "",
      } as Response);

      const token = await client.getAccessToken();

      expect(token).toBe("test-access-token");
      expect(mockFetch).toHaveBeenCalled();
    });

    it("should return cached token if not expired", async () => {
      const now = Math.floor(Date.now() / 1000);
      client["tokenCache"].set("guardhouse_access_token_test-client-id", {
        accessToken: "cached-token",
        refreshToken: "cached-refresh-token",
        expiresAt: now + 3600,
      });

      const token = await client.getAccessToken();

      expect(token).toBe("cached-token");
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it("should request new token when cached token is expired", async () => {
      const now = Math.floor(Date.now() / 1000);
      client["tokenCache"].set("guardhouse_access_token_test-client-id", {
        accessToken: "expired-token",
        refreshToken: "expired-refresh-token",
        expiresAt: now - 1,
      });

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: "new-access-token",
          expires_in: 3600,
          refresh_token: "new-refresh-token",
        }),
        text: async () => "",
      } as Response);

      const token = await client.getAccessToken();

      expect(token).toBe("new-access-token");
      expect(mockFetch).toHaveBeenCalled();
    });

    it("should cache new token after request", async () => {
      const now = Math.floor(Date.now() / 1000);

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: "new-access-token",
          expires_in: 3600,
          refresh_token: "new-refresh-token",
        }),
        text: async () => "",
      } as Response);

      await client.getAccessToken();

      const cached = client["tokenCache"].get(
        "guardhouse_access_token_test-client-id",
      );

      expect(cached).toBeDefined();
      expect(cached?.accessToken).toBe("new-access-token");
      expect(cached?.expiresAt).toBeGreaterThan(now);
    });

    it("should use refresh token when available and token is expired", async () => {
      const now = Math.floor(Date.now() / 1000);
      client["tokenCache"].set("guardhouse_access_token_test-client-id", {
        accessToken: "expired-token",
        refreshToken: "valid-refresh-token",
        expiresAt: now - 1,
      });

      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({}),
          text: async () => "",
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            access_token: "refreshed-access-token",
            expires_in: 3600,
            refresh_token: "new-refresh-token",
          }),
          text: async () => "",
        } as Response);

      const token = await client.getAccessToken();

      expect(token).toBeDefined();
      expect(mockFetch).toHaveBeenCalledTimes(2);
    });
  });

  describe("requestToken", () => {
    it("should request token with client credentials", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: "test-access-token",
          expires_in: 3600,
          token_type: "Bearer",
        }),
        text: async () => "",
      } as Response);

      const tokenResponse = await client["requestToken"]();

      expect(tokenResponse.access_token).toBe("test-access-token");
      expect(tokenResponse.expires_in).toBe(3600);
    });

    it("should throw error on failed request", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({
          error: "invalid_client",
          error_description: "Invalid client credentials",
        }),
        text: async () => "",
      } as Response);

      await expect(client["requestToken"]()).rejects.toThrow(
        "Failed to request token",
      );
    });
  });

  describe("refreshToken", () => {
    it("should refresh token with refresh token", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({
          access_token: "refreshed-access-token",
          expires_in: 3600,
          refresh_token: "new-refresh-token",
        }),
        text: async () => "",
      } as Response);

      const tokenResponse = await client["refreshToken"]("test-refresh-token");

      expect(tokenResponse.access_token).toBe("refreshed-access-token");
    });

    it("should throw error on failed refresh", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({
          error: "invalid_grant",
        }),
        text: async () => "",
      } as Response);

      await expect(
        client["refreshToken"]("test-refresh-token"),
      ).rejects.toThrow("Failed to refresh token");
    });
  });

  describe("fetch", () => {
    beforeEach(() => {
      client["tokenCache"].set("guardhouse_access_token_test-client-id", {
        accessToken: "cached-access-token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });
    });

    it("should fetch with authorization header", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: "test" }),
        text: async () => "",
      } as Response);

      await client.fetch("https://api.example.com/data");

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.example.com/data",
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: "Bearer cached-access-token",
            "Content-Type": "application/json",
            "X-Correlation-ID": expect.any(String),
          }),
        }),
      );
    });

    it("should retry on 401 response", async () => {
      mockFetch
        .mockResolvedValueOnce({
          ok: false,
          status: 401,
          json: async () => ({}),
          text: async () => "",
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({
            access_token: "retried-access-token",
            expires_in: 3600,
            token_type: "Bearer",
          }),
          text: async () => "",
        } as Response)
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: async () => ({ data: "test" }),
          text: async () => "",
        } as Response);

      const result = await client.fetch("https://api.example.com/data");

      expect(mockFetch.mock.calls.length).toBeGreaterThanOrEqual(3);
      expect(result).toEqual({ data: "test" });
    });

    it("should throw error after max retries", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 401,
        json: async () => ({}),
        text: async () => "",
      } as Response);

      await expect(
        client.fetch("https://api.example.com/data"),
      ).rejects.toThrow();
    });

    it("should support GET method", async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ data: "test" }),
        text: async () => "",
      } as Response);

      const result = await client.get("https://api.example.com/data");

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.example.com/data",
        expect.objectContaining({
          method: "GET",
        }),
      );
      expect(result).toEqual({ data: "test" });
    });

    it("should support POST method", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: "created" }),
        text: async () => "",
      } as Response);

      const result = await client.post("https://api.example.com/data", {
        test: "data",
      });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.example.com/data",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ test: "data" }),
        }),
      );
      expect(result).toEqual({ result: "created" });
    });

    it("should support PUT method", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: "updated" }),
        text: async () => "",
      } as Response);

      await client.put("https://api.example.com/data/1", {
        test: "data",
      });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.example.com/data/1",
        expect.objectContaining({
          method: "PUT",
        }),
      );
    });

    it("should support DELETE method", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: "deleted" }),
        text: async () => "",
      } as Response);

      await client.delete("https://api.example.com/data/1");

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.example.com/data/1",
        expect.objectContaining({
          method: "DELETE",
        }),
      );
    });

    it("should support PATCH method", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ result: "patched" }),
        text: async () => "",
      } as Response);

      await client.patch("https://api.example.com/data/1", {
        test: "data",
      });

      expect(mockFetch).toHaveBeenCalledWith(
        "https://api.example.com/data/1",
        expect.objectContaining({
          method: "PATCH",
        }),
      );
    });
  });

  describe("clearCache", () => {
    it("should clear token cache", async () => {
      client["tokenCache"].set("guardhouse_access_token_test-client-id", {
        accessToken: "cached-token",
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      });

      await client.clearCache();

      expect(client["tokenCache"].size).toBe(0);
    });
  });
});

describe("GuardhouseAdminClient", () => {
  let adminClient: GuardhouseAdminClient;
  const mockOptions = {
    authority: "https://auth.guardhouse.io",
    clientId: "admin-client-id",
    clientSecret: "admin-client-secret",
  };

  beforeEach(() => {
    jest.clearAllMocks();
    adminClient = new GuardhouseAdminClient(mockOptions);

    mockFetch.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({}),
      text: async () => "",
    } as Response);

    adminClient["tokenCache"].set("guardhouse_access_token_admin-client-id", {
      accessToken: "admin-access-token",
      expiresAt: Math.floor(Date.now() / 1000) + 3600,
    });
  });

  describe("deleteUser", () => {
    it("should delete user successfully", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 204,
        json: async () => ({}),
        text: async () => "",
      } as Response);

      await expect(adminClient.deleteUser("user-123")).resolves.not.toThrow();

      expect(mockFetch).toHaveBeenCalledWith(
        "https://auth.guardhouse.io/api/users/user-123",
        expect.objectContaining({
          method: "DELETE",
        }),
      );
    });

    it("should throw error on failed delete", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ error: "User not found" }),
        text: async () => "User not found",
      } as Response);

      await expect(adminClient.deleteUser("user-123")).rejects.toThrow(
        "Failed to delete user",
      );
    });
  });

  describe("getUser", () => {
    it("should get user successfully", async () => {
      const mockUserData = {
        id: "user-123",
        email: "test@example.com",
        username: "testuser",
      };

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockUserData,
        text: async () => "",
      } as Response);

      const user = await adminClient.getUser("user-123");

      expect(user).toEqual(mockUserData);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://auth.guardhouse.io/api/users/user-123",
        expect.objectContaining({
          method: "GET",
        }),
      );
    });

    it("should throw error on failed get", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ error: "User not found" }),
        text: async () => "User not found",
      } as Response);

      await expect(adminClient.getUser("user-123")).rejects.toThrow(
        "Failed to get user",
      );
    });
  });

  describe("listUsers", () => {
    it("should list users successfully", async () => {
      const mockUsers = [
        { id: "user-1", email: "user1@example.com" },
        { id: "user-2", email: "user2@example.com" },
      ];

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockUsers,
        text: async () => "",
      } as Response);

      const users = await adminClient.listUsers();

      expect(users).toEqual(mockUsers);
    });

    it("should list users with pagination", async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => [],
        text: async () => "",
      } as Response);

      await adminClient.listUsers({ page: 1, pageSize: 20, search: "test" });

      const url = mockFetch.mock.calls[0][0] as string;

      expect(url).toContain("page=1");
      expect(url).toContain("pageSize=20");
      expect(url).toContain("search=test");
    });

    it("should throw error on failed list", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 500,
        json: async () => ({ error: "Server error" }),
        text: async () => "Server error",
      } as Response);

      await expect(adminClient.listUsers()).rejects.toThrow(
        "Failed to list users",
      );
    });
  });

  describe("createUser", () => {
    it("should create user successfully", async () => {
      const newUserData = {
        email: "newuser@example.com",
        username: "newuser",
        password: "password123",
      };

      const createdUser = {
        id: "user-456",
        ...newUserData,
      };

      mockFetch.mockResolvedValue({
        ok: true,
        status: 201,
        json: async () => createdUser,
        text: async () => "",
      } as Response);

      const user = await adminClient.createUser(newUserData);

      expect(user).toEqual(createdUser);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://auth.guardhouse.io/api/users",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify(newUserData),
        }),
      );
    });

    it("should throw error on failed create", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ error: "Invalid input" }),
        text: async () => "Invalid input",
      } as Response);

      await expect(
        adminClient.createUser({ email: "invalid" }),
      ).rejects.toThrow("Failed to create user");
    });
  });

  describe("updateUser", () => {
    it("should update user successfully", async () => {
      const updateData = {
        email: "updated@example.com",
      };

      const updatedUser = {
        id: "user-123",
        ...updateData,
      };

      mockFetch.mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => updatedUser,
        text: async () => "",
      } as Response);

      const user = await adminClient.updateUser("user-123", updateData);

      expect(user).toEqual(updatedUser);
      expect(mockFetch).toHaveBeenCalledWith(
        "https://auth.guardhouse.io/api/users/user-123",
        expect.objectContaining({
          method: "PUT",
        }),
      );
    });

    it("should throw error on failed update", async () => {
      mockFetch.mockResolvedValue({
        ok: false,
        status: 404,
        json: async () => ({ error: "User not found" }),
        text: async () => "User not found",
      } as Response);

      await expect(
        adminClient.updateUser("user-123", { email: "updated@example.com" }),
      ).rejects.toThrow("Failed to update user");
    });
  });
});
