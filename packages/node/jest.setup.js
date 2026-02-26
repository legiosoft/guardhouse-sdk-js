/**
 * Jest Setup for Guardhouse Node SDK
 *
 * This file sets up mocks for external dependencies and provides
 * helper functions for testing.
 */

/**
 * Mock for jsonwebtoken
 */
const mockJwt = {
  verify: jest.fn(),
  sign: jest.fn(),
  decode: jest.fn(),
};

/**
 * Mock for jwks-rsa
 */
const mockJwksClient = jest.fn((options) => ({
  getSigningKey: jest.fn((kid, callback) => {
    callback(null, {
      getPublicKey: jest.fn(() => "mock_public_key"),
    });
  }),
}));

/**
 * Mock fetch for HTTP requests
 */
function createMockHeaders() {
  if (typeof Headers === "function") {
    return new Headers({
      "Content-Type": "application/json",
    });
  }

  return {
    get: () => null,
    set: () => undefined,
    has: () => false,
    delete: () => undefined,
  };
}

function normalizeFetchResponse(response = {}) {
  const normalized = {
    ok: true,
    status: 200,
    json: () => Promise.resolve({}),
    text: () => Promise.resolve(""),
    headers: createMockHeaders(),
    ...response,
  };

  if (!normalized.headers || typeof normalized.headers.get !== "function") {
    normalized.headers = createMockHeaders();
  }

  if (typeof normalized.json !== "function") {
    normalized.json = () => Promise.resolve({});
  }

  const providedText =
    typeof normalized.text === "function" ? normalized.text : undefined;
  normalized.text = async () => {
    const textValue = providedText ? await providedText() : "";
    if (typeof textValue === "string" && textValue.length > 0) {
      return textValue;
    }

    if (typeof normalized.json === "function") {
      try {
        const body = await normalized.json();
        return typeof body === "string" ? body : JSON.stringify(body);
      } catch {
        return "";
      }
    }

    return "";
  };

  return normalized;
}

const fetchMock = jest.fn(() => Promise.resolve(normalizeFetchResponse()));
const originalMockResolvedValue = fetchMock.mockResolvedValue.bind(fetchMock);
const originalMockResolvedValueOnce =
  fetchMock.mockResolvedValueOnce.bind(fetchMock);

fetchMock.mockResolvedValue = (value) =>
  originalMockResolvedValue(normalizeFetchResponse(value));
fetchMock.mockResolvedValueOnce = (value) =>
  originalMockResolvedValueOnce(normalizeFetchResponse(value));

global.fetch = fetchMock;

/**
 * Setup mocks before tests run
 */
beforeAll(() => {
  jest.mock("jsonwebtoken", () => mockJwt);
  jest.mock("jwks-rsa", () => ({ __esModule: true, default: mockJwksClient }));
});

/**
 * Clear mocks between tests
 */
beforeEach(() => {
  mockJwt.verify.mockClear();
  mockJwt.sign.mockClear();
  mockJwt.decode.mockClear();
  mockJwksClient.mockClear();
});

/**
 * Cleanup after tests
 */
afterAll(() => {
  jest.clearAllMocks();
});

/**
 * Helper to create a mock JWT token
 */
function createMockJwtToken(overrides = {}) {
  const header = Buffer.from(
    JSON.stringify({ alg: "RS256", typ: "JWT", kid: "mock-key-id" }),
  ).toString("base64");
  const payload = Buffer.from(
    JSON.stringify({
      sub: "user-123",
      iss: "https://auth.guardhouse.io",
      aud: "test-audience",
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      ...overrides,
    }),
  ).toString("base64");
  const signature = "mock-signature";
  return `${header}.${payload}.${signature}`;
}

/**
 * Helper to mock JWT verification success
 */
function mockJwtVerifySuccess(decodedPayload) {
  mockJwt.verify.mockReturnValue(decodedPayload);
}

/**
 * Helper to mock JWT verification failure
 */
function mockJwtVerifyFailure(error) {
  mockJwt.verify.mockImplementation(() => {
    throw error;
  });
}

/**
 * Helper to mock fetch response
 */
function mockFetchResponse(response) {
  global.fetch.mockResolvedValueOnce({
    ok: response.ok !== undefined ? response.ok : true,
    status: response.status || 200,
    json: () => Promise.resolve(response.json || {}),
    text: () => Promise.resolve(response.text || ""),
  });
}

/**
 * Helper to mock fetch error
 */
function mockFetchError(error) {
  global.fetch.mockRejectedValueOnce(error);
}
