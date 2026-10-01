import { generateKeyPairSync } from "node:crypto";
import jwt from "jsonwebtoken";
import { GuardhouseResourceService, guardhouseMiddleware } from "../middleware";

jest.mock("jwks-rsa");
const mockJwks = require("jwks-rsa");
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const authority = "https://issuer.test/";
const audience = "api-one";

beforeEach(() => {
  jest.clearAllMocks();
  mockJwks.mockReturnValue({
    getSigningKey: (
      _kid: string,
      callback: (
        error: null,
        key: { getPublicKey: () => string | Buffer },
      ) => void,
    ) =>
      callback(null, {
        getPublicKey: () =>
          keys.publicKey.export({ type: "spki", format: "pem" }),
      }),
  });
});

function introspection(overrides: Record<string, unknown> = {}) {
  const body = {
    active: true,
    sub: "test-user",
    iss: authority,
    aud: audience,
    token_type: "Bearer",
    exp: Math.floor(Date.now() / 1000) + 60,
    ...overrides,
  };
  (global.fetch as jest.Mock).mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => "",
  });
  return new GuardhouseResourceService({
    authority,
    audience,
    validationMode: "introspection",
    introspectionClientId: "resource",
    introspectionClientSecret: "test-only",
    introspectionCacheTtlSeconds: 60,
  });
}

test("the public resource service defaults to real JWT signature verification", async () => {
  const token = jwt.sign({ sub: "test-user" }, keys.privateKey, {
    algorithm: "RS256",
    keyid: "test-key",
    issuer: authority,
    audience,
    expiresIn: 60,
  });
  await expect(
    new GuardhouseResourceService({ authority, audience }).validateToken(token),
  ).resolves.toMatchObject({ sub: "test-user" });
});

test("introspection accepts array audiences and roles emitted by Guardhouse", async () => {
  await expect(
    introspection({
      aud: [audience, "other-api"],
      roles: ["Operator"],
    }).validateToken("opaque"),
  ).resolves.toMatchObject({
    aud: [audience, "other-api"],
    roles: ["Operator"],
  });
});

test.each([
  [{ aud: "different-api" }, "audience"],
  [{ aud: undefined }, "audience"],
  [{ iss: "https://different.test/" }, "issuer"],
  [{ exp: Math.floor(Date.now() / 1000) }, "expired"],
  [{ nbf: Math.floor(Date.now() / 1000) + 3600 }, "not yet"],
])(
  "introspection rejects invalid resource claims: %p",
  async (claims, message) => {
    await expect(introspection(claims).validateToken("opaque")).rejects.toThrow(
      message as string,
    );
  },
);

test("default middleware accepts OAuth Bearer introspection without treating it as a JWT typ", async () => {
  introspection();
  const middleware = guardhouseMiddleware({
    authority,
    audience,
    validationMode: "introspection",
    introspectionClientId: "resource",
    introspectionClientSecret: "test-only",
  });
  const next = jest.fn();
  const response = {
    status: jest.fn().mockReturnThis(),
    setHeader: jest.fn().mockReturnThis(),
    json: jest.fn(),
  };
  await middleware(
    { headers: { authorization: "Bearer opaque" } },
    response,
    next,
  );
  expect(next).toHaveBeenCalledTimes(1);
  expect(response.status).not.toHaveBeenCalled();
});
