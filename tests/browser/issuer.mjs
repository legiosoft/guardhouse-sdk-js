import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT, jwtVerify } from "jose";

export const issuer = "https://issuer.test/";
export const origin = "https://backoffice.test";

// A deterministic OIDC test server at the browser's HTTP boundary. The SDK,
// Web Crypto, storage, React effects and document navigations are all real.
// This is not a replacement for the release check against deployed Guardhouse.
export async function installIssuer(context, bundle, settings = {}) {
  const key = await generateKeyPair("RS256");
  const jwk = {
    ...(await exportJWK(key.publicKey)),
    kid: "browser-test",
    alg: "RS256",
    use: "sig",
  };
  const codes = new Map();
  const refreshTokens = new Map();
  const accessTokens = new Map();
  const stats = {
    authorize: 0,
    code: 0,
    refresh: 0,
    logout: 0,
    userinfo: 0,
    discovery: 0,
    jwks: 0,
  };
  const controls = { ...settings };
  let loggedIn = false;
  const response = (route, value, status = 200) =>
    route.fulfill({
      status,
      contentType: "application/json",
      headers: { "Access-Control-Allow-Origin": origin },
      body: JSON.stringify(value),
    });
  // Playwright does not intercept the subsequent request in an HTTP redirect
  // chain. A document redirect keeps the entire fixture offline while still
  // exercising real page teardown, history and sessionStorage lifetimes.
  const redirect = (route, target) =>
    route.fulfill({
      contentType: "text/html",
      body: `<script>location.replace(${JSON.stringify(target)})</script>`,
    });
  const hash = (value) =>
    createHash("sha256").update(value).digest("base64url");
  const callback = async (route, url) => {
    const clientId = url.searchParams.get("client_id");
    const redirectUri = url.searchParams.get("redirect_uri");
    assert.ok(["app", "admin"].includes(clientId));
    assert.equal(redirectUri, `${origin}/${clientId}/`);
    assert.equal(url.searchParams.get("code_challenge_method"), "S256");
    assert.ok(url.searchParams.get("nonce"));
    const target = new URL(redirectUri);
    target.searchParams.set("state", url.searchParams.get("state"));
    target.searchParams.set("iss", issuer);
    if (controls.deny) {
      target.searchParams.set("error", "access_denied");
      target.searchParams.set("error_description", "Access was denied");
    } else {
      const code = randomUUID();
      codes.set(code, Object.fromEntries(url.searchParams));
      target.searchParams.set("code", code);
      loggedIn = true;
    }
    await redirect(route, target.href);
  };
  await context.route(`${origin}/**`, async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname === "/bundle.js")
      return route.fulfill({ contentType: "text/javascript", body: bundle });
    await route.fulfill({
      contentType: "text/html",
      body: `<!doctype html><html><body><div id="root"></div><script>window.__settings=${JSON.stringify(controls)}</script><script src="/bundle.js"></script></body></html>`,
    });
  });
  await context.route(`${issuer}**`, async (route) => {
    const url = new URL(route.request().url());
    if (route.request().method() === "OPTIONS")
      return route.fulfill({
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": origin,
          "Access-Control-Allow-Headers":
            "authorization,content-type,cache-control,pragma",
          "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        },
      });
    switch (url.pathname) {
      case "/.well-known/openid-configuration":
        stats.discovery++;
        if (controls.discoveryFailure)
          return response(route, { error: "temporarily_unavailable" }, 503);
        return response(route, {
          issuer,
          authorization_endpoint: `${issuer}connect/authorize`,
          token_endpoint: `${issuer}connect/token`,
          userinfo_endpoint: `${issuer}connect/userinfo`,
          jwks_uri: `${issuer}.well-known/jwks`,
          end_session_endpoint: `${issuer}connect/logout`,
          id_token_signing_alg_values_supported: ["RS256"],
          response_types_supported: ["code"],
          grant_types_supported: ["authorization_code", "refresh_token"],
          subject_types_supported: ["public"],
          code_challenge_methods_supported: ["S256"],
          authorization_response_iss_parameter_supported: true,
        });
      case "/.well-known/jwks":
        stats.jwks++;
        return response(route, { keys: [jwk] });
      case "/connect/authorize":
        stats.authorize++;
        if (stats.authorize > 10)
          return route.fulfill({
            status: 400,
            body: "Authorization loop detected",
          });
        if (loggedIn || controls.deny) return callback(route, url);
        return route.fulfill({
          contentType: "text/html",
          body: `<form action="/login"><input type="hidden" name="request" value="${encodeURIComponent(url.href)}"><button>Sign in to fixture</button></form>`,
        });
      case "/login":
        return callback(
          route,
          new URL(decodeURIComponent(url.searchParams.get("request"))),
        );
      case "/connect/token": {
        const body = new URLSearchParams(route.request().postData());
        const refreshing = body.get("grant_type") === "refresh_token";
        stats[refreshing ? "refresh" : "code"]++;
        if (refreshing && controls.refreshFailure)
          return response(
            route,
            { error: controls.refreshFailure },
            controls.refreshFailure === "invalid_grant" ? 400 : 503,
          );
        const transaction = refreshing
          ? refreshTokens.get(body.get("refresh_token"))
          : codes.get(body.get("code"));
        assert.ok(
          transaction,
          "Only an issued, unused code/refresh token may be exchanged",
        );
        assert.equal(body.get("client_id"), transaction.client_id);
        if (refreshing) refreshTokens.delete(body.get("refresh_token"));
        else {
          assert.equal(
            hash(body.get("code_verifier")),
            transaction.code_challenge,
          );
          assert.equal(body.get("redirect_uri"), transaction.redirect_uri);
          codes.delete(body.get("code"));
        }
        const accessToken = randomUUID();
        const refreshToken = randomUUID().padEnd(
          controls.refreshTokenLength ?? 36,
          "x",
        );
        const subject = "test-subject";
        accessTokens.set(accessToken, subject);
        refreshTokens.set(refreshToken, transaction);
        const payload = {
          sub: subject,
          azp: transaction.client_id,
          nonce: transaction.nonce,
          at_hash: createHash("sha256")
            .update(accessToken)
            .digest()
            .subarray(0, 16)
            .toString("base64url"),
        };
        if (controls.badNonce) payload.nonce = "wrong-nonce";
        const idToken = await new SignJWT(payload)
          .setProtectedHeader({ alg: "RS256", kid: jwk.kid, typ: "JWT" })
          .setIssuer(issuer)
          .setAudience(
            controls.wrongAudience ? "another-client" : transaction.client_id,
          )
          .setIssuedAt()
          .setExpirationTime("20m")
          .sign(key.privateKey);
        const tokens = {
          access_token: accessToken,
          refresh_token: refreshToken,
          token_type: "Bearer",
          expires_in: controls.accessTokenLifetime ?? 1200,
          scope: transaction.scope,
        };
        if (controls.omitRefreshToken) delete tokens.refresh_token;
        if (!(refreshing && controls.omitRefreshIdToken))
          tokens.id_token = idToken;
        if (controls.tokenDelay)
          await new Promise((resolve) =>
            setTimeout(resolve, controls.tokenDelay),
          );
        return response(route, tokens);
      }
      case "/connect/userinfo": {
        stats.userinfo++;
        const subject = accessTokens.get(
          route
            .request()
            .headers()
            .authorization?.replace(/^Bearer /, ""),
        );
        if (!subject) return response(route, { error: "invalid_token" }, 401);
        if (controls.userinfoFailure)
          return response(route, { error: "temporarily_unavailable" }, 503);
        return response(route, {
          sub: controls.wrongSubject ? "another-user" : subject,
          name: "Test User",
          roles: ["Operator"],
        });
      }
      case "/connect/logout": {
        stats.logout++;
        const target = new URL(
          url.searchParams.get("post_logout_redirect_uri"),
        );
        assert.equal(target.origin, origin);
        const expectedClient = target.pathname.split("/")[1];
        if (url.searchParams.has("id_token_hint"))
          await jwtVerify(
            url.searchParams.get("id_token_hint"),
            key.publicKey,
            { issuer, audience: expectedClient },
          );
        if (controls.logoutDelay)
          await new Promise((resolve) =>
            setTimeout(resolve, controls.logoutDelay),
          );
        if (route.request().failure()) return;
        loggedIn = false;
        target.searchParams.set("state", url.searchParams.get("state"));
        return redirect(route, target.href);
      }
      default:
        throw new Error(`Unexpected fixture path: ${url.pathname}`);
    }
  });
  return { stats, controls };
}
