import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { build } from "esbuild";
import { chromium } from "playwright";
import { installIssuer, issuer, origin } from "./issuer.mjs";

let browser;
let bundle;
before(async () => {
  let alias;
  if (process.env.GUARDHOUSE_BROWSER_CONSUMER_ROOT) {
    const requireConsumer = createRequire(
      join(process.env.GUARDHOUSE_BROWSER_CONSUMER_ROOT, "package.json"),
    );
    alias = Object.fromEntries(
      ["@guardhouse/react", "@guardhouse/core"].map((name) => [
        name,
        join(dirname(requireConsumer.resolve(name)), "index.mjs"),
      ]),
    );
    alias.react = dirname(requireConsumer.resolve("react/package.json"));
    alias["react-dom"] = dirname(
      requireConsumer.resolve("react-dom/package.json"),
    );
  }
  const result = await build({
    entryPoints: ["tests/browser/app.tsx"],
    bundle: true,
    write: false,
    platform: "browser",
    format: "iife",
    alias,
    define: { "process.env.NODE_ENV": '"development"' },
  });
  bundle = result.outputFiles[0].text;
  browser = await chromium.launch({ headless: true });
});
after(async () => {
  await browser?.close();
});

async function fixture(t, settings = {}) {
  const context = await browser.newContext();
  const errors = [];
  context.on("weberror", (error) => errors.push(error.error().message));
  const server = await installIssuer(context, bundle, settings);
  const page = await context.newPage();
  page.setDefaultTimeout(7000);
  t.after(async () => {
    await context.close();
    assert.deepEqual(errors, [], "No uncaught browser errors");
  });
  return { context, page, ...server };
}
async function state(page, value) {
  await page.waitForFunction(
    (expected) =>
      document.querySelector('[data-testid="status"]')?.textContent ===
        expected &&
      (expected !== "authenticated" ||
        document.querySelector('[data-testid="document-kind"]')?.textContent ===
          "application"),
    value,
  );
}
async function signIn(page, client = "app", protectedRoute = false) {
  await page.goto(`${origin}/${client}/`);
  if (!protectedRoute) {
    await state(page, "anonymous");
    await page.getByRole("button", { name: "Login", exact: true }).click();
  }
  await page.getByRole("button", { name: "Sign in to fixture" }).click();
  await state(page, "authenticated");
}
async function expireAccessToken(page) {
  await page.evaluate(() => {
    const key = Object.keys(sessionStorage).find((key) =>
      key.startsWith("gh:v3:session:"),
    );
    const session = JSON.parse(sessionStorage.getItem(key));
    session.expiresAt = 1;
    sessionStorage.setItem(key, JSON.stringify(session));
  });
}

async function storedSession(page) {
  return page.evaluate(() => {
    const key = Object.keys(sessionStorage).find((key) =>
      key.startsWith("gh:v3:session:"),
    );
    return key ? JSON.parse(sessionStorage.getItem(key)) : null;
  });
}

for (const omitRefreshIdToken of [false, true]) {
  test(`rotated tokens survive UserInfo 503 and reload (omit ID token=${omitRefreshIdToken})`, async (t) => {
    const { page, stats, controls } = await fixture(t, {
      omitRefreshIdToken,
      protected: true,
    });
    await signIn(page, "app", true);
    const original = await storedSession(page);
    controls.userinfoFailure = true;
    await expireAccessToken(page);
    await page.getByRole("button", { name: "Concurrent tokens" }).click();
    await page.getByRole("alert").waitFor();
    assert.equal(await page.getByTestId("private").count(), 0);
    assert.equal(await page.getByTestId("subject").textContent(), "");
    const rotated = await storedSession(page);
    assert.ok(
      rotated,
      "A temporary UserInfo failure must not discard rotated credentials",
    );
    assert.notEqual(rotated.refreshToken, original.refreshToken);
    assert.notEqual(rotated.accessToken, original.accessToken);
    assert.equal(stats.refresh, 1);
    await page.reload();
    await page.getByRole("alert").waitFor();
    assert.equal(await page.getByTestId("private").count(), 0);
    assert.deepEqual(await storedSession(page), rotated);
    controls.userinfoFailure = false;
    await page.getByRole("button", { name: "Retry", exact: true }).click();
    await state(page, "authenticated");
    assert.equal(
      stats.refresh,
      1,
      "Recovery must not replay the consumed refresh token",
    );
    assert.equal(stats.code, 1);
    assert.equal(stats.authorize, 1);
    // A further refresh proves that the saved replacement is usable by the issuer.
    await expireAccessToken(page);
    await page.getByRole("button", { name: "Token", exact: true }).click();
    await page.waitForFunction(
      () =>
        document.querySelector('[data-testid="result"]')?.textContent ===
        "done",
    );
    await state(page, "authenticated");
    assert.equal(stats.refresh, 2);
    await page.getByRole("button", { name: "Logout", exact: true }).click();
    await page.getByRole("button", { name: "Sign in to fixture" }).waitFor();
    assert.equal(await storedSession(page), null);
    assert.equal(stats.logout, 1);
  });

  test(`UserInfo subject mismatch after refresh discards credentials (omit ID token=${omitRefreshIdToken})`, async (t) => {
    const { page, stats, controls } = await fixture(t, { omitRefreshIdToken });
    await signIn(page);
    controls.wrongSubject = true;
    await expireAccessToken(page);
    await page.getByRole("button", { name: "Token", exact: true }).click();
    await page.waitForFunction(
      () =>
        document.querySelector('[data-testid="result"]')?.textContent ===
        "no token",
    );
    await state(page, "anonymous");
    assert.equal(await storedSession(page), null);
    assert.equal(await page.getByTestId("subject").textContent(), "");
    assert.equal(stats.refresh, 1);
    assert.equal(stats.authorize, 1);
  });
}

test("logout wins after refresh tokens arrive while UserInfo is still pending", async (t) => {
  const { page, context, stats } = await fixture(t);
  await signIn(page);
  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  let started;
  const pending = new Promise((resolve) => {
    started = resolve;
  });
  await context.route(`${issuer}connect/userinfo`, async (route) => {
    started();
    await gate;
    await route.fallback();
  });
  await expireAccessToken(page);
  await page.getByRole("button", { name: "Token", exact: true }).click();
  await pending;
  await page.getByRole("button", { name: "Logout", exact: true }).click();
  release();
  await state(page, "anonymous");
  await page.reload();
  await state(page, "anonymous");
  assert.equal(await storedSession(page), null);
  assert.equal(stats.logout, 1);
  assert.equal(stats.authorize, 1);
});

for (const strict of [false, true]) {
  test(`complete login, reload, refresh and delayed logout (StrictMode=${strict})`, async (t) => {
    const { page, stats } = await fixture(t, {
      strict,
      protected: true,
      logoutDelay: 350,
    });
    await signIn(page, "app", true);
    assert.equal(stats.code, 1);
    await page.reload();
    await state(page, "authenticated");
    assert.equal(stats.code, 1);
    await expireAccessToken(page);
    await page.getByRole("button", { name: "Concurrent tokens" }).click();
    await page.waitForFunction(
      () =>
        document.querySelector('[data-testid="result"]')?.textContent ===
        "done",
    );
    assert.equal(stats.refresh, 1);
    await page.getByRole("button", { name: "Logout", exact: true }).click();
    await page.getByRole("button", { name: "Sign in to fixture" }).waitFor();
    assert.equal(stats.logout, 1);
    assert.equal(stats.authorize, 2);
  });
}

test("Admin and App sessions stay separate during same-tab navigation and logout", async (t) => {
  const { page, stats } = await fixture(t);
  await signIn(page, "admin");
  await page.goto(`${origin}/app/`);
  await state(page, "anonymous");
  await page.getByRole("button", { name: "Login", exact: true }).click();
  await state(page, "authenticated");
  assert.equal(stats.code, 2);
  await page.getByRole("button", { name: "Logout", exact: true }).click();
  await state(page, "anonymous");
  assert.equal(stats.logout, 1);
  assert.equal(
    await page.evaluate(
      () =>
        Object.keys(sessionStorage).filter((key) =>
          key.startsWith("gh:v3:session:"),
        ).length,
    ),
    1,
  );
});

test("refresh without replacement ID token survives a page reload", async (t) => {
  const { page, stats } = await fixture(t, { omitRefreshIdToken: true });
  await signIn(page);
  await expireAccessToken(page);
  await page.getByRole("button", { name: "Token", exact: true }).click();
  await page.waitForFunction(
    () =>
      document.querySelector('[data-testid="result"]')?.textContent === "done",
  );
  await page.reload();
  await state(page, "authenticated");
  assert.equal(stats.refresh, 1);
});

test("an opaque refresh token larger than an extension parameter can be rotated", async (t) => {
  const { page, stats } = await fixture(t, { refreshTokenLength: 8192 });
  await signIn(page);
  await expireAccessToken(page);
  await page.getByRole("button", { name: "Token", exact: true }).click();
  await page.waitForFunction(
    () =>
      document.querySelector('[data-testid="result"]')?.textContent === "done",
  );
  await state(page, "authenticated");
  assert.equal(stats.refresh, 1);
  await page.reload();
  await state(page, "authenticated");
});

test("a short-lived access token without refresh remains usable until expiration", async (t) => {
  const { page, stats } = await fixture(t, {
    omitRefreshToken: true,
    accessTokenLifetime: 30,
    config: { scope: "openid profile", allowOfflineAccessScope: false },
  });
  await signIn(page);
  await page.getByRole("button", { name: "Token", exact: true }).click();
  await page.waitForFunction(
    () =>
      document.querySelector('[data-testid="result"]')?.textContent === "done",
  );
  await state(page, "authenticated");
  assert.equal(stats.refresh, 0);
  assert.equal(stats.code, 1);
  await expireAccessToken(page);
  await page.getByRole("button", { name: "Token", exact: true }).click();
  await page.waitForFunction(
    () =>
      document.querySelector('[data-testid="result"]')?.textContent ===
      "no token",
  );
  await state(page, "anonymous");
  assert.equal(stats.refresh, 0);
});

for (const attack of ["badNonce", "wrongAudience", "wrongSubject"]) {
  test(`rejects ${attack} without disclosing authenticated content or restarting login`, async (t) => {
    const { page, stats } = await fixture(t, {
      [attack]: true,
      protected: true,
    });
    await page.goto(`${origin}/app/`);
    await page.getByRole("button", { name: "Sign in to fixture" }).click();
    await page.getByRole("alert").waitFor();
    assert.equal(await page.getByTestId("private").count(), 0);
    assert.equal(stats.authorize, 1);
    assert.equal(stats.code, 1);
  });
}

test("denied authorization shows an error and only retries after a click", async (t) => {
  const { page, stats, controls } = await fixture(t, {
    deny: true,
    protected: true,
  });
  await page.goto(`${origin}/app/`);
  await page.getByRole("alert").waitFor();
  assert.equal(stats.authorize, 1);
  controls.deny = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByRole("button", { name: "Sign in to fixture" }).waitFor();
});

test("discovery failure is retryable without a redirect loop", async (t) => {
  const { page, stats, controls } = await fixture(t, {
    discoveryFailure: true,
    protected: true,
  });
  await page.goto(`${origin}/app/`);
  await page.getByRole("alert").waitFor();
  assert.equal(stats.authorize, 0);
  controls.discoveryFailure = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByRole("button", { name: "Sign in to fixture" }).waitFor();
});

test("equivalent inline config does not restart session restoration on a parent render", async (t) => {
  const { page, stats } = await fixture(t, { unstableConfig: true });
  await signIn(page);
  const requests = stats.userinfo;
  await page.getByRole("button", { name: "Parent render" }).click();
  await page.getByRole("button", { name: "Token", exact: true }).click();
  await page.waitForFunction(
    () =>
      document.querySelector('[data-testid="result"]')?.textContent === "done",
  );
  assert.equal(stats.userinfo, requests);
});

test("issuer mismatch fails closed before authorization", async (t) => {
  const { page, stats } = await fixture(t, {
    protected: true,
    config: { authority: issuer.slice(0, -1) },
  });
  await page.goto(`${origin}/app/`);
  await page.getByRole("alert").waitFor();
  assert.equal(stats.authorize, 0);
  assert.match(await page.getByTestId("error").textContent(), /issuer/i);
});

test("temporary UserInfo outage keeps the session and Retry restores it", async (t) => {
  const { page, stats, controls } = await fixture(t, { protected: true });
  await signIn(page, "app", true);
  controls.userinfoFailure = true;
  await page.reload();
  await page.getByRole("alert").waitFor();
  assert.equal(await page.getByTestId("private").count(), 0);
  assert.equal(stats.authorize, 1);
  controls.userinfoFailure = false;
  await page.getByRole("button", { name: "Retry", exact: true }).click();
  await state(page, "authenticated");
  assert.equal(stats.code, 1);
});

test("invalid refresh token clears the session and starts one new login", async (t) => {
  const { page, stats, controls } = await fixture(t, { protected: true });
  await signIn(page, "app", true);
  controls.refreshFailure = "invalid_grant";
  await expireAccessToken(page);
  const replacement = page.waitForResponse(
    (response) =>
      response.url() === `${issuer}connect/token` &&
      response.request().postData()?.includes("grant_type=authorization_code"),
  );
  await page.getByRole("button", { name: "Token", exact: true }).click();
  await replacement;
  await state(page, "authenticated");
  assert.equal(stats.refresh, 1);
  assert.equal(stats.authorize, 2);
  assert.equal(stats.code, 2);
});

test("logout wins over an in-flight refresh and double clicks", async (t) => {
  const { page, stats, controls } = await fixture(t, { tokenDelay: 500 });
  await signIn(page);
  await expireAccessToken(page);
  const refreshStarted = page.waitForRequest(
    (request) =>
      request.url() === `${issuer}connect/token` &&
      request.postData()?.includes("grant_type=refresh_token"),
  );
  await page.getByRole("button", { name: "Token", exact: true }).click();
  await refreshStarted;
  await page.getByRole("button", { name: "Logout", exact: true }).dblclick();
  await state(page, "anonymous");
  controls.tokenDelay = 0;
  await page.reload();
  await state(page, "anonymous");
  assert.equal(stats.logout, 1);
  assert.equal(
    await page.evaluate(
      () =>
        Object.keys(sessionStorage).filter((key) =>
          key.startsWith("gh:v3:session:"),
        ).length,
    ),
    0,
  );
});

test("a new assurance requirement is enforced after configuration changes", async (t) => {
  const { page, stats, controls } = await fixture(t);
  await signIn(page);
  controls.config = { requiredAmrValues: ["mfa"] };
  await page.reload();
  await state(page, "anonymous");
  assert.equal(stats.code, 1);
  assert.equal(await page.getByTestId("subject").textContent(), "");
});
