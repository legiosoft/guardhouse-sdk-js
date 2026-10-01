import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";
import { build } from "esbuild";
import { chromium } from "playwright";

// The JSON file contains public client configuration only. A fresh browser
// profile is used. Credentials are entered by the user directly at the IdP;
// neither credentials nor token values are logged or persisted by this script.
const [configurationFile, retryFile] = process.argv.slice(2);
if (!configurationFile)
  throw new Error(
    "Usage: node scripts/check-live-browser.mjs <public-client-config.json>",
  );
const clients = JSON.parse(await readFile(configurationFile, "utf8"));
assert.ok(Array.isArray(clients) && clients.length > 0);
const origin = new URL(clients[0].redirectUri).origin;
for (const client of clients) {
  assert.equal(new URL(client.redirectUri).origin, origin);
  assert.equal(new URL(client.authority).protocol, "https:");
}
const buildOptions = {
  entryPoints: ["tests/browser/app.tsx"],
  bundle: true,
  write: false,
  platform: "browser",
  format: "iife",
  define: { "process.env.NODE_ENV": '"production"' },
};
let result = await build(buildOptions);
const browser = await chromium.launch({
  channel: process.env.GUARDHOUSE_TEST_BROWSER_CHANNEL || "msedge",
  headless: false,
});
const context = await browser.newContext();
const settings = {
  clients,
  protected: true,
  live: true,
  config: { debug: true },
};
// Playwright only routes the first request in an HTTP redirect chain. Turn
// IdP document redirects into equivalent document navigations so the callback
// is served by the local candidate instead of falling through to the deployed
// application. Requests, response cookies and token endpoints remain real.
for (const authorityOrigin of new Set(
  clients.map((client) => new URL(client.authority).origin),
)) {
  await context.route(`${authorityOrigin}/**`, async (route) => {
    try {
      if (!route.request().isNavigationRequest()) return route.continue();
      const response = await route.fetch({ maxRedirects: 0 });
      if (new URL(route.request().url()).pathname === "/connect/logout") {
        serverLogoutStatuses.push(response.status());
      }
      const headers = response.headers();
      if ([301, 302, 303].includes(response.status()) && headers.location) {
        const target = new URL(headers.location, route.request().url()).href;
        const escapedTarget = target
          .replaceAll("&", "&amp;")
          .replaceAll('"', "&quot;")
          .replaceAll("<", "&lt;");
        delete headers.location;
        delete headers["content-length"];
        delete headers["content-encoding"];
        headers["content-type"] = "text/html; charset=utf-8";
        return route.fulfill({
          response,
          status: 200,
          headers,
          body: `<!doctype html><meta http-equiv="refresh" content="0;url=${escapedTarget}">`,
        });
      }
      return route.fulfill({ response });
    } catch {
      // A failed navigation may include an ID-token hint in its exception URL.
      await route.abort().catch(() => {});
    }
  });
}
await context.route(`${origin}/**`, async (route) => {
  const path = new URL(route.request().url()).pathname;
  if (path === "/sdk-candidate.js")
    return route.fulfill({
      contentType: "text/javascript",
      body: result.outputFiles[0].text,
    });
  if (
    !clients.some((client) =>
      path.startsWith(new URL(client.redirectUri).pathname),
    )
  )
    return route.abort();
  return route.fulfill({
    contentType: "text/html",
    body: `<!doctype html><html><head><title>Guardhouse SDK candidate verification</title></head><body><div id="root"></div><script>window.__settings=${JSON.stringify(settings)}</script><script src="/sdk-candidate.js"></script></body></html>`,
  });
});
const page = await context.newPage();
let stage = "startup";
const errors = [];
const refreshRequests = new Map();
const serverLogoutStatuses = [];
page.on("pageerror", () => errors.push("Uncaught browser error"));
page.on("console", async (message) => {
  if (!message.text().includes("Token refresh failed")) return;
  const details = await message
    .args()
    .at(-1)
    ?.jsonValue()
    .catch(() => null);
  const error = typeof details?.error === "string" ? details.error : "";
  if (error.includes("refreshToken exceeds maximum allowed length")) {
    console.log("DIAGNOSTIC refresh token rejected by SDK length limit");
  }
});
page.on("response", async (response) => {
  if (new URL(response.url()).pathname !== "/connect/token") return;
  const data = await response.json().catch(() => null);
  if (!data) return;
  console.log(
    "TOKEN_RESPONSE_METADATA",
    JSON.stringify({
      status: response.status(),
      hasRefresh: typeof data.refresh_token === "string",
      refreshLength:
        typeof data.refresh_token === "string" ? data.refresh_token.length : 0,
      hasIdToken: typeof data.id_token === "string",
    }),
  );
});
page.on("domcontentloaded", () => {
  const url = new URL(page.url());
  const client = clients.find((client) =>
    url.href.startsWith(client.redirectUri),
  );
  console.log(
    client ? `PAGE candidate ${client.clientId}` : "PAGE identity server",
  );
});
page.on("request", (request) => {
  const url = new URL(request.url());
  if (url.pathname !== "/connect/token" || request.method() !== "POST") return;
  const body = new URLSearchParams(request.postData());
  if (body.get("grant_type") !== "refresh_token") return;
  const clientId = body.get("client_id");
  refreshRequests.set(clientId, (refreshRequests.get(clientId) ?? 0) + 1);
});
const waitForAuthentication = async () => {
  await page.waitForFunction(
    () =>
      (document.querySelector('[data-testid="status"]')?.textContent ===
        "authenticated" &&
        document.querySelector('[data-testid="document-kind"]')?.textContent ===
          "application") ||
      document.querySelector('[data-testid="error"]')?.textContent,
    null,
    { timeout: 10 * 60 * 1000 },
  );
  const status = await page.getByTestId("status").textContent();
  if (status !== "authenticated")
    throw new Error("Candidate reported an authentication error");
};
async function verify() {
  try {
    // First establish both client sessions in the same tab. This is the original
    // cross-application scenario and exercises actual Guardhouse SSO.
    for (const client of clients) {
      stage = `login:${client.clientId}`;
      console.log(`WAITING_FOR_SIGN_IN ${client.clientId}`);
      await page.goto(client.redirectUri);
      await waitForAuthentication();
      console.log(`PASS login ${client.clientId}`);
      stage = `reload:${client.clientId}`;
      await page.reload();
      await waitForAuthentication();
      console.log(`PASS reload ${client.clientId}`);
      stage = `refresh:${client.clientId}`;
      const refreshCount = refreshRequests.get(client.clientId) ?? 0;
      const metadata = await page.evaluate((clientId) => {
        const key = Object.keys(sessionStorage).find(
          (key) =>
            key.startsWith("gh:v3:session:") &&
            JSON.parse(sessionStorage.getItem(key)).clientId === clientId,
        );
        if (!key) throw new Error("Expected client session missing");
        const session = JSON.parse(sessionStorage.getItem(key));
        session.expiresAt = 1;
        sessionStorage.setItem(key, JSON.stringify(session));
        return {
          hasRefresh: typeof session.refreshToken === "string",
          refreshLength: session.refreshToken?.length ?? 0,
        };
      }, client.clientId);
      console.log("SESSION_METADATA", JSON.stringify(metadata));
      await page
        .getByRole("button", { name: "Concurrent tokens", exact: true })
        .click();
      await page.waitForFunction(
        () =>
          document.querySelector('[data-testid="result"]')?.textContent ===
          "done",
        null,
        { timeout: 30000 },
      );
      await waitForAuthentication();
      assert.equal(refreshRequests.get(client.clientId), refreshCount + 1);
      console.log(`PASS concurrent refresh ${client.clientId}`);
    }
    for (const client of [...clients].reverse()) {
      stage = `logout:${client.clientId}`;
      if (
        new URL(page.url()).pathname !== new URL(client.redirectUri).pathname
      ) {
        console.log(`WAITING_FOR_SIGN_IN_IF_REQUIRED ${client.clientId}`);
        await page.goto(client.redirectUri);
        await waitForAuthentication();
      }
      const logoutResponse = page.waitForResponse(
        (response) => new URL(response.url()).pathname === "/connect/logout",
        { timeout: 30000 },
      );
      await page.getByRole("button", { name: "Logout", exact: true }).click();
      const response = await logoutResponse;
      assert.equal(
        response.status(),
        200,
        "Test document redirect must be delivered",
      );
      assert.ok(
        [302, 303].includes(serverLogoutStatuses.at(-1)),
        "Logout must redirect successfully",
      );
      await page.waitForURL(
        (url) =>
          url.origin === new URL(client.authority).origin &&
          /\/account\/login/i.test(url.pathname),
        { timeout: 30000 },
      );
      console.log(`PASS logout ${client.clientId}`);
    }
    assert.equal(errors.length, 0);
    console.log(
      "PASS real Guardhouse SDK round trips; candidate UI, not Forstter business screens",
    );
    return true;
  } catch (error) {
    // Browser exception messages can contain redirect URLs and ID-token hints.
    // Emit only the stage and error class, never the raw message or stack.
    const providerError = await page
      .getByTestId("error")
      .textContent({ timeout: 1000 })
      .catch(() => "");
    const categories = [
      "issuer",
      "nonce",
      "audience",
      "signature",
      "userinfo",
      "scope",
      "expired",
      "storage",
      "network",
    ];
    console.error(
      JSON.stringify({
        result: "FAILED",
        stage,
        errorType: error?.name ?? "Error",
        providerErrorCategories: categories.filter((category) =>
          providerError?.toLowerCase().includes(category),
        ),
      }),
    );
    return false;
  }
}
try {
  while (!(await verify())) {
    if (!retryFile) {
      process.exitCode = 1;
      break;
    }
    await writeFile(retryFile, "", "utf8");
    console.log("WAITING_FOR_LOCAL_RETRY; browser remains open");
    let command = "";
    while (!command) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      command = (await readFile(retryFile, "utf8").catch(() => "")).trim();
    }
    if (command !== "retry") {
      process.exitCode = 1;
      break;
    }
    errors.length = 0;
    result = await build(buildOptions);
  }
} finally {
  await context.close();
  await browser.close();
}
