import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import dotenv from "dotenv";
import {
  GuardhouseClient,
  type AuthorizationTransaction,
  type OidcIdentityEvidence,
  type TokenResponse,
  type UserInfoResponse,
} from "@guardhouse/core";
import { GuardhouseNodeClient } from "@guardhouse/node";

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT || 3001);
const AUTHORITY = process.env.AUTHORITY?.trim() || "https://auth.example.com";
const CLIENT_ID = process.env.CLIENT_ID?.trim() || "your-client-id";
const CLIENT_SECRET = process.env.CLIENT_SECRET?.trim() || undefined;
const SERVICE_CLIENT_ID = process.env.SERVICE_CLIENT_ID?.trim();
const SERVICE_CLIENT_SECRET = process.env.SERVICE_CLIENT_SECRET?.trim();
const SERVICE_SCOPE = process.env.SERVICE_SCOPE?.trim();
const REDIRECT_URI =
  process.env.REDIRECT_URI?.trim() || `http://localhost:${PORT}/callback`;
const SCOPE =
  process.env.SCOPE?.trim() || "openid profile email offline_access";
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "http://localhost:5173")
  .split(",")
  .map((origin) => origin.trim())
  .filter(Boolean);

const oauthClient = new GuardhouseClient({
  authority: AUTHORITY,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
});

if (
  [SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET, SERVICE_SCOPE].some(Boolean) &&
  ![SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET, SERVICE_SCOPE].every(Boolean)
) {
  throw new Error(
    "SERVICE_CLIENT_ID, SERVICE_CLIENT_SECRET, and SERVICE_SCOPE must be configured together",
  );
}

const machineClient =
  SERVICE_CLIENT_ID && SERVICE_CLIENT_SECRET && SERVICE_SCOPE
    ? new GuardhouseNodeClient({
        authority: AUTHORITY,
        clientId: SERVICE_CLIENT_ID,
        clientSecret: SERVICE_CLIENT_SECRET,
        scope: SERVICE_SCOPE,
      })
    : null;

const pendingAuthRequests = new Map<string, AuthorizationTransaction>();
const verifiedIdentitiesByAccessToken = new Map<string, OidcIdentityEvidence>();

function prunePendingAuthRequests(): void {
  const now = Date.now();
  for (const [state, request] of pendingAuthRequests.entries()) {
    if (request.expiresAt <= now) {
      pendingAuthRequests.delete(state);
    }
  }
}

const pruneTimer = setInterval(prunePendingAuthRequests, 60_000);
(pruneTimer as unknown as { unref?: () => void }).unref?.();

function redactToken(token?: string): string | null {
  if (!token) {
    return null;
  }

  if (token.length <= 16) {
    return "***";
  }

  return `${token.slice(0, 8)}...${token.slice(-6)}`;
}

function getBearerToken(
  authorizationHeader: string | undefined,
): string | null {
  if (!authorizationHeader) {
    return null;
  }

  const [scheme, token] = authorizationHeader.split(" ");
  if (scheme !== "Bearer" || !token) {
    return null;
  }

  return token;
}

function toPublicTokenResponse(tokens: TokenResponse): Record<string, unknown> {
  return {
    access_token: redactToken(tokens.access_token),
    refresh_token: redactToken(tokens.refresh_token),
    id_token: redactToken(tokens.id_token),
    token_type: tokens.token_type,
    expires_in: tokens.expires_in,
    scope: tokens.scope,
  };
}

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use((req: Request, res: Response, next: NextFunction): void => {
  const origin = req.headers.origin;
  if (origin && CORS_ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  }

  res.setHeader(
    "Access-Control-Allow-Headers",
    "Authorization, Content-Type, X-Requested-With",
  );
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");

  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  next();
});

app.get("/", (_req: Request, res: Response): void => {
  res.json({
    message: "Guardhouse Node.js Example Server",
    authority: AUTHORITY,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    corsOrigins: CORS_ORIGINS,
    endpoints: {
      login: "GET /login",
      callback: "GET /callback",
      token: "POST /token",
      user: "GET /user",
      protected: "GET /protected",
    },
  });
});

app.get("/login", async (_req: Request, res: Response): Promise<void> => {
  try {
    prunePendingAuthRequests();

    const { authorizationUrl, transaction } =
      await oauthClient.createAuthorizationRequest({
        redirectUri: REDIRECT_URI,
        scope: SCOPE,
        audiencePolicy: "oidc-optional",
        allowOfflineAccessScope: true,
      });
    pendingAuthRequests.set(transaction.state, transaction);

    res.json({
      authUrl: authorizationUrl,
      state: transaction.state,
      instructions:
        "Open authUrl in a browser. Guardhouse redirects back to /callback with code and state.",
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      error: "Failed to generate auth URL",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.get("/callback", async (req: Request, res: Response): Promise<void> => {
  try {
    const state =
      typeof req.query["state"] === "string" ? req.query["state"] : "";
    if (!state) {
      res.status(400).json({
        error: "Missing state query parameter",
      });
      return;
    }

    const transaction = pendingAuthRequests.get(state);
    if (!transaction) {
      res.status(400).json({
        error: "State mismatch or expired authorization request",
      });
      return;
    }

    const callbackUrl = new URL(req.originalUrl, REDIRECT_URI).toString();
    const callback = await oauthClient.validateOAuthCallback(
      { mode: "query", url: callbackUrl },
      transaction,
    );
    pendingAuthRequests.delete(state);

    if (callback.type === "error") {
      res.status(400).json({
        error: "Authentication failed",
        details: callback.errorDescription || callback.error,
      });
      return;
    }

    const exchange = await oauthClient.exchangeAuthorizationCode(callback);
    if (exchange.mode !== "oidc") {
      throw new Error("The example requires an OIDC token response");
    }
    const tokens = exchange.tokens;
    verifiedIdentitiesByAccessToken.set(tokens.access_token, exchange.identity);

    let userInfo: UserInfoResponse | null = null;
    try {
      userInfo = await oauthClient.getUserInfo(
        tokens.access_token,
        exchange.identity,
      );
    } catch (userInfoError) {
      console.warn("User info request failed after callback:", userInfoError);
    }

    res.json({
      message: "Authentication successful",
      tokens: toPublicTokenResponse(tokens),
      user: userInfo,
    });
  } catch (error) {
    console.error("Callback error:", error);
    res.status(500).json({
      error: "Failed to exchange authorization code",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.post("/token", async (req: Request, res: Response): Promise<void> => {
  try {
    const grantType =
      typeof req.body["grant_type"] === "string"
        ? req.body["grant_type"]
        : "client_credentials";

    let tokens: TokenResponse;

    if (grantType === "refresh_token") {
      const refreshToken =
        typeof req.body["refresh_token"] === "string"
          ? req.body["refresh_token"]
          : "";

      if (!refreshToken) {
        res.status(400).json({
          error: "Missing refresh_token for refresh_token grant",
        });
        return;
      }
      const previousIdToken =
        typeof req.body["previous_id_token"] === "string"
          ? req.body["previous_id_token"]
          : "";
      if (!previousIdToken) {
        res.status(400).json({
          error: "Missing previous_id_token for an OIDC refresh",
        });
        return;
      }
      const refreshed = await oauthClient.refreshOidcSession(refreshToken, {
        previousIdToken,
        grantedScope:
          typeof req.body["granted_scope"] === "string"
            ? req.body["granted_scope"]
            : SCOPE,
      });
      tokens = refreshed.tokens;
      verifiedIdentitiesByAccessToken.set(
        tokens.access_token,
        refreshed.identity,
      );
    } else if (grantType === "client_credentials") {
      if (!machineClient) {
        res.status(503).json({
          error: "Service client not configured",
        });
        return;
      }
      tokens = await machineClient.requestToken();
    } else {
      res.status(400).json({
        error: "Unsupported grant_type",
        supported_grant_types: ["client_credentials", "refresh_token"],
      });
      return;
    }

    res.json(toPublicTokenResponse(tokens));
  } catch (error) {
    console.error("Token endpoint error:", error);
    res.status(500).json({
      error: "Failed to obtain token",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.get("/user", async (req: Request, res: Response): Promise<void> => {
  const token = getBearerToken(req.headers.authorization);
  if (!token) {
    res.status(401).json({
      error: "Missing or invalid Authorization header",
    });
    return;
  }

  try {
    const identity = verifiedIdentitiesByAccessToken.get(token);
    if (!identity) {
      res.status(401).json({ error: "No verified identity for this token" });
      return;
    }
    const userInfo = await oauthClient.getUserInfo(token, identity);
    res.json({ user: userInfo });
  } catch (error) {
    console.error("User endpoint error:", error);
    res.status(401).json({
      error: "Failed to fetch user info",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.get("/protected", async (req: Request, res: Response): Promise<void> => {
  const token = getBearerToken(req.headers.authorization);
  if (!token) {
    res.status(401).json({
      error: "Unauthorized",
      details: "Missing Bearer token",
    });
    return;
  }

  try {
    const identity = verifiedIdentitiesByAccessToken.get(token);
    if (!identity) {
      res.status(401).json({ error: "No verified identity for this token" });
      return;
    }
    const userInfo = await oauthClient.getUserInfo(token, identity);

    res.json({
      message: "This is a protected resource",
      user: {
        sub: userInfo.sub,
        name: userInfo.name,
        email: userInfo.email,
        roles: userInfo.roles,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Protected endpoint error:", error);
    res.status(401).json({
      error: "Invalid or expired token",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.use(
  (err: Error, _req: Request, res: Response, _next: NextFunction): void => {
    console.error("Unhandled error:", err);
    res.status(500).json({
      error: "Internal server error",
      details: err.message,
    });
  },
);

app.listen(PORT, () => {
  console.log(
    `Guardhouse Node.js example listening on http://localhost:${PORT}`,
  );
  console.log(`Authority: ${AUTHORITY}`);
  console.log(`Client ID: ${CLIENT_ID}`);
  console.log(`Redirect URI: ${REDIRECT_URI}`);
  console.log(`CORS Origins: ${CORS_ORIGINS.join(", ")}`);
});
