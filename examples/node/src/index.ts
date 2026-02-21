import express, {
  type NextFunction,
  type Request,
  type Response,
} from "express";
import dotenv from "dotenv";
import {
  GuardhouseClient,
  generateAuthUrl,
  generatePKCE,
  generateState,
  type TokenResponse,
  type UserInfoResponse,
} from "@guardhouse/core";
import { GuardhouseNodeClient } from "@guardhouse/node";

dotenv.config();

const app = express();

const PORT = Number(process.env.PORT || 3001);
const AUTHORITY = process.env.AUTHORITY?.trim() || "https://auth.example.com";
const CLIENT_ID = process.env.CLIENT_ID?.trim() || "your-client-id";
const CLIENT_SECRET = process.env.CLIENT_SECRET?.trim() || "your-client-secret";
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

const machineClient = new GuardhouseNodeClient({
  authority: AUTHORITY,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  scope: SCOPE,
});

type PendingAuthRequest = {
  codeVerifier: string;
  createdAt: number;
};

const pendingAuthRequests = new Map<string, PendingAuthRequest>();
const pendingAuthTtlMs = 10 * 60 * 1000;

function prunePendingAuthRequests(): void {
  const now = Date.now();
  for (const [state, request] of pendingAuthRequests.entries()) {
    if (now - request.createdAt > pendingAuthTtlMs) {
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

    const { codeVerifier, codeChallenge } = await generatePKCE();
    const state = await generateState(32);

    pendingAuthRequests.set(state, {
      codeVerifier,
      createdAt: Date.now(),
    });

    const authUrl = generateAuthUrl({
      authority: AUTHORITY,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      responseType: "code",
      scope: SCOPE,
      state,
      codeChallenge,
      codeChallengeMethod: "S256",
    });

    res.json({
      authUrl,
      state,
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
    const code = typeof req.query["code"] === "string" ? req.query["code"] : "";
    const state =
      typeof req.query["state"] === "string" ? req.query["state"] : "";
    const error =
      typeof req.query["error"] === "string" ? req.query["error"] : "";
    const errorDescription =
      typeof req.query["error_description"] === "string"
        ? req.query["error_description"]
        : "";

    if (error) {
      res.status(400).json({
        error: "Authentication failed",
        details: errorDescription || error,
      });
      return;
    }

    if (!code || !state) {
      res.status(400).json({
        error: "Missing code or state query parameter",
      });
      return;
    }

    const pendingRequest = pendingAuthRequests.get(state);
    if (!pendingRequest) {
      res.status(400).json({
        error: "State mismatch or expired authorization request",
      });
      return;
    }

    pendingAuthRequests.delete(state);

    const tokens = await oauthClient.exchangeCodeForTokens(
      code,
      pendingRequest.codeVerifier,
      REDIRECT_URI,
    );

    let userInfo: UserInfoResponse | null = null;
    try {
      userInfo = await oauthClient.getUserInfo(tokens.access_token);
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

      tokens = await oauthClient.refreshToken(refreshToken);
    } else if (grantType === "client_credentials") {
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
    const userInfo = await oauthClient.getUserInfo(token);
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
    const userInfo = await oauthClient.getUserInfo(token);

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
