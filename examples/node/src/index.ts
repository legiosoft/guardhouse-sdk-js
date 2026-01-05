import express from "express";
import dotenv from "dotenv";
import {
  GuardhouseClient,
  generateAuthUrl,
  generatePKCE,
  User,
  GuardhouseError,
} from "@guardhouse/node";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

const AUTHORITY = process.env.AUTHORITY || "https://auth.example.com";
const CLIENT_ID = process.env.CLIENT_ID || "your-client-id";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "your-client-secret";
const REDIRECT_URI =
  process.env.REDIRECT_URI || "http://localhost:3001/callback";

const client = new GuardhouseClient({
  authority: AUTHORITY,
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.json({
    message: "Guardhouse Node.js Example Server",
    endpoints: {
      login: "/login",
      callback: "/callback",
      user: "/user",
      protected: "/protected",
    },
  });
});

app.get("/login", async (req, res) => {
  try {
    const { codeVerifier, codeChallenge } = await generatePKCE();
    const state = Buffer.from(crypto.randomUUID()).toString("base64url");

    const authUrl = await generateAuthUrl({
      authority: AUTHORITY,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      responseType: "code",
      scope: "openid profile email offline_access",
      state,
      codeChallenge,
      codeChallengeMethod: "S256",
    });

    res.json({
      authUrl,
      codeVerifier,
      state,
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      error: "Failed to generate auth URL",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.get("/callback", async (req, res) => {
  try {
    const { code, state, error } = req.query;

    if (error) {
      return res.status(400).json({
        error: "Authentication failed",
        details: error,
      });
    }

    if (!code) {
      return res.status(400).json({
        error: "Missing authorization code",
      });
    }

    const codeVerifier = req.query.code_verifier as string;

    if (!codeVerifier) {
      return res.status(400).json({
        error: "Missing code verifier",
      });
    }

    const tokenResponse = await fetch(`${AUTHORITY}/connect/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: code as string,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        code_verifier: codeVerifier,
      }),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      throw new Error(`Token exchange failed: ${errorText}`);
    }

    const tokens = await tokenResponse.json();

    res.json({
      message: "Authentication successful",
      access_token: tokens.access_token.substring(0, 20) + "...",
      refresh_token: tokens.refresh_token
        ? tokens.refresh_token.substring(0, 20) + "..."
        : null,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
    });
  } catch (error) {
    console.error("Callback error:", error);
    res.status(500).json({
      error: "Failed to exchange authorization code",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.get("/user", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Missing or invalid authorization header",
    });
  }

  const accessToken = authHeader.substring(7);

  try {
    const userResponse = await fetch(`${AUTHORITY}/connect/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!userResponse.ok) {
      return res.status(userResponse.status).json({
        error: "Failed to fetch user info",
      });
    }

    const user: User = await userResponse.json();

    res.json({
      user,
    });
  } catch (error) {
    console.error("User info error:", error);
    res.status(500).json({
      error: "Failed to fetch user info",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.post("/token", async (req, res) => {
  try {
    const { grant_type, refresh_token, username, password } = req.body;

    const body: Record<string, string> = {
      grant_type: grant_type || "client_credentials",
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    };

    if (refresh_token) {
      body.refresh_token = refresh_token;
    }

    if (username && password) {
      body.username = username;
      body.password = password;
    }

    const tokenResponse = await fetch(`${AUTHORITY}/connect/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams(body),
    });

    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      return res.status(tokenResponse.status).json({
        error: "Token request failed",
        details: errorText,
      });
    }

    const tokens = await tokenResponse.json();

    res.json({
      access_token: tokens.access_token.substring(0, 20) + "...",
      refresh_token: tokens.refresh_token
        ? tokens.refresh_token.substring(0, 20) + "..."
        : null,
      expires_in: tokens.expires_in,
      token_type: tokens.token_type,
    });
  } catch (error) {
    console.error("Token error:", error);
    res.status(500).json({
      error: "Failed to obtain token",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.post("/protected", async (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "Unauthorized",
    });
  }

  const accessToken = authHeader.substring(7);

  try {
    const userResponse = await fetch(`${AUTHORITY}/connect/userinfo`, {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    });

    if (!userResponse.ok) {
      return res.status(userResponse.status).json({
        error: "Invalid or expired token",
      });
    }

    const user: User = await userResponse.json();

    res.json({
      message: "This is a protected resource",
      user: {
        sub: user.sub,
        name: user.name,
        email: user.email,
      },
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Protected endpoint error:", error);
    res.status(500).json({
      error: "Failed to process request",
      details: error instanceof Error ? error.message : "Unknown error",
    });
  }
});

app.use(
  (
    err: Error,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    console.error("Unhandled error:", err);
    res.status(500).json({
      error: "Internal server error",
      details: err.message,
    });
  },
);

app.listen(PORT, () => {
  console.log(`🚀 Guardhouse Node.js Example Server running on port ${PORT}`);
  console.log(`📖 Visit http://localhost:${PORT} for available endpoints`);
  console.log(`🔐 Authority: ${AUTHORITY}`);
  console.log(`👤 Client ID: ${CLIENT_ID}`);
});
