import express from "express";
import { guardhouseMiddleware } from "@guardhouse/node";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3002;

const AUTHORITY = process.env.AUTHORITY || "https://auth.example.com";
const AUDIENCE = process.env.AUDIENCE || "your-api-audience";

app.use(express.json());

app.get("/", (req, res) => {
  res.json({
    message: "Guardhouse Resource Server Example",
    endpoints: {
      public: "/public",
      protected: "/protected",
      protectedWithScope: "/protected/admin",
    },
  });
});

app.get("/public", (req, res) => {
  res.json({
    message: "This is a public endpoint",
    timestamp: new Date().toISOString(),
  });
});

app.use(
  "/protected",
  guardhouseMiddleware({
    authority: AUTHORITY,
    audience: AUDIENCE,
  }),
);

app.get("/protected", (req, res) => {
  res.json({
    message: "This is a protected endpoint",
    user: {
      sub: req.user?.sub,
      name: req.user?.name,
      email: req.user?.email,
      roles: req.user?.roles,
    },
    timestamp: new Date().toISOString(),
  });
});

app.get("/protected/admin", (req, res) => {
  const user = req.user;

  if (!user?.roles?.includes("admin")) {
    return res.status(403).json({
      error: "forbidden",
      message: "Admin role required",
    });
  }

  res.json({
    message: "Admin endpoint accessed successfully",
    user: {
      sub: user.sub,
      name: user.name,
      email: user.email,
      roles: user.roles,
    },
    timestamp: new Date().toISOString(),
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Guardhouse Resource Server running on port ${PORT}`);
  console.log(`📖 Public endpoint: http://localhost:${PORT}/public`);
  console.log(`🔒 Protected endpoint: http://localhost:${PORT}/protected`);
  console.log(`👑 Admin endpoint: http://localhost:${PORT}/protected/admin`);
  console.log(`🔐 Authority: ${AUTHORITY}`);
  console.log(`👥 Audience: ${AUDIENCE}`);
});
