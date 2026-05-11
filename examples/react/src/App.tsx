import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  useNavigate,
} from "react-router-dom";
import { GuardhouseProvider, useAuth } from "@guardhouse/react";
import type { AppState } from "@guardhouse/react";
import { useEffect, useMemo, useState } from "react";
import { appConfig } from "./config";

type ProfileUser = {
  sub: string;
  name?: string;
  email?: string;
  picture?: string;
  roles?: string[];
  scopes?: string[];
  [key: string]: unknown;
};

function getInitials(user: ProfileUser | null | undefined) {
  const name = typeof user?.name === "string" ? user.name.trim() : "";
  const email = typeof user?.email === "string" ? user.email.trim() : "";
  const source = name || email || "User";

  return source
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase() ?? "")
    .join("");
}

function formatUserField(value: unknown) {
  if (value == null || value === "") {
    return "N/A";
  }

  if (Array.isArray(value)) {
    return value.length > 0 ? value.join(", ") : "N/A";
  }

  if (typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }

  return String(value);
}

function Home() {
  const { user, isAuthenticated, isLoading, error, loginWithRedirect, logout } =
    useAuth();

  const handleLogin = () => {
    void loginWithRedirect({
      appState: { returnTo: "/" },
      scope: appConfig.scope,
      audience: appConfig.audience,
    });
  };

  const handleLogout = () => {
    void logout();
  };

  if (isLoading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
        Loading...
      </div>
    );
  }

  return (
    <div className="card">
      <h1>Welcome to Guardhouse React Example</h1>

      {error && (
        <div className="error">
          <strong>Error:</strong> {error}
        </div>
      )}

      {isAuthenticated && user ? (
        <>
          <p>You are logged in as {user.name || user.sub}</p>

          <div className="info-grid">
            <div className="info-item">
              <div className="info-label">Subject</div>
              <div className="info-value">{user.sub}</div>
            </div>

            {user.name && (
              <div className="info-item">
                <div className="info-label">Name</div>
                <div className="info-value">{user.name}</div>
              </div>
            )}

            {user.email && (
              <div className="info-item">
                <div className="info-label">Email</div>
                <div className="info-value">{user.email}</div>
              </div>
            )}

            {user.roles && user.roles.length > 0 && (
              <div className="info-item">
                <div className="info-label">Roles</div>
                <div className="info-value">{user.roles.join(", ")}</div>
              </div>
            )}
          </div>

          <button className="button" onClick={handleLogout}>
            Logout
          </button>
        </>
      ) : (
        <>
          <p>Please log in to access the application.</p>
          <button className="button" onClick={handleLogin}>
            Login
          </button>
        </>
      )}
    </div>
  );
}

function ProtectedPage() {
  const { user, isAuthenticated, isLoading, error } = useAuth();

  if (isLoading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
        Loading...
      </div>
    );
  }

  if (!isAuthenticated) {
    return (
      <div className="card">
        <h2>Access Denied</h2>
        <p>You need to log in to access this page.</p>
        <Link to="/">
          <button className="button">Go to Home</button>
        </Link>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Protected Page</h2>

      {error && (
        <div className="error">
          <strong>Error:</strong> {error}
        </div>
      )}

      <p>
        Welcome to the protected page! You are authenticated as{" "}
        {user?.name || user?.sub}.
      </p>

      <div className="info-grid">
        <div className="info-item">
          <div className="info-label">User ID</div>
          <div className="info-value">{user?.sub}</div>
        </div>

        <div className="info-item">
          <div className="info-label">Name</div>
          <div className="info-value">{user?.name || "N/A"}</div>
        </div>

        <div className="info-item">
          <div className="info-label">Email</div>
          <div className="info-value">{user?.email || "N/A"}</div>
        </div>

        <div className="info-item">
          <div className="info-label">Roles</div>
          <div className="info-value">{user?.roles?.join(", ") || "None"}</div>
        </div>
      </div>

      <Link to="/">
        <button className="button secondary">Back to Home</button>
      </Link>
    </div>
  );
}

function UserInfoPage() {
  const {
    user,
    isAuthenticated,
    isLoading,
    error,
    loginWithRedirect,
    getAccessToken,
  } = useAuth();
  const [profile, setProfile] = useState<ProfileUser | null>(null);
  const [profileError, setProfileError] = useState<string | null>(null);
  const [isProfileLoading, setIsProfileLoading] = useState(false);

  useEffect(() => {
    if (!isAuthenticated || !user) {
      setProfile(null);
      setProfileError(null);
      setIsProfileLoading(false);
      return;
    }

    let isMounted = true;

    const loadProfile = async () => {
      setIsProfileLoading(true);
      setProfileError(null);

      try {
        const token = await getAccessToken();

        if (!token) {
          throw new Error("No access token available");
        }

        const response = await fetch(appConfig.userInfoEndpoint, {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/json",
          },
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = (await response.json()) as ProfileUser;

        if (!data.sub) {
          throw new Error("UserInfo response does not include subject");
        }

        if (isMounted) {
          setProfile(data);
        }
      } catch (err) {
        if (isMounted) {
          setProfile(null);
          setProfileError(
            err instanceof Error ? err.message : "Failed to load user info",
          );
        }
      } finally {
        if (isMounted) {
          setIsProfileLoading(false);
        }
      }
    };

    void loadProfile();

    return () => {
      isMounted = false;
    };
  }, [getAccessToken, isAuthenticated, user]);

  if (isLoading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
        Loading...
      </div>
    );
  }

  if (!isAuthenticated || !user) {
    return (
      <div className="card">
        <h2>User Info</h2>
        <p>You need to log in to view your profile information.</p>
        <button
          className="button"
          onClick={() =>
            void loginWithRedirect({
              appState: { returnTo: "/userinfo" },
              scope: appConfig.scope,
              audience: appConfig.audience,
            })
          }
        >
          Login
        </button>
      </div>
    );
  }

  const displayedUser = profile ?? user;
  const primaryFields = [
    ["Subject", displayedUser.sub],
    ["Name", displayedUser.name],
    ["Email", displayedUser.email],
    ["Roles", displayedUser.roles],
    ["Scopes", displayedUser.scopes],
  ] as const;

  const extraFields = Object.entries(displayedUser).filter(
    ([key]) =>
      !["sub", "name", "email", "roles", "scopes", "picture"].includes(key),
  );

  const avatarUrl =
    typeof displayedUser.picture === "string" ? displayedUser.picture : null;

  return (
    <div className="card">
      <div className="profile-header">
        <div className="profile-avatar">
          {avatarUrl ? (
            <img src={avatarUrl} alt="User avatar" className="avatar-image" />
          ) : (
            <span>{getInitials(user)}</span>
          )}
        </div>

        <div className="profile-summary">
          <h2>User Info</h2>
          <p className="profile-name">
            {displayedUser.name || displayedUser.email || displayedUser.sub}
          </p>
          <p className="profile-subtitle">
            Profile data is loaded from the identity server UserInfo endpoint.
          </p>
        </div>
      </div>

      {(error || profileError) && (
        <div className="error">
          <strong>Error:</strong> {profileError || error}
        </div>
      )}

      {isProfileLoading && (
        <div className="loading">
          <div className="spinner"></div>
          Loading user info...
        </div>
      )}

      <div className="info-grid">
        {primaryFields.map(([label, value]) => (
          <div className="info-item" key={label}>
            <div className="info-label">{label}</div>
            <div className="info-value">{formatUserField(value)}</div>
          </div>
        ))}
      </div>

      {extraFields.length > 0 && (
        <div className="claims-section">
          <h3>Additional Claims</h3>
          <div className="claims-list">
            {extraFields.map(([key, value]) => (
              <div className="claim-row" key={key}>
                <div className="claim-key">{key}</div>
                <pre className="claim-value">{formatUserField(value)}</pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function ApiDemo() {
  const { getAccessToken, user } = useAuth();
  const [result, setResult] = useState<unknown>(null);
  const [productId, setProductId] = useState("1");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchProtectedData = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const token = await getAccessToken();
      const normalizedProductId = productId.trim();

      if (!token) {
        throw new Error("No access token available");
      }

      if (
        !/^\d+$/.test(normalizedProductId) ||
        Number(normalizedProductId) <= 0
      ) {
        throw new Error("Product ID must be a positive integer");
      }

      const requestPath = `/api/products/${encodeURIComponent(normalizedProductId)}`;

      const response = await fetch(requestPath, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: "application/json",
        },
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card">
      <h2>API Demo</h2>

      {user ? (
        <>
          <p>
            Call the protected products endpoint in the .NET resource example.
            <br />
            <code>/api/products/{"{id}"}</code> (proxied to{" "}
            <code>{appConfig.apiServerUrl}</code>)
          </p>

          <div style={{ marginBottom: "1rem" }}>
            <label htmlFor="product-id">Product ID: </label>
            <input
              id="product-id"
              type="number"
              min={1}
              step={1}
              value={productId}
              onChange={(event) => setProductId(event.target.value)}
              style={{ marginLeft: "0.5rem", padding: "0.35rem 0.5rem" }}
            />
          </div>

          <button
            className="button"
            onClick={fetchProtectedData}
            disabled={loading}
          >
            {loading ? "Fetching..." : "Fetch Protected Product"}
          </button>

          {error && (
            <div className="error">
              <strong>Error:</strong> {error}
            </div>
          )}

          {result && (
            <div>
              <h3>Response:</h3>
              <pre
                style={{
                  background: "#242424",
                  padding: "1rem",
                  borderRadius: "4px",
                  overflow: "auto",
                  maxHeight: "300px",
                }}
              >
                {JSON.stringify(result, null, 2)}
              </pre>
            </div>
          )}
        </>
      ) : (
        <p>Please log in to use the API demo.</p>
      )}

      <Link to="/">
        <button className="button secondary">Back to Home</button>
      </Link>
    </div>
  );
}

function CallbackPage() {
  const navigate = useNavigate();
  const { isLoading, error } = useAuth();

  useEffect(() => {
    if (!isLoading) {
      navigate("/", { replace: true });
    }
  }, [isLoading, navigate]);

  return (
    <div className="card">
      <h2>Completing sign-in...</h2>
      {error ? (
        <p>
          Login failed: {error}. <Link to="/">Go back home</Link>
        </p>
      ) : (
        <p>Please wait while we complete authentication.</p>
      )}
    </div>
  );
}

function App() {
  const config = useMemo(
    () => ({
      authority: appConfig.authority,
      clientId: appConfig.clientId,
      redirectUri: appConfig.redirectUri,
      userInfoEndpoint: appConfig.userInfoEndpoint,
      scope: appConfig.scope,
      audience: appConfig.audience,
      allowAuthorizationWithoutAudience:
        appConfig.allowAuthorizationWithoutAudience,
      allowOfflineAccessScope: appConfig.allowOfflineAccessScope,
      logoutRedirectUri: appConfig.postLogoutRedirectUri,
      onRedirectCallback: (appState?: AppState) => {
        console.log("Redirect callback:", appState);
      },
    }),
    [],
  );

  return (
    <GuardhouseProvider config={config}>
      <Router>
        <div className="header">
          <div className="header-content">
            <div className="logo">Guardhouse React Example</div>
            <nav className="nav-links">
              <Link to="/">Home</Link>
              <Link to="/protected">Protected</Link>
              <Link to="/userinfo">User Info</Link>
              <Link to="/api">API Demo</Link>
            </nav>
          </div>
        </div>

        <div className="container">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/callback" element={<CallbackPage />} />
            <Route path="/protected" element={<ProtectedPage />} />
            <Route path="/userinfo" element={<UserInfoPage />} />
            <Route path="/api" element={<ApiDemo />} />
          </Routes>
        </div>
      </Router>
    </GuardhouseProvider>
  );
}

export default App;
