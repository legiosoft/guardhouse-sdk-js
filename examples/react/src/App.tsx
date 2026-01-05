import { BrowserRouter as Router, Routes, Route, Link } from "react-router-dom";
import { GuardhouseProvider, useAuth } from "@guardhouse/react";
import { useState } from "react";

const AUTHORITY = import.meta.env.VITE_AUTHORITY || "https://auth.example.com";
const CLIENT_ID = import.meta.env.VITE_CLIENT_ID || "your-client-id";
const REDIRECT_URI =
  import.meta.env.VITE_REDIRECT_URI || "http://localhost:3000";

function Home() {
  const { user, isAuthenticated, isLoading, loginWithRedirect, logout } =
    useAuth();

  const handleLogin = () => {
    loginWithRedirect({
      appState: { returnTo: "/" },
    });
  };

  const handleLogout = () => {
    logout({ returnTo: window.location.origin });
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

function ApiDemo() {
  const { getAccessToken, user } = useAuth();
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchProtectedData = async () => {
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const token = await getAccessToken();

      if (!token) {
        throw new Error("No access token available");
      }

      const response = await fetch("http://localhost:3001/protected", {
        headers: {
          Authorization: `Bearer ${token}`,
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
          <p>Test authentication by calling a protected API endpoint.</p>

          <button
            className="button"
            onClick={fetchProtectedData}
            disabled={loading}
          >
            {loading ? "Fetching..." : "Fetch Protected Data"}
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

function App() {
  return (
    <GuardhouseProvider
      authority={AUTHORITY}
      clientId={CLIENT_ID}
      redirectUri={REDIRECT_URI}
      onRedirectCallback={(appState) => {
        console.log("Redirect callback:", appState);
      }}
    >
      <Router>
        <div className="header">
          <div className="header-content">
            <div className="logo">Guardhouse React Example</div>
            <nav className="nav-links">
              <Link to="/">Home</Link>
              <Link to="/protected">Protected</Link>
              <Link to="/api">API Demo</Link>
            </nav>
          </div>
        </div>

        <div className="container">
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/protected" element={<ProtectedPage />} />
            <Route path="/api" element={<ApiDemo />} />
          </Routes>
        </div>
      </Router>
    </GuardhouseProvider>
  );
}

export default App;
