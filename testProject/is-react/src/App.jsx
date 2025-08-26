import React, { useEffect, useState } from "react";

const CLIENT_ID = "OkQXerPG4ASHB4RAKQBSGaqFG4wa";         // WSO2 App Client ID
const REDIRECT_URI = "http://localhost:5173";               // Must match WSO2 app
const AUTH_URL = "https://localhost:9443/oauth2/authorize"; // WSO2 authorize endpoint
const SCOPE = "openid profile email";
const API_BASE = "http://localhost:5032";                   // Your .NET backend

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [refreshToken, setRefreshToken] = useState("");
  const [orders, setOrders] = useState([]);
  const [error, setError] = useState("");

  // ---------- Handle redirect from WSO2 (code -> token) ----------
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const codeVerifier = sessionStorage.getItem("pkce_verifier");

    if (!code || !codeVerifier) return;

    (async () => {
      try {
        const res = await fetch(`${API_BASE}/api/auth/token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            code,
            codeVerifier,
            redirectUri: REDIRECT_URI,
          }),
        });

        const data = await res.json();
        if (!res.ok) {
          setError(data?.error || "Token exchange failed");
          return;
        }

        // Save tokens
        sessionStorage.setItem("access_token", data.access_token);
        sessionStorage.setItem("id_token", data.id_token);
        if (data.refresh_token) sessionStorage.setItem("refresh_token", data.refresh_token);

        // Get display name from ID token (best effort)
        try {
          const payloadJson = atob(data.id_token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"));
          const payload = JSON.parse(payloadJson);
          setDisplayName(payload.name || payload.preferred_username || payload.sub || "User");
        } catch {
          setDisplayName("User");
        }

        setAccessToken(data.access_token);
        setRefreshToken(data.refresh_token || "");
        setIsAuthenticated(true);

        // Clean the URL
        window.history.replaceState({}, document.title, "/");
      } catch (e) {
        setError("Token exchange failed: " + e.message);
      }
    })();
  }, []);

  // ---------- Start Login (fetch PKCE -> redirect) ----------
  const handleLogin = async () => {
    try {
      const pkce = await fetch(`${API_BASE}/api/auth/pkce`).then((r) => r.json());
      sessionStorage.setItem("pkce_verifier", pkce.code_verifier);

      const qs = new URLSearchParams({
        response_type: "code",
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPE,
        code_challenge: pkce.code_challenge,
        code_challenge_method: "S256",
      });

      window.location.href = `${AUTH_URL}?${qs.toString()}`;
    } catch (e) {
      setError("PKCE fetch failed: " + e.message);
    }
  };

  // ---------- Logout ----------
  const handleLogout = async () => {
    try {
      const idToken = sessionStorage.getItem("id_token");
      const res = await fetch(`${API_BASE}/api/auth/logout-url?idToken=${encodeURIComponent(idToken || "")}`);
      const { logoutUrl } = await res.json();

      sessionStorage.clear();
      setIsAuthenticated(false);
      setDisplayName("");
      setAccessToken("");
      setRefreshToken("");
      setOrders([]);

      window.location.href = logoutUrl;
    } catch (e) {
      setError("Logout failed: " + e.message);
    }
  };

  // ---------- Call protected API ----------
  const fetchOrders = async () => {
    try {
      const token = sessionStorage.getItem("access_token");
      const res = await fetch(`${API_BASE}/api/orders`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const t = await res.text();
        throw new Error(t || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setOrders(data);
    } catch (e) {
      setError("Fetching orders failed: " + e.message);
    }
  };

  // ---------- Refresh token ----------
  const refresh = async () => {
    try {
      const rt = sessionStorage.getItem("refresh_token");
      if (!rt) return alert("No refresh token available");
      const res = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refreshToken: rt }),
      });
      const data = await res.json();
      if (!res.ok) {
        alert(data?.error || "Refresh failed");
        return;
      }
      sessionStorage.setItem("access_token", data.access_token);
      if (data.refresh_token) sessionStorage.setItem("refresh_token", data.refresh_token);
      setAccessToken(data.access_token);
      setRefreshToken(data.refresh_token || rt);
      alert("Token refreshed");
    } catch (e) {
      alert("Refresh token call failed: " + e.message);
    }
  };

  return (
    <div style={{
      width: "100%",
      display: "grid",
      placeItems: "center",
      background: "white",
      color: "#e2e8f0",
      padding: "32px",
      fontFamily: "ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto"
    }}>
      <div style={{
        width: "100%",
        maxWidth: 780,
        background: "#111827",
        borderRadius: 16,
        padding: 24,
        boxShadow: "0 10px 30px rgba(0,0,0,.35)"
      }}>
        <h1 style={{ fontSize: 28, fontWeight: 800, marginBottom: 12 }}>WSO2 Auth Demo</h1>
        <p style={{ opacity: .75, marginBottom: 20 }}>Login with WSO2 → get tokens → call a protected <code>/api/orders</code> endpoint.</p>

        {!isAuthenticated ? (
          <div style={{ display: "flex", gap: 12 }}>
            <button onClick={handleLogin}
              style={{
                background: "#7c3aed", border: 0, padding: "12px 18px", borderRadius: 12,
                color: "white", fontWeight: 600, cursor: "pointer"
              }}>
              🔐 Sign In with WSO2
            </button>
            {error && <span style={{ color: "#f87171" }}>{error}</span>}
          </div>
        ) : (
          <>
            <div style={{
              display: "grid", gridTemplateColumns: "1fr auto", gap: 12, alignItems: "center", marginBottom: 12
            }}>
              <div>
                <div style={{ fontSize: 18, fontWeight: 700 }}>Welcome, {displayName} 👋</div>
                <div style={{ fontSize: 12, opacity: .7 }}>You’re authenticated via WSO2 IS.</div>
              </div>
              <div style={{ display: "flex", gap: 8 }}>
                <button onClick={refresh}
                  disabled={!refreshToken}
                  style={{
                    background: "#059669", border: 0, padding: "10px 14px", borderRadius: 10,
                    color: "white", fontWeight: 600, cursor: "pointer", opacity: refreshToken ? 1 : .6
                  }}>
                  🔄 Refresh Token
                </button>
                <button onClick={handleLogout}
                  style={{
                    background: "#ef4444", border: 0, padding: "10px 14px", borderRadius: 10,
                    color: "white", fontWeight: 700, cursor: "pointer"
                  }}>
                  🚪 Logout
                </button>
              </div>
            </div>

            <div style={{ marginTop: 10, marginBottom: 18 }}>
              <div style={{ fontSize: 12, opacity: .7, marginBottom: 6 }}>Access Token</div>
              <div style={{
                background: "#0b1220", border: "1px solid #1f2937", borderRadius: 12,
                padding: 12, maxHeight: 170, overflow: "auto", wordBreak: "break-all"
              }}>
                {accessToken || "(empty)"}
              </div>
            </div>

            <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
              <button onClick={fetchOrders}
                style={{
                  background: "#2563eb", border: 0, padding: "12px 16px", borderRadius: 12,
                  color: "white", fontWeight: 700, cursor: "pointer"
                }}>
                📦 Load Orders (Protected API)
              </button>
            </div>

            {orders.length > 0 && (
              <div style={{
                background: "#0b1220", border: "1px solid #1f2937", borderRadius: 12, padding: 12
              }}>
                <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 8 }}>Orders</div>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {orders.map(o => (
                    <li key={o.id} style={{ marginBottom: 6 }}>
                      <code>#{o.id}</code> — {o.item} — <strong>${o.price}</strong>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {error && <div style={{ marginTop: 12, color: "#f87171" }}>{error}</div>}
          </>
        )}
      </div>
    </div>
  );
}
