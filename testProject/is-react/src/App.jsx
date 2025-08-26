import React, { useEffect, useState } from "react";

const CLIENT_ID = "OkQXerPG4ASHB4RAKQBSGaqFG4wa";
const REDIRECT_URI = "http://localhost:5173";
const AUTH_URL = "https://localhost:9443/oauth2/authorize";
const SCOPE = "openid profile email";
const API_BASE = "http://localhost:5032";

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [refreshToken, setRefreshToken] = useState("");
  const [orders, setOrders] = useState([]);
  const [error, setError] = useState("");

  // Handle redirect (code -> token)
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
          body: JSON.stringify({ code, codeVerifier, redirectUri: REDIRECT_URI })
        });
        const data = await res.json();
        if (!res.ok) { setError(data?.error); return; }

        sessionStorage.setItem("access_token", data.access_token);
        sessionStorage.setItem("id_token", data.id_token);
        if (data.refresh_token) sessionStorage.setItem("refresh_token", data.refresh_token);

        setAccessToken(data.access_token);
        setRefreshToken(data.refresh_token || "");
        setIsAuthenticated(true);
        try {
          const payload = JSON.parse(atob(data.id_token.split(".")[1]));
          setDisplayName(payload.name || payload.preferred_username || "User");
        } catch { setDisplayName("User"); }

        window.history.replaceState({}, document.title, "/");
      } catch (e) { setError(e.message); }
    })();
  }, []);

  const handleLogin = async () => {
    try {
      const pkce = await fetch(`${API_BASE}/api/auth/pkce`).then(r => r.json());
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
    } catch (e) { setError(e.message); }
  };

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
    } catch (e) { setError(e.message); }
  };

  const fetchOrders = async () => {
    try {
      const token = sessionStorage.getItem("access_token");
      const res = await fetch(`${API_BASE}/api/orders`, { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) throw new Error(await res.text());
      setOrders(await res.json());
    } catch (e) { setError(e.message); }
  };

  return (
    <div style={{ display: "grid", placeItems: "center", padding: 32, fontFamily: "ui-sans-serif" }}>
      {!isAuthenticated ? <button onClick={handleLogin}>Login with WSO2</button> : (
        <div>
          <h2>Welcome, {displayName}</h2>
          <button onClick={fetchOrders}>Load Orders</button>
          <button onClick={handleLogout}>Logout</button>
          {orders.length > 0 && <pre>{JSON.stringify(orders, null, 2)}</pre>}
          {error && <p style={{ color: 'red' }}>{error}</p>}
        </div>
      )}
    </div>
  );
}
