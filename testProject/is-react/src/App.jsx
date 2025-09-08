import React, { useEffect, useState, useRef } from "react";
import Cookies from "js-cookie";

const CLIENT_ID = "OkQXerPG4ASHB4RAKQBSGaqFG4wa";
const REDIRECT_URI = "http://localhost:5173";
const AUTH_URL = "https://localhost:9443/oauth2/authorize";
const SCOPE = "openid profile email";
const API_BASE = "http://localhost:5032";

export default function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [displayName, setDisplayName] = useState("");
  const [orders, setOrders] = useState([]);
  const [error, setError] = useState("");
  const [tokens, setTokens] = useState({ access_token: "", id_token: "", refresh_token: "" });
  const refreshTimer = useRef(null);

  // -------------------- Silent Refresh Setup --------------------
  const scheduleSilentRefresh = (token) => {
    try {
      const payload = JSON.parse(atob(token.split(".")[1]));
      if (!payload.exp) return;

      const expiry = payload.exp * 1000; // exp is in seconds
      const now = Date.now();
      const refreshTime = expiry - now - 60 * 1000; // 1 min before expiry

      if (refreshTimer.current) clearTimeout(refreshTimer.current);

      if (refreshTime > 0) {
        refreshTimer.current = setTimeout(() => {
          silentRefresh();
        }, refreshTime);
        console.log(`[SilentRefresh] Scheduled in ${Math.round(refreshTime / 1000)}s`);
      }
    } catch (e) {
      console.error("[SilentRefresh] Failed to decode token", e);
    }
  };

  const silentRefresh = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/auth/refresh`, {
        method: "POST",
        credentials: "include",
      });

      if (res.ok) {
        const data = await res.json();
        setTokens({
          access_token: data.access_token || "",
          id_token: data.id_token || "",
          refresh_token: data.refresh_token || "",
        });

        console.log("[SilentRefresh] Token refreshed at", new Date().toISOString());

        // Schedule next refresh
        scheduleSilentRefresh(data.access_token || data.id_token);
      } else {
        console.warn("[SilentRefresh] Failed, logging out user");
        setIsAuthenticated(false);
      }
    } catch (e) {
      console.error("[SilentRefresh] Error:", e);
    }
  };

  // -------------------- Fetch with auto refresh (fallback) --------------------
  const fetchWithRefresh = async (url, options = {}) => {
    const headers = {
      ...(options.headers || {}),
      ...(tokens.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : {}),
    };

    let res = await fetch(url, { ...options, headers, credentials: "include" });

    if (res.status === 401) {
      await silentRefresh();

      const retryHeaders = {
        ...(options.headers || {}),
        ...(tokens.access_token ? { Authorization: `Bearer ${tokens.access_token}` } : {}),
      };

      res = await fetch(url, { ...options, headers: retryHeaders, credentials: "include" });
    }

    return res;
  };


  // -------------------- Handle redirect after login --------------------
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const codeVerifier = Cookies.get("pkce_verifier");

    if (!code || !codeVerifier || Cookies.get("code_exchanged")) return;
    Cookies.set("code_exchanged", "true");

    (async () => {
      try {
        const res = await fetch(`${API_BASE}/api/auth/token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code, codeVerifier, redirectUri: REDIRECT_URI }),
          credentials: "include"
        });

        const data = await res.json();
        if (!res.ok) { setError(data?.error); return; }

        setIsAuthenticated(true);

        const payload = JSON.parse(atob(data.id_token.split(".")[1]));
        setDisplayName(payload.name || payload.preferred_username || "User");

        setTokens({
          access_token: data.access_token || "",
          id_token: data.id_token || "",
          refresh_token: data.refresh_token || ""
        });

        // Start silent refresh
        scheduleSilentRefresh(data.access_token || data.id_token);

        window.history.replaceState({}, document.title, "/");
      } catch (e) {
        setError(e.message);
      }
    })();
  }, []);

  // -------------------- Login handler --------------------
  const handleLogin = async () => {
    try {
      const pkce = await fetch(`${API_BASE}/api/auth/pkce`).then(r => r.json());
      Cookies.set("pkce_verifier", pkce.code_verifier, { secure: true, sameSite: "Strict" });

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
      setError(e.message);
    }
  };

  // -------------------- Logout handler --------------------
  const handleLogout = async () => {
    try {
      const idToken = tokens.id_token || "";

      const res = await fetch(`${API_BASE}/api/auth/logout-url?idToken=${encodeURIComponent(idToken)}`, {
        credentials: "include"
      });
      const { logoutUrl } = await res.json();

      setIsAuthenticated(false);
      setDisplayName("");
      setOrders([]);
      setTokens({ access_token: "", id_token: "", refresh_token: "" });
      Cookies.remove("pkce_verifier");
      Cookies.remove("code_exchanged");

      if (refreshTimer.current) clearTimeout(refreshTimer.current);

      window.location.href = logoutUrl;
    } catch (e) {
      setError(e.message);
    }
  };

  // -------------------- Fetch orders --------------------
  const fetchOrders = async () => {
    try {
      const res = await fetchWithRefresh(`${API_BASE}/api/orders`);
      if (!res.ok) throw new Error(await res.text());
      setOrders(await res.json());
    } catch (e) {
      setError(e.message);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex flex-col items-center justify-center p-8">
      {!isAuthenticated ? (
        <div className="max-w-2xl text-center space-y-6">
          <h1 className="text-4xl font-bold text-indigo-800">
            Welcome to our <span className="text-blue-600">WSO2 Demo Project</span>
          </h1>
          <p className="text-gray-700 text-lg">
            WSO2 Identity Server is an open-source identity and access management (IAM) solution.
            It supports SSO, OAuth2.0, OpenID Connect, and many other security standards.
          </p>

          <div className="grid gap-4 sm:grid-cols-2 mt-8">
            <div className="bg-white p-6 rounded-2xl shadow-md">
              <h2 className="font-semibold text-indigo-700 text-xl">🔐 Security</h2>
              <p className="text-gray-600 text-sm mt-2">Robust authentication & authorization with SSO.</p>
            </div>
            <div className="bg-white p-6 rounded-2xl shadow-md">
              <h2 className="font-semibold text-indigo-700 text-xl">🌍 Open Standards</h2>
              <p className="text-gray-600 text-sm mt-2">Built on OAuth2, OIDC, and SAML for interoperability.</p>
            </div>
            <div className="bg-white p-6 rounded-2xl shadow-md">
              <h2 className="font-semibold text-indigo-700 text-xl">⚡ Scalable</h2>
              <p className="text-gray-600 text-sm mt-2">Enterprise-ready, handles millions of users.</p>
            </div>
            <div className="bg-white p-6 rounded-2xl shadow-md">
              <h2 className="font-semibold text-indigo-700 text-xl">🛠️ Extensible</h2>
              <p className="text-gray-600 text-sm mt-2">Customizable with policies, workflows, and APIs.</p>
            </div>
          </div>

          <button
            onClick={handleLogin}
            className="mt-8 px-6 py-3 bg-indigo-600 hover:bg-indigo-700 text-white rounded-xl shadow-lg font-medium transition"
          >
            Login with WSO2
          </button>
        </div>
      ) : (
        <div className="w-full max-w-xl bg-white p-8 rounded-2xl shadow-lg text-center space-y-6">
          <h2 className="text-2xl font-semibold text-indigo-800">Welcome, {displayName} 🎉</h2>

          <div className="flex flex-col sm:flex-row justify-center gap-4">
            <button
              onClick={fetchOrders}
              className="px-5 py-2 bg-blue-500 hover:bg-blue-600 text-white rounded-lg shadow-md"
            >
              Load Orders
            </button>
            <button
              onClick={handleLogout}
              className="px-5 py-2 bg-red-500 hover:bg-red-600 text-white rounded-lg shadow-md"
            >
              Logout
            </button>
          </div>

          {/* 👇 Show Tokens here (UI only, not used for requests) */}
          <div className="bg-gray-100 p-4 rounded-lg text-left max-h-60 overflow-y-auto">
            <h3 className="text-lg font-semibold mb-2 text-indigo-700">🔑 Tokens</h3>
            <pre className="text-xs text-gray-800 whitespace-pre-wrap break-all">
              {JSON.stringify(tokens, null, 2)}
            </pre>
          </div>

          {orders.length > 0 && (
            <div className="bg-gray-100 p-4 rounded-lg text-left max-h-60 overflow-y-auto">
              <pre className="text-sm text-gray-800">{JSON.stringify(orders, null, 2)}</pre>
            </div>
          )}

          {error && <p className="text-red-500 font-medium">{error}</p>}
        </div>
      )}
    </div>
  );
}