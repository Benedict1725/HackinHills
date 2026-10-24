const BASE = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status;
  }
}

const TOKEN_KEY = "lp_token";
export const tokenStore = {
  get: () => sessionStorage.getItem(TOKEN_KEY),
  set: (t) => sessionStorage.setItem(TOKEN_KEY, t),
  clear: () => sessionStorage.removeItem(TOKEN_KEY),
};

async function request(path, options = {}) {
  let res;
  const token = tokenStore.get();
  try {
    res = await fetch(`${BASE}${path}`, {
      ...options,
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    });
  } catch {
    throw new ApiError(`Cannot reach the backend at ${BASE}. Is it running?`, 0);
  }
  if (!res.ok) {
    if (res.status === 401 && token && !path.startsWith("/api/auth/login")) {
      tokenStore.clear();
      window.dispatchEvent(new Event("lp-unauth"));
    }
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch { /* non-JSON body */ }
    if (Array.isArray(detail)) detail = detail.map((d) => d.msg).join("; ");
    throw new ApiError(typeof detail === "string" ? detail : "Request failed", res.status);
  }
  return res.json();
}

export const api = {
  baseUrl: BASE,
  health: () => request("/api/health"),
  dashboard: () => request("/api/dashboard"),
  aiHealth: () => request("/api/ai/health"),
  testCases: () => request("/api/test-cases"),
  tests: (params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
    return request(`/api/tests${q ? `?${q}` : ""}`);
  },
  test: (id) => request(`/api/tests/${encodeURIComponent(id)}`),
  login: (email, password) => request("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  me: () => request("/api/auth/me"),
  logout: () => request("/api/auth/logout", { method: "POST" }).catch(() => null),
  defenseConfig: () => request("/api/defense/config"),
  saveDefenseConfig: (cfg) => request("/api/defense/config", { method: "POST", body: JSON.stringify(cfg) }),
  runComparison: () => request("/api/comparisons/run", { method: "POST" }),
  latestComparison: () => request("/api/comparisons/latest"),
  verifyAudit: () => request("/api/audit/verify", { method: "POST" }),
  audit: (params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v)).toString();
    return request(`/api/audit${q ? `?${q}` : ""}`);
  },
  runTest: (payload) => request("/api/tests/run", { method: "POST", body: JSON.stringify(payload) }),
  runSuite: (mode = "auto", trials = 1) => request("/api/tests/run-suite", { method: "POST", body: JSON.stringify({ mode, trials }) }),
  evaluationReport: () => request("/api/reports/evaluation"),
};
