import { useState } from "react";
import { useAuth } from "../services/auth";

export default function Login() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function submit(e) {
    e.preventDefault();
    setBusy(true); setError("");
    try { await login(email, password); } catch (err) { setError(err.message); } finally { setBusy(false); }
  }
  return (
    <div className="login-wrap">
      <form className="card form login" onSubmit={submit}>
        <div className="brand-name">LeakProof AI</div>
        <p className="muted">Secure AI Safety Testing &amp; Evaluation Platform</p>
        <label htmlFor="email">Email</label>
        <input id="email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required />
        <label htmlFor="pw">Password</label>
        <input id="pw" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
        {error && <div className="state error" role="alert" style={{ padding: ".5rem" }}>{error}</div>}
        <button className="btn primary" disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
    </div>
  );
}
