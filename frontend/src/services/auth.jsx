import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { api, tokenStore } from "./api";

const Ctx = createContext(null);
export const useAuth = () => useContext(Ctx);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [ready, setReady] = useState(!tokenStore.get());

  useEffect(() => {
    if (tokenStore.get()) api.me().then(setUser).catch(() => tokenStore.clear()).finally(() => setReady(true));
    const onUnauth = () => setUser(null);
    window.addEventListener("lp-unauth", onUnauth);
    return () => window.removeEventListener("lp-unauth", onUnauth);
  }, []);

  const login = useCallback(async (email, password) => {
    const r = await api.login(email, password);
    tokenStore.set(r.token);
    setUser(r.user);
  }, []);
  const logout = useCallback(async () => { await api.logout(); tokenStore.clear(); setUser(null); }, []);
  return <Ctx.Provider value={{ user, ready, login, logout }}>{children}</Ctx.Provider>;
}
