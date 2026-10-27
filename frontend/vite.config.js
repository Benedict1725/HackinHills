import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// strictPort: if 5173 is already taken (e.g. by an OLD copy of this project that is still running), fail loudly instead of
// silently starting on 5174 while the browser keeps showing the stale copy on 5173 (a missing "Red Team Findings" tab).
// __BUILD_STAMP__ is shown in the corner of every page so you can tell which build the browser is really running.
export default defineConfig({
  plugins: [react()],
  define: { __BUILD_STAMP__: JSON.stringify(`${new Date().toISOString().slice(0, 16).replace("T", " ")} UTC`) },
  server: { port: 5173, strictPort: true },
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test/setup.js"], css: false },
});
