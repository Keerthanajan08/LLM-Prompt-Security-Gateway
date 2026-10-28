/// <reference types="vitest/config" />
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The API runs on :8000 (`uvicorn app.main:app`). In development Vite proxies
// API calls to it; in production the built files are served by FastAPI at /ui.
const API = "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  base: "/ui/",
  build: {
    outDir: "../app/ui",
    emptyOutDir: true,
  },
  server: {
    // evals/results.json lives outside this folder.
    fs: { allow: [".."] },
    proxy: {
      "/check": API,
      "/query": API,
      "/stats": API,
      "/health": API,
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
  },
});
