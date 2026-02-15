import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  base: '/dashboard/',
  plugins: [react(), tailwindcss()],
  build: {
    outDir: "dist",
  },
  server: {
    // 開発時は Control Plane の API にプロキシ
    proxy: {
      "/api": "http://127.0.0.1:39000",
      "/healthcheck": "http://127.0.0.1:39000",
      "/metrics": "http://127.0.0.1:39000",
    },
  },
});
