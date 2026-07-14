import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const apiKey = process.env.SIKRYPT_API_KEY || "";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "https://localhost:3000",
        changeOrigin: true,
        secure: false,
        rewrite: (path) => path.replace(/^\/api/, ""),
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyReq) => {
            if (apiKey) {
              proxyReq.setHeader("x-api-key", apiKey);
            }
          });
        }
      },
      "/ws": {
        target: "https://localhost:3000",
        ws: true,
        changeOrigin: true,
        secure: false
      }
    }
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.js"
  }
});
