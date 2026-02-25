import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const apiServerUrl = (
    env.VITE_API_SERVER_URL?.trim() ||
    env.VITE_API_BASE_URL?.trim() ||
    "https://localhost:5001"
  ).replace(/\/+$/, "");

  return {
    plugins: [react()],
    resolve: {
      alias: {
        "@guardhouse/react": path.resolve(__dirname, "../../packages/react"),
      },
    },
    server: {
      port: 3000,
      proxy: {
        "/api": {
          target: apiServerUrl,
          changeOrigin: true,
          secure: false,
        },
      },
    },
  };
});
