import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // The API is local by design; there is no remote PHANTOM.
      "/api": "http://127.0.0.1:8000",
    },
  },
});
