import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import viteReact from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  server: {
    port: 3000,
    // Loopback only: the dev password-reset route trusts that the server is not reachable remotely.
    host: "localhost",
  },
  resolve: {
    tsconfigPaths: true,
  },
  plugins: [
    tanstackStart(),
    // React's plugin must come after Start's.
    viteReact(),
  ],
});
