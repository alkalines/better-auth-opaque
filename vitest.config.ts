import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "node",
          environment: "node",
          include: ["test/unit/**/*.test.ts"],
        },
      },
      {
        test: {
          name: "edge",
          environment: "edge-runtime",
          include: ["test/unit/**/*.test.ts"],
        },
      },
    ],
  },
});
