import { defineConfig } from "vitest/config";

// The unit suite itself, with `createTestDb` backed by Postgres (Drizzle adapter) and Redis.
export default defineConfig({
  test: {
    dir: "../unit",
    include: ["**/*.test.ts"],
    // Two-factor builds Better Auth itself, on the memory adapter with the twoFactor table.
    exclude: ["two-factor.test.ts"],
    environment: "node",
    globalSetup: ["test/global-setup.ts"],
    setupFiles: ["test/setup.ts"],
    testTimeout: 60_000,
    hookTimeout: 60_000,
  },
});
