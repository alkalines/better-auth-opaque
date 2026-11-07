import { defineConfig } from "vitest/config";

// Every test shares one backend and one deployment database, so files run one after another.
export default defineConfig({
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    globalSetup: ["test/global-setup.ts"],
    fileParallelism: false,
    reporters: ["verbose"],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
