import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defineConfig, devices } from "@playwright/test";
import { ready, server } from "@serenity-kit/opaque";

const port = 3100;
const baseURL = `http://localhost:${port}`;

// The config is evaluated again in every worker; the first evaluation publishes the generated
// values through process.env so workers and the web server share one setup and one database.
if (process.env.E2E_OPAQUE_SERVER_SETUP === undefined) {
  await ready;
  process.env.E2E_OPAQUE_SERVER_SETUP = server.createSetup();
  process.env.E2E_BETTER_AUTH_SECRET = randomBytes(32).toString("base64url");
  process.env.E2E_DATABASE_URL = `file:${join(mkdtempSync(join(tmpdir(), "opaque-e2e-")), "e2e.db")}`;
}

export default defineConfig({
  testDir: ".",
  testMatch: "*.spec.ts",
  // Traces and results stay out of the working tree.
  outputDir: join(tmpdir(), "opaque-e2e-results"),
  // The flows share one server, rate limits and one database; run them one after another.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],
  use: { baseURL, trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    // Builds the package (the example consumes `dist/`), migrates the isolated database, then
    // starts Vite on the fixed test port.
    command: `bun run --cwd ../.. build && bun run db:setup && vite dev --port ${port} --strictPort`,
    cwd: join(import.meta.dirname, ".."),
    url: `${baseURL}/`,
    reuseExistingServer: false,
    timeout: 240_000,
    stdout: "pipe",
    stderr: "pipe",
    env: {
      OPAQUE_SERVER_SETUP: process.env.E2E_OPAQUE_SERVER_SETUP,
      BETTER_AUTH_SECRET: process.env.E2E_BETTER_AUTH_SECRET!,
      BETTER_AUTH_URL: baseURL,
      DATABASE_URL: process.env.E2E_DATABASE_URL!,
    },
  },
});
