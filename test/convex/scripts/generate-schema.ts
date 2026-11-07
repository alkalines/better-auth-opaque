/**
 * Postinstall: generates the Better Auth component schema `convex/betterAuth/schema.ts`
 * (gitignored) from `convex/betterAuth/auth.ts`, so it always matches the installed Better Auth
 * and the plugin's account fields.
 *
 * The auth config imports `@alkalines/better-auth-opaque`, whose exports point at `dist/`, so the
 * root package is built first. The Better Auth CLI requires Node >= 22.12; it runs under Bun here
 * (`--bun`) so installs do not depend on the system Node version.
 */
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(projectDir, "../..");

function run(args: string[], cwd: string): void {
  const result = spawnSync(process.execPath, args, { cwd, stdio: "inherit" });
  if (result.status !== 0) {
    throw new Error(`\`bun ${args.join(" ")}\` failed with exit code ${result.status}`);
  }
}

run(["run", "build"], repoRoot);
run(
  [
    "--bun",
    resolve(projectDir, "node_modules/.bin/auth"),
    "generate",
    "--config",
    "convex/betterAuth/auth.ts",
    "--output",
    "convex/betterAuth/schema.ts",
    "--yes",
  ],
  projectDir,
);
