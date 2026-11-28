/**
 * Postinstall: generates the Drizzle schemas `generated/schema-<format>.ts` (gitignored) from
 * `schema/auth.ts` with the Better Auth CLI, one per user id format the suite runs against, so
 * they always match the installed Better Auth and the plugin's account fields.
 *
 * The Better Auth CLI requires Node >= 22.12; it runs under Bun here (`--bun`) so installs do not
 * depend on the system Node version.
 */
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ID_FORMATS } from "../test/id-formats.ts";

const projectDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

for (const format of ID_FORMATS) {
  const args = [
    "--bun",
    resolve(projectDir, "node_modules/.bin/auth"),
    "generate",
    "--config",
    "schema/auth.ts",
    "--output",
    `generated/schema-${format}.ts`,
    "--yes",
  ];
  const result = spawnSync(process.execPath, args, {
    cwd: projectDir,
    stdio: "inherit",
    env: { ...process.env, SCHEMA_ID_FORMAT: format },
  });
  if (result.status !== 0) {
    throw new Error(`\`bun ${args.join(" ")}\` failed with exit code ${result.status}`);
  }
}
