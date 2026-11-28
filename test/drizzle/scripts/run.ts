/**
 * Runs the unit suite (`test/unit`, see `vitest.config.ts`) against Better Auth's Drizzle adapter
 * on Postgres with Redis/Valkey as secondary storage, once on Node and once on Bun.
 *
 * `DATABASE_URL` (default `postgres://radium:radium@localhost:5432/opaque_test`, created when
 * missing) and `REDIS_URL` (default `redis://localhost:6379`) select the servers. Every test gets
 * its own Postgres schema and Redis key prefix, dropped after the run. Arguments are passed to
 * Vitest (e.g. a file filter).
 */
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const projectDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const vitestBin = resolve(projectDir, "node_modules/vitest/vitest.mjs");
const vitestArgs = ["run", ...process.argv.slice(2)];

// `bun --bun` makes Vitest and its test workers run on Bun instead of the `node` shebang.
const runtimes = [
  { name: "node", command: "node", args: [vitestBin, ...vitestArgs] },
  { name: "bun", command: process.execPath, args: ["--bun", vitestBin, ...vitestArgs] },
] as const;

const failed: string[] = [];
for (const runtime of runtimes) {
  const version = spawnSync(runtime.command, ["--version"], { encoding: "utf8" }).stdout?.trim();
  console.log(`\n── ${runtime.name} ${version ?? "(not found)"} ──`);
  const result = spawnSync(runtime.command, runtime.args, {
    cwd: projectDir,
    stdio: "inherit",
    env: { ...process.env, OPAQUE_TEST_RUNTIME: runtime.name },
  });
  if (result.status !== 0) {
    failed.push(runtime.name);
  }
}

if (failed.length > 0) {
  console.error(`\nDrizzle suite failed on: ${failed.join(", ")}`);
  process.exit(1);
}
