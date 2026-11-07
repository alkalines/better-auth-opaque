/**
 * Runs the Convex test suite against a real anonymous local backend, without any login.
 *
 * Flow: wipe local state → `convex init` (anonymous deployment) → set fresh deployment secrets →
 * measure the bundle (`--debug-bundle-path`) → `convex dev` (pushes, keeps the backend running) →
 * `vitest run` → stop everything, also on failure or signals.
 *
 * Docs: https://docs.convex.dev/cli/agent-mode (anonymous local backend, `CONVEX_AGENT_MODE`),
 * https://docs.convex.dev/cli/local-deployments (the backend is a subprocess of `convex dev` and
 * exits with it).
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { measureBundle } from "./bundle-size.ts";

const projectDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = resolve(projectDir, "../..");
const convexBin = resolve(projectDir, "node_modules/.bin/convex");
const vitestBin = resolve(projectDir, "node_modules/.bin/vitest");
const stateDir = resolve(projectDir, ".convex");
const scratchDir = resolve(projectDir, ".convex-test");
const envLocalFile = resolve(projectDir, ".env.local");
const SITE_URL = "http://localhost:3000";
const DEV_READY_TIMEOUT_MS = 180_000;
const DEV_STOP_TIMEOUT_MS = 10_000;

// A deployment, deploy key, or URL inherited from the caller must never decide where tests run.
const childEnv: NodeJS.ProcessEnv = { ...process.env, CONVEX_AGENT_MODE: "anonymous" };
for (const name of [
  "CONVEX_DEPLOYMENT",
  "CONVEX_DEPLOY_KEY",
  "CONVEX_URL",
  "CONVEX_SITE_URL",
  "CONVEX_SELF_HOSTED_URL",
  "CONVEX_SELF_HOSTED_ADMIN_KEY",
]) {
  delete childEnv[name];
}

let devServer: ChildProcess | undefined;
let suite: ChildProcess | undefined;

/** Runs a Convex CLI command to completion, failing the run when it exits non-zero. */
function convexCli(args: string[]): void {
  const result = spawnSync(convexBin, args, { cwd: projectDir, env: childEnv, encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(
      `convex ${args[0]} failed (${result.status})\n${result.stdout}\n${result.stderr}`,
    );
  }
}

/** Reads the deployment URLs that `convex init` wrote to `.env.local`. */
function readDeploymentUrls(): { convexUrl: string; siteUrl: string } {
  const text = readFileSync(envLocalFile, "utf8");
  const read = (name: string) => text.match(new RegExp(`^${name}=(.+)$`, "m"))?.[1]?.trim();
  const convexUrl = read("CONVEX_URL");
  const siteUrl = read("CONVEX_SITE_URL");
  if (!convexUrl || !siteUrl) {
    throw new Error("convex init did not write CONVEX_URL and CONVEX_SITE_URL to .env.local");
  }
  return { convexUrl, siteUrl };
}

/** Fresh secrets per run. They only ever exist in the deployment's database and a temp file. */
function setDeploymentEnvironment(): void {
  const created = spawnSync("node", [resolve(repoRoot, "dist/cli.js"), "create-setup"], {
    encoding: "utf8",
  });
  const serverSetup = created.stdout.trim();
  if (created.status !== 0 || serverSetup === "") {
    throw new Error(
      `create-setup failed (run \`bun run build\` at the repo root first)\n${created.stderr}`,
    );
  }

  mkdirSync(scratchDir, { recursive: true });
  const envFile = resolve(scratchDir, "deployment.env");
  writeFileSync(
    envFile,
    [
      `OPAQUE_SERVER_SETUP=${serverSetup}`,
      `BETTER_AUTH_SECRET=${randomBytes(32).toString("base64")}`,
      `SITE_URL=${SITE_URL}`,
      "",
    ].join("\n"),
    { mode: 0o600 },
  );
  try {
    convexCli(["env", "set", "--from-file", envFile]);
  } finally {
    rmSync(envFile, { force: true });
  }
}

/** Starts `convex dev` (which owns the backend process) and resolves once functions are pushed. */
async function startDevServer(): Promise<void> {
  // Own process group, so one signal reaches the CLI and the backend binary it spawned.
  const child = spawn(convexBin, ["dev", "--tail-logs", "disable", "--typecheck", "disable"], {
    cwd: projectDir,
    env: childEnv,
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  devServer = child;

  let output = "";
  child.stdout.on("data", (chunk) => (output += chunk));
  child.stderr.on("data", (chunk) => (output += chunk));

  const started = Date.now();
  while (!output.includes("Convex functions ready")) {
    if (child.exitCode !== null) {
      throw new Error(`convex dev exited with ${child.exitCode} before it was ready\n${output}`);
    }
    if (Date.now() - started > DEV_READY_TIMEOUT_MS) {
      throw new Error(`convex dev was not ready after ${DEV_READY_TIMEOUT_MS} ms\n${output}`);
    }
    await sleep(250);
  }
}

/** Stops `convex dev` and the backend it spawned; safe to call more than once. */
async function stopDevServer(): Promise<void> {
  const child = devServer;
  devServer = undefined;
  if (!child?.pid) {
    return;
  }

  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    // The group is already gone.
  }
  if (child.exitCode === null) {
    await Promise.race([once(child, "exit"), sleep(DEV_STOP_TIMEOUT_MS)]);
  }

  // The CLI kills the backend on SIGTERM; anything still alive in the group is killed here.
  try {
    process.kill(-child.pid, "SIGKILL");
  } catch {
    // Nothing left in the group.
  }
}

async function isBackendListening(convexUrl: string): Promise<boolean> {
  try {
    await fetch(`${convexUrl}/instance_name`, { signal: AbortSignal.timeout(1_000) });
    return true;
  } catch {
    return false;
  }
}

async function runSuite(): Promise<number> {
  rmSync(stateDir, { recursive: true, force: true });
  rmSync(envLocalFile, { force: true });
  rmSync(scratchDir, { recursive: true, force: true });

  convexCli(["init"]);
  const { convexUrl, siteUrl } = readDeploymentUrls();
  setDeploymentEnvironment();

  // `--debug-bundle-path` writes the bundles of the push and skips the push itself.
  const bundleDir = resolve(scratchDir, "bundle");
  mkdirSync(bundleDir, { recursive: true });
  convexCli(["dev", "--once", "--typecheck", "disable", "--debug-bundle-path", bundleDir]);
  const bundle = measureBundle(resolve(bundleDir, "isolate"), "http.js");
  console.log(
    `[bundle] auth HTTP action (convex/http.js + ${bundle.files - 1} shared chunks): ` +
      `${bundle.rawBytes} bytes raw, ${bundle.gzipBytes} bytes gzip, ${bundle.brotliBytes} bytes brotli`,
  );

  await startDevServer();

  suite = spawn(vitestBin, ["run"], {
    cwd: projectDir,
    stdio: "inherit",
    env: {
      ...childEnv,
      CONVEX_URL: convexUrl,
      CONVEX_SITE_URL: siteUrl,
      CONVEX_TEST_BUNDLE: JSON.stringify(bundle),
    },
  });
  const [code] = (await once(suite, "exit")) as [number | null];
  return code ?? 1;
}

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    suite?.kill("SIGTERM");
    void stopDevServer().then(() => process.exit(1));
  });
}

let exitCode = 1;
try {
  exitCode = await runSuite();
} catch (error) {
  console.error(error);
} finally {
  await stopDevServer();
}

if (existsSync(envLocalFile)) {
  const { convexUrl } = readDeploymentUrls();
  if (await isBackendListening(convexUrl)) {
    console.error(`the Convex backend is still listening on ${convexUrl} after shutdown`);
    exitCode = 1;
  }
}
rmSync(scratchDir, { recursive: true, force: true });
process.exit(exitCode);
