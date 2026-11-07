import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { opaqueClient } from "@alkalines/better-auth-opaque/client";
import { createAuthClient } from "better-auth/client";
import { expect } from "vitest";

const projectDir = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is not set; run the suite with \`bun run test:convex\``);
  }
  return value;
}

/** `CONVEX_SITE_URL` of the local backend (HTTP actions); set by `scripts/run.ts`. */
export const BACKEND_SITE_URL = requiredEnv("CONVEX_SITE_URL");

/** The origin the deployment trusts (`SITE_URL` on the deployment, see `scripts/run.ts`). */
export const TRUSTED_ORIGIN = "http://localhost:3000";

export const AUTH_URL = `${BACKEND_SITE_URL}/api/auth`;

/** A unique, valid email per call so tests never see each other's users. */
export function uniqueEmail(label: string): string {
  return `${label}-${crypto.randomUUID()}@example.com`;
}

/** A request captured on its way to the backend: everything the client sent over the network. */
export type CapturedRequest = { url: string; body: string };

/**
 * A real Better Auth client with the OPAQUE client plugin talking to the local backend over HTTP.
 * Keeps its own cookie jar (one browser) and records every request body.
 */
export function createTestClient() {
  const cookies = new Map<string, string>();
  const requests: CapturedRequest[] = [];

  const customFetchImpl = async (input: string | URL | Request, init?: RequestInit) => {
    const request = new Request(input, init);
    requests.push({ url: request.url, body: await request.clone().text() });

    const headers = new Headers(request.headers);
    headers.set("origin", TRUSTED_ORIGIN);
    if (cookies.size > 0) {
      headers.set("cookie", [...cookies].map(([name, value]) => `${name}=${value}`).join("; "));
    }
    const response = await fetch(new Request(request, { headers }));

    for (const setCookie of response.headers.getSetCookie()) {
      const [pair = "", ...attributes] = setCookie.split(";");
      const separator = pair.indexOf("=");
      const name = pair.slice(0, separator).trim();
      const value = pair.slice(separator + 1).trim();
      const expired = attributes.some(
        (attribute) => attribute.trim().toLowerCase() === "max-age=0",
      );
      if (value === "" || expired) {
        cookies.delete(name);
      } else {
        cookies.set(name, value);
      }
    }
    return response;
  };

  const authClient = createAuthClient({
    baseURL: BACKEND_SITE_URL,
    plugins: [opaqueClient()],
    fetchOptions: { customFetchImpl },
  });

  return { authClient, requests, cookies };
}

/** Asserts that none of the given secrets (passwords, export keys) appears in any request body. */
export function expectNotSent(clients: { requests: CapturedRequest[] }[], secrets: string[]): void {
  for (const { requests } of clients) {
    expect(requests.length).toBeGreaterThan(0);
    for (const request of requests) {
      for (const secret of secrets) {
        expect(request.body).not.toContain(secret);
      }
    }
  }
}

/** Raw JSON POST to a Better Auth path, below the client plugin. */
export async function postJson(
  path: string,
  body: unknown,
  headers?: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> | null }> {
  const response = await fetch(`${AUTH_URL}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: TRUSTED_ORIGIN, ...headers },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

/**
 * Calls an internal function of the deployment with the Convex CLI (`convex run`), which
 * authenticates with the local deployment's admin credentials. Internal functions are never
 * reachable over HTTP, which is how the server-only plugin APIs are exposed to the tests.
 */
export function convexRun<T>(functionName: string, args: Record<string, unknown> = {}): T {
  const result = spawnSync(
    resolve(projectDir, "node_modules/.bin/convex"),
    ["run", "--typecheck", "disable", "--codegen", "disable", functionName, JSON.stringify(args)],
    {
      cwd: projectDir,
      encoding: "utf8",
      env: { ...process.env, CONVEX_AGENT_MODE: "anonymous" },
    },
  );
  if (result.status !== 0) {
    throw new Error(`convex run ${functionName} failed (${result.status})\n${result.stderr}`);
  }
  return JSON.parse(result.stdout) as T;
}

/** `convex run payloads:versionsOf`: the credential versions that have a stored payload. */
export function payloadVersionsOf(userId: string): string[] {
  return convexRun<string[]>("payloads:versionsOf", { userId });
}

/** `convex run testSupport:describeUser`: users and accounts of an email, from the component. */
export function describeUser(email: string) {
  return convexRun<{
    users: number;
    accounts: { userId: string; providerId: string; credentialVersion: string | null }[];
  }>("testSupport:describeUser", { email });
}

/** The server-only `createPasswordResetToken`, called through an internal Convex action. */
export function createPasswordResetToken(email: string) {
  return convexRun<{ url: string; expiresAt: string | number }>(
    "testSupport:createPasswordResetToken",
    { email },
  );
}

/** Reset tokens are delivered inside the URL the app configured. */
export function tokenFromResetUrl(url: string): string {
  const token = new URL(url).searchParams.get("token");
  if (!token) {
    throw new Error("the reset URL has no token");
  }
  return token;
}
