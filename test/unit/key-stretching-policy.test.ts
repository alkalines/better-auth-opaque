import { beforeAll, describe, expect, test } from "vitest";
import { opaqueClient, type OpaqueClientOptions } from "../../src/client/index.ts";
import { OPAQUE_ACCOUNT_FIELDS, type OpaqueKeyStretching } from "../../src/contract.ts";
import {
  CHEAP_STRETCHING,
  createMemoryDb,
  createPayloadApp,
  createTestAuth,
  createTestClient,
  serverSetupForTests,
} from "./helpers.ts";

const EMAIL = "policy@example.com";
const PASSWORD = "policy-current-password";
const NEW_PASSWORD = "policy-replacement-password";
// The most expensive profile the schema admits; still refused because no policy lists it.
const RAISED: OpaqueKeyStretching = {
  "argon2id-custom": { iterations: 64, memory: 2 ** 21 - 1, parallelism: 1 },
};
// Outside the schema bounds: serenity would throw on it (Argon2 needs 8 KiB per lane).
const BROKEN = { "argon2id-custom": { iterations: 1, memory: 1, parallelism: 1 } };
let serverSetup: string;
beforeAll(async () => {
  serverSetup = await serverSetupForTests();
});

/** Rewrites only successful challenge JSON, preserving real server state and session cookies. */
function rewriteChallenge(
  auth: { handler: (request: Request) => Promise<Response> },
  path: string,
  rewrite: (body: Record<string, unknown>) => Record<string, unknown>,
) {
  return {
    handler: async (request: Request) => {
      const response = await auth.handler(request);
      if (!response.ok || !new URL(request.url).pathname.endsWith(path)) return response;
      const body = rewrite((await response.json()) as Record<string, unknown>);
      return new Response(JSON.stringify(body), {
        status: response.status,
        headers: response.headers,
      });
    },
  };
}

async function fixture() {
  const app = createPayloadApp();
  const db = createMemoryDb();
  const auth = createTestAuth({
    db,
    opaque: {
      serverSetup,
      keyStretching: CHEAP_STRETCHING,
      hooks: app.hooks,
      passwordReset: { url: (token) => `http://localhost:3000/reset?token=${token}` },
    },
  });
  const owner = createTestClient(auth);
  const registered = await owner.authClient.signUp.opaque({
    email: EMAIL,
    password: PASSWORD,
    name: "Policy",
  });
  expect(registered.error).toBeNull();
  return { auth, owner, registered, db };
}

describe("client key-stretching options", () => {
  test.each([
    { keyStretching: "rfc-recommended" },
    { keyStretching: { registration: [] } },
    { keyStretching: { login: [] } },
    { keyStretching: { registration: ["unknown"] } },
    { keyStretching: { registration: [CHEAP_STRETCHING], extra: true } },
    { extra: true },
    null,
  ])("rejects invalid options at construction: %j", (options) => {
    expect(() => opaqueClient(options as unknown as OpaqueClientOptions)).toThrow(
      "Invalid opaqueClient options",
    );
  });
});

describe("registration challenge policy", () => {
  const flows = [
    ["sign-up", "/sign-up/opaque/challenge"],
    ["change", "/opaque/change-password/challenge"],
    ["reset", "/reset/opaque/challenge"],
  ] as const;
  const profiles = [
    ["weak", CHEAP_STRETCHING, "KEY_STRETCHING_MISMATCH", 400, "BAD_REQUEST"],
    ["missing", undefined, "INVALID_SERVER_RESPONSE", 502, "BAD_GATEWAY"],
    ["non-schema", "not-a-profile", "INVALID_SERVER_RESPONSE", 502, "BAD_GATEWAY"],
  ] as const;

  for (const [flow, path] of flows) {
    for (const [profile, keyStretching, code, status, statusText] of profiles) {
      test(`${flow} refuses a ${profile} profile before payload or complete`, async () => {
        const { auth, owner } = await fixture();
        const browser = createTestClient(
          rewriteChallenge(auth, path, (body) => ({
            ...body,
            keyStretching,
            // A valid schema but invalid login message detects derivation before policy checks.
            ...(flow === "change"
              ? { loginKeyStretching: "memory-constrained", loginResponse: "AAAA" }
              : {}),
          })),
          {},
        );
        for (const [name, value] of owner.cookies) browser.cookies.set(name, value);
        let payloadBuilt = false;
        const payload = () => {
          payloadBuilt = true;
          return { wrapped: true };
        };
        let result;
        if (flow === "sign-up") {
          result = await browser.authClient.signUp.opaque({
            email: "new-policy@example.com",
            password: NEW_PASSWORD,
            name: "New",
            payload,
          });
        } else if (flow === "change") {
          result = await browser.authClient.opaque.changePassword({
            currentPassword: PASSWORD,
            newPassword: NEW_PASSWORD,
            payload,
          });
        } else {
          const { url } = await auth.api.createPasswordResetToken({ body: { email: EMAIL } });
          result = await browser.authClient.opaque.resetPassword({
            token: new URL(url).searchParams.get("token")!,
            newPassword: NEW_PASSWORD,
            payload,
          });
        }
        expect(result).toMatchObject({ data: null, error: { code, status, statusText } });
        expect(payloadBuilt).toBe(false);
        expect(browser.requests.some((request) => request.url.endsWith("/complete"))).toBe(false);
      });
    }
  }

  test("application payload exceptions are not converted to server errors", async () => {
    const { auth } = await fixture();
    const browser = createTestClient(auth);
    await expect(
      browser.authClient.signUp.opaque({
        email: "app-error@example.com",
        password: PASSWORD,
        name: "App",
        payload: () => {
          throw new Error("application payload failed");
        },
      }),
    ).rejects.toThrow("application payload failed");
    expect(browser.requests.some((request) => request.url.endsWith("/complete"))).toBe(false);
  });
});

describe("login challenge policy", () => {
  for (const [flow, path] of [
    ["sign-in", "/sign-in/opaque/challenge"],
    ["proof", "/opaque/password-proof/challenge"],
    ["change", "/opaque/change-password/challenge"],
  ] as const) {
    test(`${flow} refuses a maximal out-of-policy profile before complete`, async () => {
      const { auth, owner } = await fixture();
      const browser = createTestClient(
        rewriteChallenge(auth, path, (body) => ({
          ...body,
          [flow === "change" ? "loginKeyStretching" : "keyStretching"]: RAISED,
        })),
      );
      for (const [name, value] of owner.cookies) browser.cookies.set(name, value);
      const result =
        flow === "sign-in"
          ? await browser.authClient.signIn.opaque({ email: EMAIL, password: PASSWORD })
          : flow === "proof"
            ? await browser.authClient.opaque.createPasswordProof({ password: PASSWORD })
            : await browser.authClient.opaque.changePassword({
                currentPassword: PASSWORD,
                newPassword: NEW_PASSWORD,
                payload: () => {
                  throw new Error("payload must not run");
                },
              });
      expect(result).toMatchObject({
        data: null,
        error: { code: "KEY_STRETCHING_MISMATCH", status: 400, statusText: "BAD_REQUEST" },
      });
      expect(browser.requests.some((request) => request.url.endsWith("/complete"))).toBe(false);
    });
  }

  test("an explicitly allowed older stored profile still signs in after a default change", async () => {
    const { db, registered } = await fixture();
    const newProfile = { "argon2id-custom": { iterations: 2, memory: 2048, parallelism: 1 } };
    const auth = createTestAuth({ db, opaque: { serverSetup, keyStretching: newProfile } });
    const browser = createTestClient(auth, {
      keyStretching: { registration: [newProfile], login: [CHEAP_STRETCHING] },
    });
    const signedIn = await browser.authClient.signIn.opaque({ email: EMAIL, password: PASSWORD });
    expect(signedIn.error).toBeNull();
    expect(signedIn.data?.exportKey).toBe(registered.data?.exportKey);
  });

  test.each([
    ["schema-invalid", "not base64url!"],
    ["serenity-invalid", "AAAA"],
  ])("a %s login response resolves to INVALID_SERVER_RESPONSE", async (_kind, loginResponse) => {
    const { auth } = await fixture();
    const browser = createTestClient(
      rewriteChallenge(auth, "/sign-in/opaque/challenge", (body) => ({ ...body, loginResponse })),
    );
    const result = await browser.authClient.signIn.opaque({ email: EMAIL, password: PASSWORD });
    expect(result).toMatchObject({
      data: null,
      error: { code: "INVALID_SERVER_RESPONSE", status: 502, statusText: "BAD_GATEWAY" },
    });
    expect(browser.requests.some((request) => request.url.endsWith("/complete"))).toBe(false);
  });

  test("an Argon2 profile outside the schema bounds is neither accepted nor configurable", async () => {
    const { auth } = await fixture();
    const browser = createTestClient(
      rewriteChallenge(auth, "/sign-in/opaque/challenge", (body) => ({
        ...body,
        keyStretching: BROKEN,
      })),
    );
    const result = await browser.authClient.signIn.opaque({ email: EMAIL, password: PASSWORD });
    expect(result).toMatchObject({
      data: null,
      error: { code: "INVALID_SERVER_RESPONSE", status: 502 },
    });
    expect(browser.requests.some((request) => request.url.endsWith("/complete"))).toBe(false);
    expect(() => opaqueClient({ keyStretching: { login: [BROKEN] as never } })).toThrow(
      /Invalid opaqueClient options/,
    );
  });

  test("a legacy out-of-bounds stored profile cannot sign in but can be reset", async () => {
    const { auth, db } = await fixture();
    const row = db.account.find((account) => account.providerId === "opaque")!;
    row[OPAQUE_ACCOUNT_FIELDS.keyStretching] = JSON.stringify(BROKEN);

    const refused = await createTestClient(auth).authClient.signIn.opaque({
      email: EMAIL,
      password: PASSWORD,
    });
    expect(refused.error?.code).toBe("INVALID_CREDENTIALS");

    const { url } = await auth.api.createPasswordResetToken({ body: { email: EMAIL } });
    const reset = await createTestClient(auth).authClient.opaque.resetPassword({
      token: new URL(url).searchParams.get("token")!,
      newPassword: NEW_PASSWORD,
    });
    expect(reset.error).toBeNull();

    const signedIn = await createTestClient(auth).authClient.signIn.opaque({
      email: EMAIL,
      password: NEW_PASSWORD,
    });
    expect(signedIn.error).toBeNull();
    const stored = db.account.find((account) => account.providerId === "opaque")!;
    expect(JSON.parse(stored[OPAQUE_ACCOUNT_FIELDS.keyStretching] as string)).toEqual(
      CHEAP_STRETCHING,
    );
  });
});
