import { beforeAll, describe, expect, test } from "vitest";
import {
  CHEAP_STRETCHING,
  createMemoryDb,
  createPayloadApp,
  createTestAuth,
  createTestClient,
  expectNotSent,
  postJson,
  serverSetupForTests,
} from "./helpers.ts";

const EMAIL = "attach-client@example.com";
const CLASSIC_PASSWORD = "classic-password-known-to-server";
const NEW_PASSWORD = "opaque-password-kept-on-client";
const CHALLENGE_PATH = "/opaque/attach/challenge";
const COMPLETE_PATH = "/opaque/attach/complete";
let serverSetup: string;

beforeAll(async () => {
  serverSetup = await serverSetupForTests();
});

/** Keeps protocol/session handling real while replacing one untrusted challenge response. */
function rewriteChallenge(
  auth: { handler: (request: Request) => Promise<Response> },
  rewrite: (body: Record<string, unknown>) => Record<string, unknown>,
) {
  return {
    handler: async (request: Request) => {
      const response = await auth.handler(request);
      if (!response.ok || !new URL(request.url).pathname.endsWith(CHALLENGE_PATH)) return response;
      return new Response(JSON.stringify(rewrite(await response.json())), {
        status: response.status,
        headers: response.headers,
      });
    },
  };
}

async function classicUser(requireCurrentPassword = true) {
  const app = createPayloadApp();
  const auth = createTestAuth({
    db: createMemoryDb(),
    options: { emailAndPassword: { enabled: true } },
    opaque: {
      serverSetup,
      keyStretching: CHEAP_STRETCHING,
      attach: { requireCurrentPassword },
      hooks: app.hooks,
      passwordReset: { url: (token) => `http://localhost:3000/reset?token=${token}` },
    },
  });
  const signedUp = await postJson(auth, "/sign-up/email", {
    email: EMAIL,
    password: CLASSIC_PASSWORD,
    name: "Classic",
  });
  expect(signedUp.status).toBe(200);
  const browser = createTestClient(auth);
  const signedIn = await browser.authClient.signIn.email({
    email: EMAIL,
    password: CLASSIC_PASSWORD,
  });
  expect(signedIn.error).toBeNull();
  return { auth, browser };
}

describe("opaque.attachCredential", () => {
  test("attaches a first credential, replaces the session and keeps the new password/export key local", async () => {
    const { auth, browser } = await classicUser();
    const oldToken = (await browser.authClient.getSession()).data!.session.token;
    const start = browser.requests.length;
    let builderKey: string | undefined;
    const attached = await browser.authClient.opaque.attachCredential({
      currentPassword: CLASSIC_PASSWORD,
      newPassword: NEW_PASSWORD,
      payload: (exportKey: string) => {
        builderKey = exportKey;
        return { encrypted: "credential-vault" };
      },
    });
    expect(attached.error).toBeNull();
    expect(attached.data).toMatchObject({ status: true, token: expect.any(String) });
    expect(attached.data?.token).not.toBe(oldToken);
    expect(attached.data?.exportKey).toEqual(expect.any(String));
    expect(attached.data?.exportKey).toBe(builderKey);
    expect((await browser.authClient.getSession()).data?.session.token).toBe(attached.data?.token);

    const login = createTestClient(auth);
    const signedIn = await login.authClient.signIn.opaque({ email: EMAIL, password: NEW_PASSWORD });
    expect(signedIn.error).toBeNull();
    expect(signedIn.data?.exportKey).toBe(attached.data?.exportKey);
    expect(signedIn.data?.payload).toEqual({ encrypted: "credential-vault" });
    expectNotSent([browser, login], [NEW_PASSWORD, attached.data!.exportKey]);
    const attachRequests = browser.requests.slice(start);
    const challenge = attachRequests.find((request) => request.url.endsWith(CHALLENGE_PATH));
    expect(JSON.parse(challenge!.body).currentPassword).toBe(CLASSIC_PASSWORD);
    const otherBodies = attachRequests
      .filter((request) => !request.url.endsWith(CHALLENGE_PATH))
      .map((request) => request.body);
    expect(otherBodies.join("\n")).not.toContain(CLASSIC_PASSWORD);
  });

  test("refuses a reused classic password without making any request", async () => {
    const { browser } = await classicUser();
    const start = browser.requests.length;
    const result = await browser.authClient.opaque.attachCredential({
      currentPassword: CLASSIC_PASSWORD,
      newPassword: CLASSIC_PASSWORD,
      payload: () => {
        throw new Error("payload must not run");
      },
    });
    expect(result).toMatchObject({
      data: null,
      error: { code: "PASSWORD_REUSED", status: 400, statusText: "BAD_REQUEST" },
    });
    expect(browser.requests.slice(start)).toEqual([]);
  });

  test.each([
    ["weak", CHEAP_STRETCHING, "KEY_STRETCHING_MISMATCH"],
    ["missing", undefined, "INVALID_SERVER_RESPONSE"],
  ])(
    "refuses a %s advertised profile before payload or complete",
    async (_kind, keyStretching, code) => {
      const { auth, browser: owner } = await classicUser();
      const browser = createTestClient(
        rewriteChallenge(auth, (body) => ({ ...body, keyStretching })),
        {},
      );
      for (const [name, value] of owner.cookies) browser.cookies.set(name, value);
      let payloadBuilt = false;
      const result = await browser.authClient.opaque.attachCredential({
        currentPassword: CLASSIC_PASSWORD,
        newPassword: NEW_PASSWORD,
        payload: () => {
          payloadBuilt = true;
          return { encrypted: true };
        },
      });
      expect(result).toMatchObject({ data: null, error: { code } });
      expect(payloadBuilt).toBe(false);
      expect(browser.requests.some((request) => request.url.endsWith(COMPLETE_PATH))).toBe(false);
    },
  );

  test("allows omission of the classic password when the server accepts a fresh session", async () => {
    const { browser } = await classicUser(false);
    const result = await browser.authClient.opaque.attachCredential({ newPassword: NEW_PASSWORD });
    expect(result.error).toBeNull();
    const challenge = browser.requests.find((request) => request.url.endsWith(CHALLENGE_PATH));
    expect(JSON.parse(challenge!.body)).not.toHaveProperty("currentPassword");
    expectNotSent([browser], [NEW_PASSWORD, result.data!.exportKey]);
  });

  test("withholds the derived export key when complete is rejected", async () => {
    const { auth, browser: owner } = await classicUser();
    const browser = createTestClient({
      handler: async (request) => {
        if (new URL(request.url).pathname.endsWith(COMPLETE_PATH)) {
          return Response.json(
            { code: "FORBIDDEN", message: "Complete rejected" },
            { status: 403 },
          );
        }
        return auth.handler(request);
      },
    });
    for (const [name, value] of owner.cookies) browser.cookies.set(name, value);
    let derivedKey: string | undefined;
    const result = await browser.authClient.opaque.attachCredential({
      currentPassword: CLASSIC_PASSWORD,
      newPassword: NEW_PASSWORD,
      payload: (exportKey: string) => {
        derivedKey = exportKey;
        return { encrypted: true };
      },
    });
    expect(derivedKey).toEqual(expect.any(String));
    expect(result).toMatchObject({ data: null, error: { status: 403 } });
    expectNotSent([browser], [NEW_PASSWORD, derivedKey!]);
  });
});

test("the existing reset action enrols a classic-only user when explicitly authorized", async () => {
  const { auth } = await classicUser();
  const { url } = await auth.api.createPasswordResetToken({
    body: { email: EMAIL, allowEnrolment: true },
  });
  const browser = createTestClient(auth);
  const reset = await browser.authClient.opaque.resetPassword({
    token: new URL(url).searchParams.get("token")!,
    newPassword: NEW_PASSWORD,
    payload: { encrypted: "enrolled-vault" },
  });
  expect(reset.error).toBeNull();
  expect(reset.data?.status).toBe(true);
  const signedIn = await browser.authClient.signIn.opaque({ email: EMAIL, password: NEW_PASSWORD });
  expect(signedIn.error).toBeNull();
  expect(signedIn.data?.exportKey).toBe(reset.data?.exportKey);
  expect(signedIn.data?.payload).toEqual({ encrypted: "enrolled-vault" });
  expectNotSent([browser], [NEW_PASSWORD, reset.data!.exportKey]);
});
