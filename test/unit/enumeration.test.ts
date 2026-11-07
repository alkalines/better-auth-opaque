import { client as opaqueProtocol } from "@serenity-kit/opaque";
import { beforeAll, describe, expect, test } from "vitest";
import {
  CHEAP_STRETCHING,
  createMemoryDb,
  createTestAuth,
  createTestClient,
  postJson,
  serverSetupForTests,
} from "./helpers.ts";

describe("sign-in enumeration resistance", () => {
  let auth: ReturnType<typeof createTestAuth>;

  beforeAll(async () => {
    const serverSetup = await serverSetupForTests();
    auth = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
      options: { emailAndPassword: { enabled: true } },
    });
    const known = await createTestClient(auth).authClient.signUp.opaque({
      email: "known@example.com",
      password: "known-password",
      name: "Known",
    });
    const decoy = await createTestClient(auth).authClient.signUp.opaque({
      email: "decoy@example.com",
      password: "decoy-password",
      name: "Decoy",
    });
    // A user without an OPAQUE account (email/password only).
    const passwordOnly = await postJson(auth, "/sign-up/email", {
      email: "password-only@example.com",
      password: "email-password-123",
      name: "Password Only",
    });
    if (known.error || decoy.error || passwordOnly.status !== 200) {
      throw new Error("enumeration fixture setup failed");
    }
  });

  const cases = ["unknown@example.com", "password-only@example.com", "known@example.com"];

  async function challenge(email: string) {
    const login = opaqueProtocol.startLogin({ password: "wrong-password" });
    const response = await postJson(auth, "/sign-in/opaque/challenge", {
      email,
      loginRequest: login.startLoginRequest,
    });
    return { login, response };
  }

  test("challenge responses have the same status and shape", async () => {
    const responses = await Promise.all(
      cases.map(async (email) => (await challenge(email)).response),
    );
    const shapes = responses.map((response) => ({
      status: response.status,
      keys: Object.keys(response.body ?? {}).toSorted(),
      stateIdLength: String(response.body?.stateId).length,
      loginResponseLength: String(response.body?.loginResponse).length,
      keyStretching: response.body?.keyStretching,
    }));
    expect(shapes[0]?.status).toBe(200);
    expect(shapes[1]).toEqual(shapes[0]);
    expect(shapes[2]).toEqual(shapes[0]);
  });

  test("the client reports the same error for wrong passwords and unknown emails", async () => {
    const errors = [];
    for (const email of cases) {
      const browser = createTestClient(auth);
      const result = await browser.authClient.signIn.opaque({ email, password: "wrong-password" });
      expect(result.data).toBeNull();
      errors.push(result.error);
      // The local OPAQUE step already failed, so nothing reached the complete endpoint.
      expect(browser.requests.some((request) => request.url.endsWith("/complete"))).toBe(false);
    }
    expect(errors[0]).toEqual({
      code: "INVALID_CREDENTIALS",
      message: "Invalid email or password",
      status: 401,
      statusText: "UNAUTHORIZED",
    });
    expect(errors[1]).toEqual(errors[0]);
    expect(errors[2]).toEqual(errors[0]);
  });

  test("complete answers identically for fake states and wrong passwords", async () => {
    // A well-formed finalization from a real login on another account.
    const decoyLogin = opaqueProtocol.startLogin({ password: "decoy-password" });
    const decoyChallenge = await postJson(auth, "/sign-in/opaque/challenge", {
      email: "decoy@example.com",
      loginRequest: decoyLogin.startLoginRequest,
    });
    const decoyFinish = opaqueProtocol.finishLogin({
      clientLoginState: decoyLogin.clientLoginState,
      loginResponse: decoyChallenge.body?.loginResponse as string,
      password: "decoy-password",
      keyStretching: CHEAP_STRETCHING,
    });
    expect(decoyFinish).toBeDefined();

    const completes = [];
    for (const email of cases) {
      const { response } = await challenge(email);
      completes.push(
        await postJson(auth, "/sign-in/opaque/complete", {
          stateId: response.body?.stateId,
          loginFinalization: decoyFinish!.finishLoginRequest,
        }),
      );
    }
    expect(completes[0]).toEqual({
      status: 401,
      body: { code: "INVALID_CREDENTIALS", message: "Invalid email or password" },
    });
    expect(completes[1]).toEqual(completes[0]);
    expect(completes[2]).toEqual(completes[0]);
  });
});
