import { client as opaqueProtocol } from "@serenity-kit/opaque";
import { afterEach, beforeAll, describe, expect, test, vi } from "vitest";
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

let serverSetup: string;

beforeAll(async () => {
  serverSetup = await serverSetupForTests();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("sign-up and sign-in", () => {
  test("registration and login yield the same export key; secrets never leave the client", async () => {
    const auth = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
    });
    const browser = createTestClient(auth);
    const password = "correct horse battery staple";

    const signUp = await browser.authClient.signUp.opaque({
      email: "Alice@Example.com",
      password,
      name: "Alice",
    });
    expect(signUp.error).toBeNull();
    expect(signUp.data?.token).toEqual(expect.any(String));
    expect(signUp.data?.user.email).toBe("alice@example.com");

    const other = createTestClient(auth);
    const signIn = await other.authClient.signIn.opaque({ email: "alice@example.com", password });
    expect(signIn.error).toBeNull();
    expect(signIn.data?.exportKey).toEqual(expect.any(String));
    expect(signIn.data?.exportKey).toBe(signUp.data?.exportKey);
    expect(signIn.data?.payload).toBeNull();

    const session = await other.authClient.getSession();
    expect(session.data?.user.email).toBe("alice@example.com");

    expectNotSent([browser, other], [password, signUp.data!.exportKey]);
  });

  // Runs two full rfc-recommended Argon2id derivations (sign-up and sign-in), which takes several
  // seconds on shared CI runners, well past Vitest's 5 s default.
  test("the default rfc-recommended profile works end to end", { timeout: 30_000 }, async () => {
    const auth = createTestAuth({ db: createMemoryDb(), opaque: { serverSetup } });
    const browser = createTestClient(auth);
    const password = "default-profile-password";

    const signUp = await browser.authClient.signUp.opaque({
      email: "default@example.com",
      password,
      name: "Default",
    });
    expect(signUp.error).toBeNull();

    const challenge = await postJson(auth, "/sign-in/opaque/challenge", {
      email: "default@example.com",
      loginRequest: "AAAA",
    });
    // A malformed login request is rejected without revealing anything about the account.
    expect(challenge.body?.code).toBe("INVALID_OPAQUE_MESSAGE");

    const signIn = await browser.authClient.signIn.opaque({
      email: "default@example.com",
      password,
    });
    expect(signIn.error).toBeNull();
    expect(signIn.data?.exportKey).toBe(signUp.data?.exportKey);
  });

  test("a configured server identifier is advertised and bound into the record", async () => {
    const db = createMemoryDb();
    const auth = createTestAuth({
      db,
      opaque: {
        serverSetup,
        keyStretching: CHEAP_STRETCHING,
        serverIdentifier: "auth.example.com",
      },
    });
    const browser = createTestClient(auth);
    const signUp = await browser.authClient.signUp.opaque({
      email: "ident@example.com",
      password: "pw-ident",
      name: "Ident",
    });
    expect(signUp.error).toBeNull();
    const signIn = await browser.authClient.signIn.opaque({
      email: "ident@example.com",
      password: "pw-ident",
    });
    expect(signIn.data?.exportKey).toBe(signUp.data?.exportKey);

    // Removing the identifier later breaks the existing record, as documented.
    const withoutIdentifier = createTestAuth({
      db,
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
    });
    const broken = await createTestClient(withoutIdentifier).authClient.signIn.opaque({
      email: "ident@example.com",
      password: "pw-ident",
    });
    expect(broken.error?.code).toBe("INVALID_CREDENTIALS");
  });

  test("keyStretching is stored per account and survives a later default change", async () => {
    const db = createMemoryDb();
    const before = createTestAuth({ db, opaque: { serverSetup, keyStretching: CHEAP_STRETCHING } });
    const signUp = await createTestClient(before).authClient.signUp.opaque({
      email: "profile@example.com",
      password: "pw-profile",
      name: "Profile",
    });
    expect(signUp.error).toBeNull();

    const newDefault = { "argon2id-custom": { iterations: 2, memory: 2048, parallelism: 1 } };
    const after = createTestAuth({ db, opaque: { serverSetup, keyStretching: newDefault } });
    const signIn = await createTestClient(after).authClient.signIn.opaque({
      email: "profile@example.com",
      password: "pw-profile",
    });
    expect(signIn.error).toBeNull();
    expect(signIn.data?.exportKey).toBe(signUp.data?.exportKey);

    const freshSignUp = await createTestClient(after).authClient.signUp.opaque({
      email: "profile2@example.com",
      password: "pw-profile2",
      name: "Profile 2",
    });
    expect(freshSignUp.error).toBeNull();

    const profileOf = async (email: string) => {
      const { startLoginRequest } = opaqueProtocol.startLogin({ password: "irrelevant" });
      const challenge = await postJson(after, "/sign-in/opaque/challenge", {
        email,
        loginRequest: startLoginRequest,
      });
      return challenge.body?.keyStretching;
    };
    expect(await profileOf("profile@example.com")).toEqual(CHEAP_STRETCHING);
    expect(await profileOf("profile2@example.com")).toEqual(newDefault);
    expect(await profileOf("unknown@example.com")).toEqual(newDefault);
  });

  test("a pinned client profile aborts before complete when the server differs", async () => {
    const auth = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
    });
    const browser = createTestClient(auth, { keyStretching: "memory-constrained" });
    const result = await browser.authClient.signUp.opaque({
      email: "pinned@example.com",
      password: "pw-pinned",
      name: "Pinned",
    });
    expect(result.data).toBeNull();
    expect(result.error?.code).toBe("KEY_STRETCHING_MISMATCH");
    expect(browser.requests.some((request) => request.url.endsWith("/complete"))).toBe(false);
  });

  test("sign-up payloads require commitPayload and pass validatePayload", async () => {
    const withoutHooks = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
    });
    const unsupported = await createTestClient(withoutHooks).authClient.signUp.opaque({
      email: "payload@example.com",
      password: "pw-payload",
      name: "Payload",
      payload: { data: 1 },
    });
    expect(unsupported.error?.code).toBe("PAYLOAD_NOT_SUPPORTED");

    const app = createPayloadApp();
    const db = createMemoryDb();
    const withHooks = createTestAuth({
      db,
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING, hooks: app.hooks },
    });
    const rejected = await createTestClient(withHooks).authClient.signUp.opaque({
      email: "payload@example.com",
      password: "pw-payload",
      name: "Payload",
      payload: { invalid: true },
    });
    expect(rejected.error?.code).toBe("INVALID_PAYLOAD");
    expect(db.user).toHaveLength(0);

    let keySeenByCallback: string | undefined;
    const accepted = await createTestClient(withHooks).authClient.signUp.opaque({
      email: "payload@example.com",
      password: "pw-payload",
      name: "Payload",
      payload: async (exportKey: string) => {
        keySeenByCallback = exportKey;
        return { sealed: "app-data" };
      },
    });
    expect(accepted.error).toBeNull();
    expect(keySeenByCallback).toBe(accepted.data?.exportKey);

    const signIn = await createTestClient(withHooks).authClient.signIn.opaque({
      email: "payload@example.com",
      password: "pw-payload",
    });
    expect(signIn.data?.payload).toEqual({ sealed: "app-data" });
  });
});

describe("single-use state", () => {
  test("a consumed sign-in state cannot be replayed", async () => {
    const auth = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
    });
    const browser = createTestClient(auth);
    await browser.authClient.signUp.opaque({
      email: "replay@example.com",
      password: "pw",
      name: "R",
    });
    const signIn = await browser.authClient.signIn.opaque({
      email: "replay@example.com",
      password: "pw",
    });
    expect(signIn.error).toBeNull();

    const complete = browser.requests.findLast((request) =>
      request.url.endsWith("/sign-in/opaque/complete"),
    );
    const replay = await postJson(auth, "/sign-in/opaque/complete", JSON.parse(complete!.body));
    expect(replay.status).toBe(400);
    expect(replay.body?.code).toBe("INVALID_STATE");

    const signUpComplete = browser.requests.find((request) =>
      request.url.endsWith("/sign-up/opaque/complete"),
    );
    const signUpReplay = await postJson(
      auth,
      "/sign-up/opaque/complete",
      JSON.parse(signUpComplete!.body),
    );
    expect(signUpReplay.body?.code).toBe("INVALID_STATE");
  });

  test("an expired sign-up state is rejected", async () => {
    const auth = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
    });
    const registration = opaqueProtocol.startRegistration({ password: "pw-expired" });
    const challenge = await postJson(auth, "/sign-up/opaque/challenge", {
      email: "expired@example.com",
      registrationRequest: registration.registrationRequest,
    });
    expect(challenge.status).toBe(200);
    const finished = opaqueProtocol.finishRegistration({
      password: "pw-expired",
      registrationResponse: challenge.body!.registrationResponse as string,
      clientRegistrationState: registration.clientRegistrationState,
      keyStretching: CHEAP_STRETCHING,
    });

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 5 * 60 * 1000 + 1000);

    const complete = await postJson(auth, "/sign-up/opaque/complete", {
      stateId: challenge.body!.stateId,
      registrationRecord: finished.registrationRecord,
      name: "Expired",
    });
    expect(complete.status).toBe(400);
    expect(complete.body?.code).toBe("INVALID_STATE");
  });
});

describe("existing emails", () => {
  test("sign-up for an existing email answers like email/password sign-up and never attaches", async () => {
    const db = createMemoryDb();
    const auth = createTestAuth({
      db,
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
      options: { emailAndPassword: { enabled: true } },
    });
    const existing = await postJson(auth, "/sign-up/email", {
      email: "taken@example.com",
      password: "email-password-123",
      name: "Taken",
    });
    expect(existing.status).toBe(200);

    const opaqueSignUp = await createTestClient(auth).authClient.signUp.opaque({
      email: "taken@example.com",
      password: "pw-taken",
      name: "Taken",
    });
    const emailSignUp = await postJson(auth, "/sign-up/email", {
      email: "taken@example.com",
      password: "email-password-123",
      name: "Taken",
    });
    expect(opaqueSignUp.error?.status).toBe(emailSignUp.status);
    expect(opaqueSignUp.error?.code).toBe(emailSignUp.body?.code);
    expect(db.account.filter((account) => account.providerId === "opaque")).toHaveLength(0);
  });

  test("an email registered between challenge and complete is re-checked at complete", async () => {
    const db = createMemoryDb();
    const auth = createTestAuth({
      db,
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
      options: { emailAndPassword: { enabled: true } },
    });
    const registration = opaqueProtocol.startRegistration({ password: "pw-race" });
    const challenge = await postJson(auth, "/sign-up/opaque/challenge", {
      email: "race@example.com",
      registrationRequest: registration.registrationRequest,
    });
    expect(challenge.status).toBe(200);

    await postJson(auth, "/sign-up/email", {
      email: "race@example.com",
      password: "email-password-123",
      name: "Race",
    });

    const finished = opaqueProtocol.finishRegistration({
      password: "pw-race",
      registrationResponse: challenge.body!.registrationResponse as string,
      clientRegistrationState: registration.clientRegistrationState,
      keyStretching: CHEAP_STRETCHING,
    });
    const complete = await postJson(auth, "/sign-up/opaque/complete", {
      stateId: challenge.body!.stateId,
      registrationRecord: finished.registrationRecord,
      name: "Race",
    });
    expect(complete.status).toBe(422);
    expect(complete.body?.code).toBe("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL");
    expect(db.user).toHaveLength(1);
    expect(db.account).toHaveLength(1);
    expect(db.account[0]?.providerId).toBe("credential");
  });

  test("with requireEmailVerification, existing emails get a synthetic success and sign-in requires verification", async () => {
    const db = createMemoryDb();
    const auth = createTestAuth({
      db,
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
      options: { emailAndPassword: { enabled: true, requireEmailVerification: true } },
    });

    const first = await createTestClient(auth).authClient.signUp.opaque({
      email: "verify@example.com",
      password: "pw-verify",
      name: "Verify",
    });
    expect(first.error).toBeNull();
    expect(first.data?.token).toBeNull();

    const duplicate = await createTestClient(auth).authClient.signUp.opaque({
      email: "verify@example.com",
      password: "pw-other",
      name: "Verify",
    });
    expect(duplicate.error).toBeNull();
    expect(duplicate.data?.token).toBeNull();
    expect(duplicate.data?.user.id).not.toBe(first.data?.user.id);
    expect(db.user).toHaveLength(1);
    expect(db.account).toHaveLength(1);

    const browser = createTestClient(auth);
    const unverified = await browser.authClient.signIn.opaque({
      email: "verify@example.com",
      password: "pw-verify",
    });
    expect(unverified.error?.code).toBe("EMAIL_NOT_VERIFIED");
    const wrong = await browser.authClient.signIn.opaque({
      email: "verify@example.com",
      password: "pw-other",
    });
    expect(wrong.error?.code).toBe("INVALID_CREDENTIALS");
  });
});

describe("password change", () => {
  test("revokes other sessions, keeps the current one, and retires the old password", async () => {
    const app = createPayloadApp();
    const auth = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING, hooks: app.hooks },
    });
    const laptop = createTestClient(auth);
    const phone = createTestClient(auth);

    await laptop.authClient.signUp.opaque({
      email: "change@example.com",
      password: "old-password",
      name: "Change",
      payload: { tag: "old" },
    });
    await phone.authClient.signIn.opaque({ email: "change@example.com", password: "old-password" });
    expect((await phone.authClient.getSession()).data?.user.email).toBe("change@example.com");

    const wrong = await laptop.authClient.opaque.changePassword({
      currentPassword: "not-the-password",
      newPassword: "new-password",
    });
    expect(wrong.error?.code).toBe("INVALID_PASSWORD");

    const changed = await laptop.authClient.opaque.changePassword({
      currentPassword: "old-password",
      newPassword: "new-password",
      payload: { tag: "new" },
    });
    expect(changed.error).toBeNull();
    expect(changed.data?.status).toBe(true);

    expect((await laptop.authClient.getSession()).data?.user.email).toBe("change@example.com");
    expect((await phone.authClient.getSession()).data).toBeNull();

    const fresh = createTestClient(auth);
    const old = await fresh.authClient.signIn.opaque({
      email: "change@example.com",
      password: "old-password",
    });
    expect(old.error?.code).toBe("INVALID_CREDENTIALS");
    const renewed = await fresh.authClient.signIn.opaque({
      email: "change@example.com",
      password: "new-password",
    });
    expect(renewed.error).toBeNull();
    expect(renewed.data?.exportKey).toBe(changed.data?.exportKey);
    expect(renewed.data?.payload).toEqual({ tag: "new" });

    expectNotSent(
      [laptop, phone, fresh],
      ["old-password", "new-password", "not-the-password", changed.data!.exportKey],
    );
  });

  test("requires a session", async () => {
    const auth = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
    });
    const result = await createTestClient(auth).authClient.opaque.changePassword({
      currentPassword: "a",
      newPassword: "b",
    });
    expect(result.error?.status).toBe(401);
  });
});

async function setUpResettableUser() {
  const app = createPayloadApp();
  const auth = createTestAuth({
    db: createMemoryDb(),
    opaque: {
      serverSetup,
      keyStretching: CHEAP_STRETCHING,
      hooks: app.hooks,
      passwordReset: { url: (token) => `http://localhost:3000/reset?token=${token}` },
    },
  });
  const owner = createTestClient(auth);
  const signUp = await owner.authClient.signUp.opaque({
    email: "reset@example.com",
    password: "forgotten-password",
    name: "Reset",
    payload: { tag: "old" },
  });
  if (signUp.error) {
    throw new Error(`fixture sign-up failed: ${signUp.error.code}`);
  }
  return { auth, owner };
}

describe("password reset", () => {
  test("verify does not consume; the token is single use; all sessions end", async () => {
    const { auth, owner } = await setUpResettableUser();
    const { url, expiresAt } = await auth.api.createPasswordResetToken({
      body: { email: "reset@example.com" },
    });
    expect(expiresAt.getTime()).toBeGreaterThan(Date.now());
    const token = new URL(url).searchParams.get("token")!;

    const browser = createTestClient(auth);
    for (let attempt = 0; attempt < 2; attempt++) {
      const verified = await browser.authClient.opaque.verifyResetToken({ token });
      expect(verified.error).toBeNull();
      expect(verified.data?.payload).toEqual({ tag: "old" });
    }

    const reset = await browser.authClient.opaque.resetPassword({
      token,
      newPassword: "brand-new-password",
      payload: { tag: "new" },
    });
    expect(reset.error).toBeNull();
    expect((await owner.authClient.getSession()).data).toBeNull();

    const again = await browser.authClient.opaque.resetPassword({
      token,
      newPassword: "another-password",
    });
    expect(again.error?.code).toBe("INVALID_RESET_TOKEN");
    expect((await browser.authClient.opaque.verifyResetToken({ token })).error?.code).toBe(
      "INVALID_RESET_TOKEN",
    );

    const signIn = await browser.authClient.signIn.opaque({
      email: "reset@example.com",
      password: "brand-new-password",
    });
    expect(signIn.data?.exportKey).toBe(reset.data?.exportKey);
    expect(signIn.data?.payload).toEqual({ tag: "new" });
    const old = await browser.authClient.signIn.opaque({
      email: "reset@example.com",
      password: "forgotten-password",
    });
    expect(old.error?.code).toBe("INVALID_CREDENTIALS");

    expectNotSent([browser], ["brand-new-password", "forgotten-password", reset.data!.exportKey]);
  });

  test("expired tokens are rejected", async () => {
    const { auth } = await setUpResettableUser();
    const { url } = await auth.api.createPasswordResetToken({
      body: { email: "reset@example.com" },
    });
    const token = new URL(url).searchParams.get("token")!;

    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.now() + 3600 * 1000 + 1000);

    const browser = createTestClient(auth);
    expect((await browser.authClient.opaque.verifyResetToken({ token })).error?.code).toBe(
      "INVALID_RESET_TOKEN",
    );
    expect(
      (await browser.authClient.opaque.resetPassword({ token, newPassword: "late-password" })).error
        ?.code,
    ).toBe("INVALID_RESET_TOKEN");
  });

  test("createPasswordResetToken fails with USER_NOT_FOUND for unknown emails", async () => {
    const { auth } = await setUpResettableUser();
    await expect(
      auth.api.createPasswordResetToken({ body: { email: "nobody@example.com" } }),
    ).rejects.toMatchObject({ body: { code: "USER_NOT_FOUND" } });
  });
});

describe("server-only endpoints", () => {
  test("are not reachable over HTTP", async () => {
    const auth = createTestAuth({
      db: createMemoryDb(),
      opaque: {
        serverSetup,
        keyStretching: CHEAP_STRETCHING,
        passwordReset: { url: (token) => `/reset?token=${token}` },
      },
    });
    for (const path of ["/create-password-reset-token", "/validate-opaque-setup"]) {
      const response = await postJson(auth, path, { email: "a@example.com" });
      expect(response.status).toBe(404);
    }
    await expect(auth.api.validateOpaqueSetup()).resolves.toEqual({
      publicKey: expect.any(String),
    });
  });
});

describe("rate limits", () => {
  test("sign-in challenges are limited per client", async () => {
    const auth = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
      options: { rateLimit: { enabled: true } },
    });
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 6; attempt++) {
      const response = await postJson(
        auth,
        "/sign-in/opaque/challenge",
        { email: "limited@example.com", loginRequest: "AAAA" },
        { "x-forwarded-for": "203.0.113.7" },
      );
      statuses.push(response.status);
    }
    expect(statuses.slice(0, 5).every((status) => status !== 429)).toBe(true);
    expect(statuses[5]).toBe(429);
  });
});
