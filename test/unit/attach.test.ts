import { client as opaqueProtocol } from "@serenity-kit/opaque";
import type { BetterAuthOptions } from "better-auth";
import { beforeAll, describe, expect, test } from "vitest";
import {
  OPAQUE_ACCOUNT_FIELDS,
  OPAQUE_PATHS,
  type OpaqueCredentialChangeFlow,
  type OpaqueHooks,
} from "../../src/contract.ts";
import type { OpaqueOptions } from "../../src/server/index.ts";
import {
  CHEAP_STRETCHING,
  createMemoryDb,
  createPayloadApp,
  createTestAuth,
  createTestClient,
  postJson,
  serverSetupForTests,
  type AuthUnderTest,
  type TestClient,
} from "./helpers.ts";

const EMAIL = "migrating@example.com";
const CLASSIC = "classic-password-1";
const OPAQUE_PASSWORD = "opaque-password-1";
const CHANGED = "changed-password-2";

let serverSetup: string;
beforeAll(async () => {
  serverSetup = await serverSetupForTests();
});

type CredentialChange = {
  userId: string;
  flow: OpaqueCredentialChangeFlow;
  previousCredentialVersion: string | null;
  credentialVersion: string;
};

type SetUpConfig = {
  opaque?: Partial<OpaqueOptions>;
  options?: Partial<BetterAuthOptions>;
};

/** A user who signed up with Better Auth's classic email/password and is signed in. */
async function setUpClassic(config: SetUpConfig = {}) {
  const db = createMemoryDb();
  const app = createPayloadApp();
  const changes: CredentialChange[] = [];
  const hooks: OpaqueHooks = {
    ...app.hooks,
    onCredentialChanged: (input) => {
      changes.push(input);
    },
  };
  const auth = createTestAuth({
    db,
    options: { emailAndPassword: { enabled: true }, ...config.options },
    opaque: {
      serverSetup,
      keyStretching: CHEAP_STRETCHING,
      hooks,
      passwordReset: { url: (token) => `http://localhost:3000/reset?token=${token}` },
      ...config.opaque,
    },
  });
  const browser = createTestClient(auth);
  const signUp = await browser.authClient.signUp.email({
    email: EMAIL,
    password: CLASSIC,
    name: "Migrating",
  });
  expect(signUp.error).toBeNull();
  const userId = signUp.data!.user.id;

  const opaqueRows = () => db.account.filter((row) => row.providerId === "opaque");
  const classicRows = () => db.account.filter((row) => row.providerId === "credential");
  const sessionRows = () => db.session.filter((row) => row.userId === userId);
  const currentVersion = () => opaqueRows()[0]?.[OPAQUE_ACCOUNT_FIELDS.credentialVersion];
  return {
    db,
    app,
    auth,
    browser,
    userId,
    changes,
    opaqueRows,
    classicRows,
    sessionRows,
    currentVersion,
  };
}

const cookieHeader = (client: TestClient) =>
  [...client.cookies].map(([name, value]) => `${name}=${value}`).join("; ");

const post = (
  auth: AuthUnderTest,
  client: TestClient,
  path: string,
  body: Record<string, unknown>,
) => postJson(auth, path, body, { cookie: cookieHeader(client) });

/** Raw attach challenge, below the client plugin, so tests can interleave or tamper. */
async function rawAttachChallenge(
  auth: AuthUnderTest,
  client: TestClient,
  input: { password: string; currentPassword?: string },
) {
  const registration = opaqueProtocol.startRegistration({ password: input.password });
  const response = await post(auth, client, OPAQUE_PATHS.attachChallenge, {
    registrationRequest: registration.registrationRequest,
    currentPassword: input.currentPassword,
  });
  return { response, registration, password: input.password };
}

type RawAttachChallenge = {
  response: Awaited<ReturnType<typeof postJson>>;
  registration: ReturnType<typeof opaqueProtocol.startRegistration>;
  password: string;
};

function finishRawRegistration(challenge: RawAttachChallenge) {
  const body = challenge.response.body!;
  return opaqueProtocol.finishRegistration({
    password: challenge.password,
    registrationResponse: body.registrationResponse as string,
    clientRegistrationState: challenge.registration.clientRegistrationState,
    keyStretching: body.keyStretching as typeof CHEAP_STRETCHING,
  }).registrationRecord;
}

describe("attach a first OPAQUE credential to a classic user", () => {
  test("replaces the classic password, revokes other sessions, and keeps the caller signed in", async () => {
    const { auth, browser, userId, opaqueRows, classicRows, sessionRows } = await setUpClassic();
    const elsewhere = createTestClient(auth);
    expect(
      (await elsewhere.authClient.signIn.email({ email: EMAIL, password: CLASSIC })).error,
    ).toBeNull();
    expect(sessionRows()).toHaveLength(2);

    const attached = await browser.authClient.opaque.attachCredential({
      newPassword: OPAQUE_PASSWORD,
      currentPassword: CLASSIC,
    });
    expect(attached.error).toBeNull();
    expect(attached.data?.token).toEqual(expect.any(String));

    expect(opaqueRows()).toHaveLength(1);
    expect(classicRows()).toHaveLength(0);
    expect(sessionRows()).toHaveLength(1);
    expect(sessionRows()[0]?.token).toBe(attached.data?.token);
    expect((await browser.authClient.getSession()).data?.user.id).toBe(userId);
    expect((await elsewhere.authClient.getSession()).data).toBeNull();

    expect(
      (await createTestClient(auth).authClient.signIn.email({ email: EMAIL, password: CLASSIC }))
        .error,
    ).not.toBeNull();
    const signIn = await createTestClient(auth).authClient.signIn.opaque({
      email: EMAIL,
      password: OPAQUE_PASSWORD,
    });
    expect(signIn.error).toBeNull();
    expect(signIn.data?.exportKey).toBe(attached.data?.exportKey);
  });

  test("removeClassicCredential: false keeps the classic password until the server API removes it", async () => {
    const { auth, browser, userId, classicRows } = await setUpClassic({
      opaque: { removeClassicCredential: false },
    });
    await expect(auth.api.removeClassicCredential({ body: { userId } })).rejects.toMatchObject({
      body: { code: "OPAQUE_ACCOUNT_NOT_FOUND" },
    });
    expect(classicRows()).toHaveLength(1);

    expect(
      (
        await browser.authClient.opaque.attachCredential({
          newPassword: OPAQUE_PASSWORD,
          currentPassword: CLASSIC,
        })
      ).error,
    ).toBeNull();
    expect(classicRows()).toHaveLength(1);
    expect(
      (await createTestClient(auth).authClient.signIn.email({ email: EMAIL, password: CLASSIC }))
        .error,
    ).toBeNull();

    await expect(auth.api.removeClassicCredential({ body: { userId } })).resolves.toEqual({
      status: true,
    });
    expect(classicRows()).toHaveLength(0);
  });

  test("the server-only removal is not reachable over HTTP", async () => {
    const { auth, userId } = await setUpClassic();
    const response = await postJson(auth, "/remove-classic-credential", { userId });
    expect(response.status).toBe(404);
  });

  test("a wrong classic password is rejected and nothing is created", async () => {
    const { auth, browser, db, opaqueRows, classicRows } = await setUpClassic();
    const verificationBefore = db.verification.length;
    const wrong = await browser.authClient.opaque.attachCredential({
      newPassword: OPAQUE_PASSWORD,
      currentPassword: "not-the-classic-password",
    });
    expect(wrong.error?.code).toBe("INVALID_PASSWORD");
    expect(opaqueRows()).toHaveLength(0);
    expect(classicRows()).toHaveLength(1);
    expect(db.verification.length).toBe(verificationBefore);
    expect(
      (await createTestClient(auth).authClient.signIn.email({ email: EMAIL, password: CLASSIC }))
        .error,
    ).toBeNull();
  });

  test("without currentPassword the default policy refuses", async () => {
    const { browser, opaqueRows } = await setUpClassic();
    const missing = await browser.authClient.opaque.attachCredential({
      newPassword: OPAQUE_PASSWORD,
    });
    expect(missing.error?.code).toBe("INVALID_PASSWORD");
    expect(opaqueRows()).toHaveLength(0);
  });

  test("requireCurrentPassword: false accepts a fresh session and refuses a stale one", async () => {
    const { browser, sessionRows, opaqueRows } = await setUpClassic({
      opaque: { attach: { requireCurrentPassword: false, freshSessionAge: 600 } },
    });
    for (const row of sessionRows()) {
      row.createdAt = new Date(Date.now() - 60 * 60 * 1000);
    }
    const stale = await browser.authClient.opaque.attachCredential({
      newPassword: OPAQUE_PASSWORD,
    });
    expect(stale.error?.code).toBe("SESSION_NOT_FRESH");
    expect(stale.error?.status).toBe(403);
    expect(opaqueRows()).toHaveLength(0);

    for (const row of sessionRows()) {
      row.createdAt = new Date();
    }
    const fresh = await browser.authClient.opaque.attachCredential({
      newPassword: OPAQUE_PASSWORD,
    });
    expect(fresh.error).toBeNull();
    expect(opaqueRows()).toHaveLength(1);
  });

  test("a user who already has an OPAQUE credential gets OPAQUE_ACCOUNT_EXISTS", async () => {
    const { auth } = await setUpClassic();
    const owner = createTestClient(auth);
    expect(
      (
        await owner.authClient.signUp.opaque({
          email: "has-opaque@example.com",
          password: OPAQUE_PASSWORD,
          name: "Has",
        })
      ).error,
    ).toBeNull();
    const attach = await owner.authClient.opaque.attachCredential({
      newPassword: CHANGED,
      currentPassword: CLASSIC,
    });
    expect(attach.error?.code).toBe("OPAQUE_ACCOUNT_EXISTS");
  });

  test("a classic password changed between challenge and complete fails with CREDENTIAL_CHANGED", async () => {
    const { auth, browser, classicRows, opaqueRows } = await setUpClassic();
    const challenge = await rawAttachChallenge(auth, browser, {
      password: OPAQUE_PASSWORD,
      currentPassword: CLASSIC,
    });
    expect(challenge.response.status).toBe(200);

    classicRows()[0]!.password = "replaced-hash";
    const complete = await post(auth, browser, OPAQUE_PATHS.attachComplete, {
      stateId: challenge.response.body!.stateId,
      registrationRecord: finishRawRegistration(challenge),
    });
    expect(complete.status).toBe(409);
    expect(complete.body?.code).toBe("CREDENTIAL_CHANGED");
    expect(opaqueRows()).toHaveLength(0);
    expect(classicRows()).toHaveLength(1);
  });

  test("the challenge state is single use and bound to its user", async () => {
    const { auth, browser, opaqueRows } = await setUpClassic();
    const challenge = await rawAttachChallenge(auth, browser, {
      password: OPAQUE_PASSWORD,
      currentPassword: CLASSIC,
    });
    const body = {
      stateId: challenge.response.body!.stateId,
      registrationRecord: finishRawRegistration(challenge),
    };

    expect((await post(auth, browser, OPAQUE_PATHS.attachComplete, body)).status).toBe(200);
    expect(opaqueRows()).toHaveLength(1);
    // Replay with the (now replaced) session cookie is unauthenticated; with a fresh session
    // the consumed state is gone.
    const again = await post(auth, browser, OPAQUE_PATHS.attachComplete, body);
    expect(again.status).toBeGreaterThanOrEqual(400);
    expect(opaqueRows()).toHaveLength(1);
  });

  test("concurrent attaches never leave two OPAQUE accounts", { timeout: 30_000 }, async () => {
    const { auth, browser, app, opaqueRows, classicRows } = await setUpClassic();
    const first = await rawAttachChallenge(auth, browser, {
      password: OPAQUE_PASSWORD,
      currentPassword: CLASSIC,
    });
    const second = await rawAttachChallenge(auth, browser, {
      password: "another-opaque-password",
      currentPassword: CLASSIC,
    });

    // Hold both flows after their pre-checks so both insert before either re-checks.
    let arrived = 0;
    let release!: () => void;
    // `Promise.withResolvers` is not in the repo's TypeScript lib target.
    const bothArrived = new Promise<void>((resolve) => {
      release = resolve;
    });
    app.pauses.set("commitPayload", async () => {
      arrived += 1;
      if (arrived === 2) {
        release();
      }
      await bothArrived;
    });

    const results = await Promise.all(
      [first, second].map((challenge) =>
        post(auth, browser, OPAQUE_PATHS.attachComplete, {
          stateId: challenge.response.body!.stateId,
          registrationRecord: finishRawRegistration(challenge),
          payload: { tag: "attached" },
        }),
      ),
    );

    // Both inserted before either re-checked, so both back out; a retry then succeeds.
    expect(results.map((result) => result.status)).toEqual([409, 409]);
    for (const result of results) {
      expect(result.body?.code).toBe("OPAQUE_ACCOUNT_EXISTS");
    }
    expect(opaqueRows()).toHaveLength(0);
    expect(classicRows()).toHaveLength(1);

    app.pauses.clear();
    const retry = await browser.authClient.opaque.attachCredential({
      newPassword: OPAQUE_PASSWORD,
      currentPassword: CLASSIC,
    });
    expect(retry.error).toBeNull();
    expect(opaqueRows()).toHaveLength(1);
  });

  test("a malformed registration record is rejected before anything is written", async () => {
    const { auth, browser, opaqueRows, classicRows, sessionRows } = await setUpClassic();
    const challenge = await rawAttachChallenge(auth, browser, {
      password: OPAQUE_PASSWORD,
      currentPassword: CLASSIC,
    });
    const sessionsBefore = sessionRows().length;

    const complete = await post(auth, browser, OPAQUE_PATHS.attachComplete, {
      stateId: challenge.response.body!.stateId,
      registrationRecord: "AAAA",
    });
    expect(complete.status).toBe(400);
    expect(complete.body?.code).toBe("INVALID_OPAQUE_MESSAGE");
    expect(opaqueRows()).toHaveLength(0);
    expect(classicRows()).toHaveLength(1);
    expect(sessionRows()).toHaveLength(sessionsBefore);
  });

  test("the per-account rate limit refuses attach challenges", async () => {
    const { auth, browser, db, opaqueRows } = await setUpClassic({
      opaque: { accountRateLimit: ({ flow }) => flow !== "attach" },
    });
    const verificationBefore = db.verification.length;
    const challenge = await rawAttachChallenge(auth, browser, {
      password: OPAQUE_PASSWORD,
      currentPassword: CLASSIC,
    });
    expect(challenge.response.status).toBe(429);
    expect(challenge.response.body?.code).toBe("TOO_MANY_ATTEMPTS");
    expect(db.verification.length).toBe(verificationBefore);
    expect(opaqueRows()).toHaveLength(0);
  });
});

async function setUpOpaqueUser(config: SetUpConfig = {}) {
  const setup = await setUpClassic(config);
  const attached = await setup.browser.authClient.opaque.attachCredential({
    newPassword: OPAQUE_PASSWORD,
    currentPassword: CLASSIC,
  });
  expect(attached.error).toBeNull();
  setup.changes.length = 0;
  return setup;
}

describe("credential changes of an OPAQUE user", () => {
  test("a malformed registration record is rejected at change-password complete", async () => {
    const { auth, browser, opaqueRows, sessionRows } = await setUpOpaqueUser();
    const recordBefore = opaqueRows()[0]?.[OPAQUE_ACCOUNT_FIELDS.registrationRecord];
    const sessionsBefore = sessionRows().length;

    const login = opaqueProtocol.startLogin({ password: OPAQUE_PASSWORD });
    const registration = opaqueProtocol.startRegistration({ password: CHANGED });
    const challenge = await post(auth, browser, OPAQUE_PATHS.changePasswordChallenge, {
      loginRequest: login.startLoginRequest,
      registrationRequest: registration.registrationRequest,
    });
    expect(challenge.status).toBe(200);
    const proven = opaqueProtocol.finishLogin({
      clientLoginState: login.clientLoginState,
      loginResponse: challenge.body!.loginResponse as string,
      password: OPAQUE_PASSWORD,
      keyStretching: challenge.body!.loginKeyStretching as typeof CHEAP_STRETCHING,
    });

    const complete = await post(auth, browser, OPAQUE_PATHS.changePasswordComplete, {
      stateId: challenge.body!.stateId,
      loginFinalization: proven!.finishLoginRequest,
      registrationRecord: "AAAA",
    });
    expect(complete.body?.code).toBe("INVALID_OPAQUE_MESSAGE");
    expect(opaqueRows()[0]?.[OPAQUE_ACCOUNT_FIELDS.registrationRecord]).toBe(recordBefore);
    expect(sessionRows()).toHaveLength(sessionsBefore);
  });

  test("a malformed registration record is rejected at reset complete", async () => {
    const { auth, opaqueRows } = await setUpOpaqueUser();
    const { url } = await auth.api.createPasswordResetToken({ body: { email: EMAIL } });
    const token = new URL(url).searchParams.get("token")!;
    const recordBefore = opaqueRows()[0]?.[OPAQUE_ACCOUNT_FIELDS.registrationRecord];

    const registration = opaqueProtocol.startRegistration({ password: CHANGED });
    const challenge = await postJson(auth, OPAQUE_PATHS.resetChallenge, {
      token,
      registrationRequest: registration.registrationRequest,
    });
    expect(challenge.status).toBe(200);
    const complete = await postJson(auth, OPAQUE_PATHS.resetComplete, {
      stateId: challenge.body!.stateId,
      registrationRecord: "AAAA",
    });
    expect(complete.body?.code).toBe("INVALID_OPAQUE_MESSAGE");
    expect(opaqueRows()[0]?.[OPAQUE_ACCOUNT_FIELDS.registrationRecord]).toBe(recordBefore);
  });

  test("the per-account rate limit refuses change-password challenges", async () => {
    const { auth, browser, db } = await setUpOpaqueUser({
      opaque: { accountRateLimit: ({ flow }) => flow !== "change-password" },
    });
    const verificationBefore = db.verification.length;
    const response = await post(auth, browser, OPAQUE_PATHS.changePasswordChallenge, {
      loginRequest: opaqueProtocol.startLogin({ password: OPAQUE_PASSWORD }).startLoginRequest,
      registrationRequest: opaqueProtocol.startRegistration({ password: CHANGED })
        .registrationRequest,
    });
    expect(response.status).toBe(429);
    expect(response.body?.code).toBe("TOO_MANY_ATTEMPTS");
    expect(db.verification.length).toBe(verificationBefore);
  });
});

describe("onCredentialChanged", () => {
  test("fires once per attach, change, and reset with the right versions", async () => {
    const { auth, browser, userId, changes, currentVersion } = await setUpClassic();

    expect(
      (
        await browser.authClient.opaque.attachCredential({
          newPassword: OPAQUE_PASSWORD,
          currentPassword: CLASSIC,
        })
      ).error,
    ).toBeNull();
    const attachedVersion = currentVersion() as string;
    expect(changes).toEqual([
      {
        userId,
        flow: "attach",
        previousCredentialVersion: null,
        credentialVersion: attachedVersion,
      },
    ]);

    expect(
      (
        await browser.authClient.opaque.changePassword({
          currentPassword: OPAQUE_PASSWORD,
          newPassword: CHANGED,
        })
      ).error,
    ).toBeNull();
    const changedVersion = currentVersion() as string;
    expect(changes).toHaveLength(2);
    expect(changes[1]).toEqual({
      userId,
      flow: "change-password",
      previousCredentialVersion: attachedVersion,
      credentialVersion: changedVersion,
    });

    const { url } = await auth.api.createPasswordResetToken({ body: { email: EMAIL } });
    expect(
      (
        await createTestClient(auth).authClient.opaque.resetPassword({
          token: new URL(url).searchParams.get("token")!,
          newPassword: "reset-password-3",
        })
      ).error,
    ).toBeNull();
    expect(changes).toHaveLength(3);
    expect(changes[2]).toEqual({
      userId,
      flow: "reset-password",
      previousCredentialVersion: changedVersion,
      credentialVersion: currentVersion(),
    });
  });

  test("still fires, after sessions were revoked, when activatePayload throws", async () => {
    const { app, browser, changes, sessionRows } = await setUpClassic();

    app.faults.add("activatePayload");
    const attached = await browser.authClient.opaque.attachCredential({
      newPassword: OPAQUE_PASSWORD,
      currentPassword: CLASSIC,
    });
    app.faults.clear();

    expect(attached.error).not.toBeNull();
    expect(changes).toHaveLength(1);
    expect(changes[0]).toMatchObject({ flow: "attach", previousCredentialVersion: null });
    expect(sessionRows()).toHaveLength(0);
  });

  test("a throwing hook is returned to the client without rolling the change back", async () => {
    const { auth, browser, classicRows, opaqueRows } = await setUpClassic({
      opaque: {
        hooks: {
          onCredentialChanged: () => {
            throw new Error("audit sink down");
          },
        },
      },
    });
    const attached = await browser.authClient.opaque.attachCredential({
      newPassword: OPAQUE_PASSWORD,
      currentPassword: CLASSIC,
    });
    expect(attached.error).not.toBeNull();
    expect(opaqueRows()).toHaveLength(1);
    expect(classicRows()).toHaveLength(0);
    expect(
      (
        await createTestClient(auth).authClient.signIn.opaque({
          email: EMAIL,
          password: OPAQUE_PASSWORD,
        })
      ).error,
    ).toBeNull();
  });
});

const enrolmentLink = async (auth: AuthUnderTest) => {
  const { url } = await auth.api.createPasswordResetToken({
    body: { email: EMAIL, allowEnrolment: true },
  });
  return new URL(url).searchParams.get("token")!;
};

describe("reset enrolment of a classic-only user", () => {
  test("without allowEnrolment the user gets USER_NOT_FOUND", async () => {
    const { auth } = await setUpClassic();
    await expect(
      auth.api.createPasswordResetToken({ body: { email: EMAIL } }),
    ).rejects.toMatchObject({ body: { code: "USER_NOT_FOUND" } });
    await expect(
      auth.api.createPasswordResetToken({
        body: { email: "nobody@example.com", allowEnrolment: true },
      }),
    ).rejects.toMatchObject({ body: { code: "USER_NOT_FOUND" } });
  });

  test("registers the first credential, drops the classic password, and revokes sessions", async () => {
    const loaded: unknown[] = [];
    const { auth, browser, changes, opaqueRows, classicRows, sessionRows, userId } =
      await setUpClassic({
        opaque: {
          hooks: {
            loadPayload: (input) => {
              loaded.push(input);
              return { recovery: "material" };
            },
            onCredentialChanged: () => {},
          },
        },
      });
    const token = await enrolmentLink(auth);

    const verify = await createTestClient(auth).authClient.opaque.verifyResetToken({ token });
    expect(verify.data?.payload).toEqual({ recovery: "material" });
    expect(loaded).toEqual([{ userId, credentialVersion: null, flow: "reset-password" }]);

    const reset = await createTestClient(auth).authClient.opaque.resetPassword({
      token,
      newPassword: OPAQUE_PASSWORD,
    });
    expect(reset.error).toBeNull();
    expect(opaqueRows()).toHaveLength(1);
    expect(classicRows()).toHaveLength(0);
    expect(sessionRows()).toHaveLength(0);
    expect((await browser.authClient.getSession()).data).toBeNull();

    const signIn = await createTestClient(auth).authClient.signIn.opaque({
      email: EMAIL,
      password: OPAQUE_PASSWORD,
    });
    expect(signIn.error).toBeNull();
    expect(signIn.data?.exportKey).toBe(reset.data?.exportKey);
    expect(changes).toHaveLength(0);
  });

  test("reports the enrolment to onCredentialChanged", async () => {
    const { auth, changes, userId, currentVersion } = await setUpClassic();
    const token = await enrolmentLink(auth);
    expect(
      (
        await createTestClient(auth).authClient.opaque.resetPassword({
          token,
          newPassword: OPAQUE_PASSWORD,
        })
      ).error,
    ).toBeNull();
    expect(changes).toEqual([
      {
        userId,
        flow: "reset-password",
        previousCredentialVersion: null,
        credentialVersion: currentVersion(),
      },
    ]);
  });

  test("removeClassicCredential: false keeps the classic password after enrolment", async () => {
    const { auth, classicRows } = await setUpClassic({
      opaque: { removeClassicCredential: false },
    });
    expect(
      (
        await createTestClient(auth).authClient.opaque.resetPassword({
          token: await enrolmentLink(auth),
          newPassword: OPAQUE_PASSWORD,
        })
      ).error,
    ).toBeNull();
    expect(classicRows()).toHaveLength(1);
  });

  test("an enrolment link dies once the user owns an OPAQUE credential", async () => {
    const { auth } = await setUpClassic();
    const used = await enrolmentLink(auth);
    const stale = await enrolmentLink(auth);
    expect(
      (
        await createTestClient(auth).authClient.opaque.resetPassword({
          token: used,
          newPassword: OPAQUE_PASSWORD,
        })
      ).error,
    ).toBeNull();

    const client = createTestClient(auth);
    expect((await client.authClient.opaque.verifyResetToken({ token: stale })).error?.code).toBe(
      "INVALID_RESET_TOKEN",
    );
    expect(
      (await client.authClient.opaque.resetPassword({ token: stale, newPassword: CHANGED })).error
        ?.code,
    ).toBe("INVALID_RESET_TOKEN");
  });

  test("an enrolment link and a concurrent attach resolve to one OPAQUE account", async () => {
    const { auth, browser, opaqueRows } = await setUpClassic();
    const token = await enrolmentLink(auth);
    const challenge = await postJson(auth, OPAQUE_PATHS.resetChallenge, {
      token,
      registrationRequest: opaqueProtocol.startRegistration({ password: CHANGED })
        .registrationRequest,
    });
    expect(challenge.status).toBe(200);

    expect(
      (
        await browser.authClient.opaque.attachCredential({
          newPassword: OPAQUE_PASSWORD,
          currentPassword: CLASSIC,
        })
      ).error,
    ).toBeNull();

    // The enrolment's challenge predates the attach; completing it must not add a second row.
    const registration = opaqueProtocol.startRegistration({ password: CHANGED });
    const finished = opaqueProtocol.finishRegistration({
      password: CHANGED,
      registrationResponse: challenge.body!.registrationResponse as string,
      clientRegistrationState: registration.clientRegistrationState,
      keyStretching: challenge.body!.keyStretching as typeof CHEAP_STRETCHING,
    });
    const complete = await postJson(auth, OPAQUE_PATHS.resetComplete, {
      stateId: challenge.body!.stateId,
      registrationRecord: finished.registrationRecord,
    });
    expect(complete.status).toBeGreaterThanOrEqual(400);
    expect(opaqueRows()).toHaveLength(1);
  });
});
