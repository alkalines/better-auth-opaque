import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { client as opaqueProtocol } from "@serenity-kit/opaque";
import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { twoFactor } from "better-auth/plugins";
import { expect, test } from "vitest";
import { OPAQUE_PATHS } from "../../src/contract.ts";
import { opaque } from "../../src/server/index.ts";
import {
  BASE_URL,
  CHEAP_STRETCHING,
  createMemoryDb,
  createPayloadApp,
  createTestClient,
  expectNotSent,
  postJson,
  SECRET,
  serverSetupForTests,
  type TestClient,
} from "./helpers.ts";

const EMAIL = "2fa@example.com";
const PASSWORD = "2fa-password-never-transmitted";
const PAYLOAD = { ciphertext: "credential-bound-encrypted-app-payload" };

async function fixture(input?: { missingHook?: boolean; opaqueFirst?: boolean; maxAge?: number }) {
  const db = { ...createMemoryDb(), twoFactor: [] };
  const app = createPayloadApp();
  const opaquePlugin = opaque({
    serverSetup: await serverSetupForTests(),
    keyStretching: CHEAP_STRETCHING,
    hooks: app.hooks,
    passwordReset: { url: (token) => `https://example.com/reset?token=${token}` },
  });
  const twoFactorPlugin = twoFactor({
    allowPasswordless: true,
    twoFactorCookieMaxAge: input?.maxAge,
  });
  if (input?.missingHook) twoFactorPlugin.hooks.after = [];
  const plugins = input?.opaqueFirst
    ? [opaquePlugin, twoFactorPlugin]
    : [twoFactorPlugin, opaquePlugin];
  const auth = betterAuth({
    baseURL: BASE_URL,
    secret: SECRET,
    database: memoryAdapter(db),
    rateLimit: { enabled: false },
    logger: { disabled: true },
    plugins,
  });
  const browser = createTestClient(auth);
  const signUp = await browser.authClient.signUp.opaque({
    email: EMAIL,
    password: PASSWORD,
    name: "Two Factor",
    payload: PAYLOAD,
  });
  expect(signUp.error).toBeNull();
  return { db, app, auth, browser, exportKey: signUp.data!.exportKey };
}

async function passwordProof(browser: TestClient, password = PASSWORD): Promise<string> {
  const result = await browser.authClient.opaque.createPasswordProof({ password });
  expect(result.error).toBeNull();
  return result.data!.proof;
}

async function totpCode(uri: string): Promise<string> {
  const secret = new URL(uri).searchParams.get("secret");
  expect(secret).toBeTruthy();
  return createOTP(base32.decode(secret!)).totp();
}

async function enableTotp(browser: TestClient): Promise<string> {
  const enabled = await browser.authClient.twoFactor.enable({
    password: await passwordProof(browser),
  });
  expect(enabled.error).toBeNull();
  expect(enabled.data).toHaveProperty("totpURI");
  if (enabled.data?.method !== "totp") throw new Error("Expected TOTP setup");
  const uri = enabled.data!.totpURI!;
  expect(
    (await browser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
  ).toBeNull();
  return uri;
}

async function pendingSignIn(browser: TestClient, password = PASSWORD) {
  const result = await browser.authClient.signIn.opaque({ email: EMAIL, password });
  expect(result.error).toBeNull();
  if (!result.data?.twoFactorRedirect) throw new Error("Expected a second-factor challenge");
  expect(result.data.twoFactorMethods).toContain("totp");
  expect(result.data).not.toHaveProperty("payload");
  expect(result.data).not.toHaveProperty("token");
  expect(result.data).not.toHaveProperty("user");
  expect(result.data.payloadToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
  return result.data;
}

test("OPAQUE proves the password for every 2FA management endpoint without sending it", async () => {
  const { browser, db } = await fixture();
  const wrong = await browser.authClient.opaque.createPasswordProof({ password: "wrong-password" });
  expect(wrong.error).toMatchObject({ status: 400, code: "INVALID_PASSWORD" });
  expect((await browser.authClient.twoFactor.enable({})).error?.code).toBe("INVALID_PASSWORD");
  expect((await browser.authClient.twoFactor.enable({ password: "garbage" })).error?.code).toBe(
    "INVALID_PASSWORD",
  );

  const proof = await passwordProof(browser);
  const enabled = await browser.authClient.twoFactor.enable({ password: proof });
  expect(enabled.error).toBeNull();
  expect((await browser.authClient.twoFactor.enable({ password: proof })).error?.code).toBe(
    "INVALID_PASSWORD",
  );
  if (enabled.data?.method !== "totp") throw new Error("Expected TOTP setup");
  const uri = enabled.data!.totpURI!;
  expect(
    (await browser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
  ).toBeNull();
  expect(db.user[0]!.twoFactorEnabled).toBe(true);

  for (const call of [
    (password: string) => browser.authClient.twoFactor.getTotpUri({ password }),
    (password: string) => browser.authClient.twoFactor.generateBackupCodes({ password }),
  ]) {
    expect((await call("garbage")).error?.code).toBe("INVALID_PASSWORD");
    const managementProof = await passwordProof(browser);
    expect((await call(managementProof)).error).toBeNull();
    expect((await call(managementProof)).error?.code).toBe("INVALID_PASSWORD");
  }
  expect((await browser.authClient.twoFactor.disable({ password: "garbage" })).error?.code).toBe(
    "INVALID_PASSWORD",
  );
  const disableProof = await passwordProof(browser);
  expect((await browser.authClient.twoFactor.disable({ password: disableProof })).error).toBeNull();
  expect((await browser.authClient.twoFactor.disable({ password: disableProof })).error?.code).toBe(
    "INVALID_PASSWORD",
  );
  expectNotSent([browser], [PASSWORD, "wrong-password"]);
});

test("management proofs are user-bound, version-bound, hashed, expiring, and single use", async () => {
  const { browser, auth, db } = await fixture();
  const other = createTestClient(auth);
  await other.authClient.signUp.opaque({
    email: "other@example.com",
    password: "other-password",
    name: "Other",
  });
  const foreignProof = await passwordProof(other, "other-password");
  expect((await browser.authClient.twoFactor.enable({ password: foreignProof })).error?.code).toBe(
    "INVALID_PASSWORD",
  );
  expect((await other.authClient.twoFactor.enable({ password: foreignProof })).error?.code).toBe(
    "INVALID_PASSWORD",
  );

  const stale = await passwordProof(browser);
  expect(
    (
      await browser.authClient.opaque.changePassword({
        currentPassword: PASSWORD,
        newPassword: "new-password",
      })
    ).error,
  ).toBeNull();
  expect((await browser.authClient.twoFactor.enable({ password: stale })).error?.code).toBe(
    "INVALID_PASSWORD",
  );
  const expired = await passwordProof(browser, "new-password");
  const row = db.verification.find((value) =>
    String(value.identifier).startsWith("opaque:password-proof:"),
  )!;
  expect(row.value).not.toContain(expired);
  expect(row.identifier).not.toContain(expired);
  expect(
    new Date(row.expiresAt as Date).getTime() - new Date(row.createdAt as Date).getTime(),
  ).toBeLessThanOrEqual(300_000);
  row.expiresAt = new Date(Date.now() - 1000);
  expect((await browser.authClient.twoFactor.enable({ password: expired })).error?.code).toBe(
    "INVALID_PASSWORD",
  );
  expectNotSent([browser, other], [PASSWORD, "other-password", "new-password"]);
});

for (const opaqueFirst of [false, true]) {
  test(`2FA gates payload/session and preserves endpoint-to-hook context (opaque first: ${opaqueFirst})`, async () => {
    const { browser: owner, auth, db, exportKey } = await fixture({ opaqueFirst, maxAge: 120 });
    const uri = await enableTotp(owner);
    await owner.authClient.signOut();
    const browser = createTestClient(auth);
    const pending = await pendingSignIn(browser);
    expect(pending.exportKey).toBe(exportKey);
    expect(db.session).toHaveLength(0);
    expect((await browser.authClient.getSession()).data).toBeNull();
    expect(browser.responses.every(({ body }) => !body.includes(PAYLOAD.ciphertext))).toBe(true);
    const row = db.verification.find((value) =>
      String(value.identifier).startsWith("opaque:two-factor-payload:"),
    )!;
    expect(row.identifier).not.toContain(pending.payloadToken);
    expect(row.value).not.toContain(pending.payloadToken);
    expect(
      new Date(row.expiresAt as Date).getTime() - new Date(row.createdAt as Date).getTime(),
    ).toBeLessThanOrEqual(120_000);
    const unauthenticated = await browser.authClient.opaque.loadSignInPayload({
      payloadToken: pending.payloadToken,
    });
    expect(unauthenticated.error?.status).toBe(401);
    expect(
      (await browser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
    ).toBeNull();
    expect((await browser.authClient.getSession()).data?.user.email).toBe(EMAIL);
    expect(
      (await browser.authClient.opaque.loadSignInPayload({ payloadToken: pending.payloadToken }))
        .data?.payload,
    ).toEqual(PAYLOAD);
    expect(
      (await browser.authClient.opaque.loadSignInPayload({ payloadToken: pending.payloadToken }))
        .error?.code,
    ).toBe("INVALID_STATE");
    expectNotSent([owner, browser], [PASSWORD, exportKey]);
  });
}

test("payload tokens reject another user's session, an older session, and expiry", async () => {
  const { browser: owner, auth, db } = await fixture();
  const uri = await enableTotp(owner);
  const oldSession = new Map(owner.cookies);
  const other = createTestClient(auth);
  await other.authClient.signUp.opaque({
    email: "other@example.com",
    password: "other-password",
    name: "Other",
  });
  const browser = createTestClient(auth);
  const pending = await pendingSignIn(browser);
  expect(
    (await other.authClient.opaque.loadSignInPayload({ payloadToken: pending.payloadToken })).error
      ?.code,
  ).toBe("INVALID_STATE");
  expect(
    (await browser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
  ).toBeNull();
  expect(
    (await browser.authClient.opaque.loadSignInPayload({ payloadToken: pending.payloadToken }))
      .error?.code,
  ).toBe("INVALID_STATE");

  const next = createTestClient(auth);
  const nextPending = await pendingSignIn(next);
  const oldBrowser = createTestClient(auth);
  for (const [name, value] of oldSession) oldBrowser.cookies.set(name, value);
  // Model a definitely older stored session, even on coarse clocks.
  const ownerId = db.user.find((row) => row.email === EMAIL)!.id;
  for (const session of db.session.filter((row) => row.userId === ownerId))
    session.createdAt = new Date(0);
  expect(
    (
      await oldBrowser.authClient.opaque.loadSignInPayload({
        payloadToken: nextPending.payloadToken,
      })
    ).error?.code,
  ).toBe("INVALID_STATE");

  const expiredBrowser = createTestClient(auth);
  const expiredPending = await pendingSignIn(expiredBrowser);
  for (const row of db.verification.filter((value) =>
    String(value.identifier).startsWith("opaque:two-factor-payload:"),
  )) {
    row.expiresAt = new Date(Date.now() - 1000);
  }
  expect(
    (await expiredBrowser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
  ).toBeNull();
  expect(
    (
      await expiredBrowser.authClient.opaque.loadSignInPayload({
        payloadToken: expiredPending.payloadToken,
      })
    ).error?.code,
  ).toBe("INVALID_STATE");
});

test("reset after the first factor invalidates the credential-bound payload token", async () => {
  const { browser: owner, auth } = await fixture();
  const uri = await enableTotp(owner);
  await owner.authClient.signOut();
  const browser = createTestClient(auth);
  const pending = await pendingSignIn(browser);
  const reset = await auth.api.createPasswordResetToken({ body: { email: EMAIL } });
  const token = new URL(reset.url).searchParams.get("token")!;
  expect(
    (
      await createTestClient(auth).authClient.opaque.resetPassword({
        token,
        newPassword: "reset-password",
        payload: { ciphertext: "replacement" },
      })
    ).error,
  ).toBeNull();
  expect(
    (await browser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
  ).toBeNull();
  expect(
    (await browser.authClient.opaque.loadSignInPayload({ payloadToken: pending.payloadToken }))
      .error?.code,
  ).toBe("CREDENTIAL_CHANGED");
});

test("trusted devices receive the payload directly and failed loading revokes the new session", async () => {
  const { browser, auth, app, exportKey, db } = await fixture();
  const uri = await enableTotp(browser);
  await browser.authClient.signOut();
  const pending = await pendingSignIn(browser);
  expect(
    (
      await browser.authClient.twoFactor.verifyTotp({
        code: await totpCode(uri),
        trustDevice: true,
      })
    ).error,
  ).toBeNull();
  expect(
    (await browser.authClient.opaque.loadSignInPayload({ payloadToken: pending.payloadToken }))
      .error,
  ).toBeNull();
  await browser.authClient.signOut();
  const trusted = await browser.authClient.signIn.opaque({ email: EMAIL, password: PASSWORD });
  expect(trusted.error).toBeNull();
  expect(trusted.data?.twoFactorRedirect).not.toBe(true);
  expect(trusted.data?.payload).toEqual(PAYLOAD);
  expect(trusted.data?.exportKey).toBe(exportKey);
  expect((await browser.authClient.getSession()).data?.user.email).toBe(EMAIL);
  await browser.authClient.signOut();
  app.faults.add("loadPayload");
  const failed = await browser.authClient.signIn.opaque({ email: EMAIL, password: PASSWORD });
  expect(failed.error?.status).toBe(500);
  expect(db.session).toHaveLength(0);
  expect((await browser.authClient.getSession()).data).toBeNull();
  expect((await createTestClient(auth).authClient.getSession()).data).toBeNull();
});

test("wrong and unknown passwords disclose no 2FA signal; disabling restores direct sign-in", async () => {
  const { browser: owner, auth } = await fixture();
  await enableTotp(owner);
  const browser = createTestClient(auth);
  const wrong = await browser.authClient.signIn.opaque({
    email: EMAIL,
    password: "wrong-password",
  });
  const unknown = await browser.authClient.signIn.opaque({
    email: "unknown@example.com",
    password: "wrong-password",
  });
  expect(wrong).toEqual(unknown);
  expect(wrong.error).toMatchObject({ status: 401, code: "INVALID_CREDENTIALS" });
  expect(browser.responses.every(({ body }) => !body.includes("twoFactorRedirect"))).toBe(true);
  expect(
    (await owner.authClient.twoFactor.disable({ password: await passwordProof(owner) })).error,
  ).toBeNull();
  const direct = await browser.authClient.signIn.opaque({ email: EMAIL, password: PASSWORD });
  expect(direct.error).toBeNull();
  expect(direct.data?.token).toBeTruthy();
  expect(direct.data?.payload).toEqual(PAYLOAD);
});

test("2FA fails closed after a valid proof when the installed plugin's sign-in hook is missing", async () => {
  const { auth, db } = await fixture({ missingHook: true });
  db.user[0]!.twoFactorEnabled = true;
  const browser = createTestClient(auth);
  const sessionsBefore = db.session.length;
  const result = await browser.authClient.signIn.opaque({ email: EMAIL, password: PASSWORD });
  expect(result.error).toMatchObject({ status: 403, code: "TWO_FACTOR_NOT_SUPPORTED" });
  expect(db.session).toHaveLength(sessionsBefore);
  expect((await browser.authClient.getSession()).data).toBeNull();
  expect(browser.responses.every(({ body }) => !body.includes(PAYLOAD.ciphertext))).toBe(true);
});

test("password proof challenge state cannot cross sessions or survive a credential change", async () => {
  const { browser, auth } = await fixture();
  const other = createTestClient(auth);
  await other.authClient.signUp.opaque({
    email: "other@example.com",
    password: "other-password",
    name: "Other",
  });
  const login = opaqueProtocol.startLogin({ password: PASSWORD });
  const cookie = [...browser.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  const challenge = await postJson(
    auth,
    OPAQUE_PATHS.passwordProofChallenge,
    { loginRequest: login.startLoginRequest },
    { cookie },
  );
  const finished = opaqueProtocol.finishLogin({
    password: PASSWORD,
    clientLoginState: login.clientLoginState,
    loginResponse: challenge.body!.loginResponse as string,
    keyStretching: CHEAP_STRETCHING,
  })!;
  const otherCookie = [...other.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  const crossed = await postJson(
    auth,
    OPAQUE_PATHS.passwordProofComplete,
    { stateId: challenge.body!.stateId, loginFinalization: finished.finishLoginRequest },
    { cookie: otherCookie },
  );
  expect(crossed.body?.code).toBe("INVALID_PASSWORD");
  const reused = await postJson(
    auth,
    OPAQUE_PATHS.passwordProofComplete,
    { stateId: challenge.body!.stateId, loginFinalization: finished.finishLoginRequest },
    { cookie },
  );
  expect(reused.body?.code).toBe("INVALID_STATE");
  const staleLogin = opaqueProtocol.startLogin({ password: PASSWORD });
  const staleChallenge = await postJson(
    auth,
    OPAQUE_PATHS.passwordProofChallenge,
    { loginRequest: staleLogin.startLoginRequest },
    { cookie },
  );
  const staleFinished = opaqueProtocol.finishLogin({
    password: PASSWORD,
    clientLoginState: staleLogin.clientLoginState,
    loginResponse: staleChallenge.body!.loginResponse as string,
    keyStretching: CHEAP_STRETCHING,
  })!;
  expect(
    (
      await browser.authClient.opaque.changePassword({
        currentPassword: PASSWORD,
        newPassword: "replacement-password",
      })
    ).error,
  ).toBeNull();
  const staleComplete = await postJson(
    auth,
    OPAQUE_PATHS.passwordProofComplete,
    { stateId: staleChallenge.body!.stateId, loginFinalization: staleFinished.finishLoginRequest },
    { cookie },
  );
  expect(staleComplete.body?.code).toBe("INVALID_PASSWORD");
});
