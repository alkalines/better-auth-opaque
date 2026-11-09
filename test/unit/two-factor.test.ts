import { base32 } from "@better-auth/utils/base32";
import { createOTP } from "@better-auth/utils/otp";
import { client as opaqueProtocol } from "@serenity-kit/opaque";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { twoFactor } from "better-auth/plugins";
import { expect, test } from "vitest";
import { OPAQUE_PATHS } from "../../src/contract.ts";
import { opaque, type OpaqueOptions } from "../../src/server/index.ts";
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

async function fixture(input?: {
  missingHook?: boolean;
  opaqueFirst?: boolean;
  maxAge?: number;
  accountRateLimit?: OpaqueOptions["accountRateLimit"];
  advanced?: BetterAuthOptions["advanced"];
  /** Also enables Better Auth's own email/password sign-in. */
  classic?: boolean;
}) {
  const db = { ...createMemoryDb(), twoFactor: [] };
  const app = createPayloadApp();
  const opaquePlugin = opaque({
    serverSetup: await serverSetupForTests(),
    keyStretching: CHEAP_STRETCHING,
    hooks: app.hooks,
    passwordReset: { url: (token) => `https://example.com/reset?token=${token}` },
    accountRateLimit: input?.accountRateLimit,
  });
  const otps: string[] = [];
  const resetTokens: string[] = [];
  // Runs before every session row is written; a test arms it to race a credential switch.
  const sessionCreation: { before?: () => Promise<void> } = {};
  const twoFactorPlugin = twoFactor({
    allowPasswordless: true,
    twoFactorCookieMaxAge: input?.maxAge,
    otpOptions: {
      sendOTP: ({ otp }) => {
        otps.push(otp);
      },
    },
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
    advanced: input?.advanced,
    emailAndPassword: {
      enabled: input?.classic ?? false,
      sendResetPassword: async ({ token }) => {
        resetTokens.push(token);
      },
    },
    databaseHooks: {
      session: {
        create: {
          before: async () => {
            await sessionCreation.before?.();
          },
        },
      },
    },
  });
  const browser = createTestClient(auth);
  const signUp = await browser.authClient.signUp.opaque({
    email: EMAIL,
    password: PASSWORD,
    name: "Two Factor",
    payload: PAYLOAD,
  });
  expect(signUp.error).toBeNull();
  return {
    db,
    app,
    auth,
    browser,
    otps,
    resetTokens,
    sessionCreation,
    exportKey: signUp.data!.exportKey,
  };
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
    const bindingPrefix = "opaque:two-factor-pending:";
    const binding = db.verification.find((value) =>
      String(value.identifier).startsWith(bindingPrefix),
    )!;
    // The native challenge row is `2fa-<random>`; its random part may itself contain "-".
    const challenge = db.verification.find((value) => {
      const identifier = String(value.identifier);
      return (
        identifier.startsWith("2fa-") &&
        !identifier.startsWith("2fa-attempts-") &&
        !identifier.startsWith("2fa-otp-")
      );
    })!;
    expect(binding.identifier).not.toContain(String(challenge.identifier));
    expect(new Date(binding.expiresAt as Date).getTime()).toBeLessThanOrEqual(
      new Date(challenge.expiresAt as Date).getTime() + 1000,
    );
    const unauthenticated = await browser.authClient.opaque.loadSignInPayload({
      payloadToken: pending.payloadToken,
    });
    expect(unauthenticated.error?.status).toBe(401);
    expect(
      (await browser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
    ).toBeNull();
    expect((await browser.authClient.getSession()).data?.user.email).toBe(EMAIL);
    expect(
      db.verification.some((value) => String(value.identifier).startsWith(bindingPrefix)),
    ).toBe(false);
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

type Factor = "totp" | "otp" | "backup-code";
type Replacement = "reset" | "change-password";

async function enableAllFactors(owner: TestClient) {
  const uri = await enableTotp(owner);
  const generated = await owner.authClient.twoFactor.generateBackupCodes({
    password: await passwordProof(owner),
  });
  expect(generated.error).toBeNull();
  return { uri, backupCode: generated.data!.backupCodes[0]! };
}

async function verifySecondFactor(
  browser: TestClient,
  factor: Factor,
  secrets: { uri: string; backupCode: string; otps: string[] },
) {
  if (factor === "totp") {
    return browser.authClient.twoFactor.verifyTotp({ code: await totpCode(secrets.uri) });
  }
  if (factor === "backup-code") {
    return browser.authClient.twoFactor.verifyBackupCode({ code: secrets.backupCode });
  }
  const sent = await browser.authClient.twoFactor.sendOtp({});
  if (sent.error) return sent;
  return browser.authClient.twoFactor.verifyOtp({ code: secrets.otps.at(-1) ?? "000000" });
}

async function replacePassword(
  replacement: Replacement,
  auth: Awaited<ReturnType<typeof fixture>>["auth"],
  owner: TestClient,
) {
  let error: unknown;
  if (replacement === "change-password") {
    ({ error } = await owner.authClient.opaque.changePassword({
      currentPassword: PASSWORD,
      newPassword: "replacement-password",
    }));
  } else {
    const { url } = await auth.api.createPasswordResetToken({ body: { email: EMAIL } });
    ({ error } = await createTestClient(auth).authClient.opaque.resetPassword({
      token: new URL(url).searchParams.get("token")!,
      newPassword: "replacement-password",
      payload: { ciphertext: "replacement" },
    }));
  }
  expect(error).toBeNull();
}

for (const replacement of ["reset", "change-password"] as const) {
  for (const factor of ["totp", "otp", "backup-code"] as const) {
    test(`a pending sign-in proven before a ${replacement} cannot finish with ${factor}`, async () => {
      const { browser: owner, auth, db, otps } = await fixture();
      const secrets = { ...(await enableAllFactors(owner)), otps };
      const attacker = createTestClient(auth);
      await pendingSignIn(attacker);
      await replacePassword(replacement, auth, owner);
      const sessions = db.session.length;
      const sentOtps = otps.length;
      const challengeCookies = new Map(attacker.cookies);

      // For OTP the refusal already comes from sending: a stale challenge triggers no delivery.
      const refused = await verifySecondFactor(attacker, factor, secrets);
      expect(refused.error).toMatchObject({ status: 409, code: "CREDENTIAL_CHANGED" });
      expect(otps).toHaveLength(sentOtps);
      expect(db.session).toHaveLength(sessions);
      expect((await attacker.authClient.getSession()).data).toBeNull();

      // The challenge is retired: replaying its cookie cannot finish it either.
      for (const [name, value] of challengeCookies) attacker.cookies.set(name, value);
      const replayed = await verifySecondFactor(attacker, factor, secrets);
      expect(replayed.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
      expect(db.session).toHaveLength(sessions);

      // The refusal spent no factor: the new password still signs in with the same one.
      const browser = createTestClient(auth);
      await pendingSignIn(browser, "replacement-password");
      expect((await verifySecondFactor(browser, factor, secrets)).error).toBeNull();
      expect((await browser.authClient.getSession()).data?.user.email).toBe(EMAIL);
    });
  }
}

for (const opaqueFirst of [false, true]) {
  test(`a credential switch during second-factor verification leaves no session or trusted device (opaque first: ${opaqueFirst})`, async () => {
    const { browser: owner, auth, db, sessionCreation } = await fixture({ opaqueFirst });
    const uri = await enableTotp(owner);
    await owner.authClient.signOut();
    const attacker = createTestClient(auth);
    await pendingSignIn(attacker);
    // Switch after the verify passed its credential check, before its session is written.
    sessionCreation.before = async () => {
      sessionCreation.before = undefined;
      await replacePassword("reset", auth, owner);
    };
    const verified = await attacker.authClient.twoFactor.verifyTotp({
      code: await totpCode(uri),
      trustDevice: true,
    });
    expect(sessionCreation.before).toBeUndefined();
    expect(verified.error).toMatchObject({ status: 409, code: "CREDENTIAL_CHANGED" });
    expect(db.session).toHaveLength(0);
    expect((await attacker.authClient.getSession()).data).toBeNull();
    expect(db.verification.some((row) => String(row.identifier).startsWith("trust-device-"))).toBe(
      false,
    );
    // Even with the new password, this device was never trusted.
    await pendingSignIn(attacker, "replacement-password");
  });
}

for (const advanced of [
  { cookiePrefix: "custom-app" },
  { cookiePrefix: "custom-app", useSecureCookies: true },
]) {
  test(`the challenge binding follows the configured cookie names (${JSON.stringify(advanced)})`, async () => {
    const { browser: owner, auth } = await fixture({ advanced });
    const uri = await enableTotp(owner);
    await owner.authClient.signOut();
    const prefix = advanced.useSecureCookies ? "__Secure-custom-app." : "custom-app.";

    const browser = createTestClient(auth);
    await pendingSignIn(browser);
    expect(browser.cookies.has(`${prefix}two_factor`)).toBe(true);
    expect(
      (await browser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
    ).toBeNull();
    expect((await browser.authClient.getSession()).data?.user.email).toBe(EMAIL);

    const attacker = createTestClient(auth);
    await pendingSignIn(attacker);
    await replacePassword("reset", auth, owner);
    const refused = await attacker.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) });
    expect(refused.error?.code).toBe("CREDENTIAL_CHANGED");
    expect((await attacker.authClient.getSession()).data).toBeNull();
  });
}

const CLASSIC_EMAIL = "classic@example.com";
const CLASSIC_PASSWORD = "classic-password";

/** A user of Better Auth's own email/password sign-in with TOTP, backup codes and OTP. */
async function classicOwner(auth: Awaited<ReturnType<typeof fixture>>["auth"]) {
  const owner = createTestClient(auth);
  const signUp = await owner.authClient.signUp.email({
    email: CLASSIC_EMAIL,
    password: CLASSIC_PASSWORD,
    name: "Classic",
  });
  expect(signUp.error).toBeNull();
  const enabled = await owner.authClient.twoFactor.enable({ password: CLASSIC_PASSWORD });
  if (enabled.data?.method !== "totp") throw new Error("Expected TOTP setup");
  const uri = enabled.data.totpURI!;
  expect(
    (await owner.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
  ).toBeNull();
  const generated = await owner.authClient.twoFactor.generateBackupCodes({
    password: CLASSIC_PASSWORD,
  });
  expect(generated.error).toBeNull();
  return { owner, uri, backupCode: generated.data!.backupCodes[0]! };
}

async function startClassicSignIn(browser: TestClient, password = CLASSIC_PASSWORD) {
  const started = await browser.authClient.signIn.email({ email: CLASSIC_EMAIL, password });
  expect(started.data).toMatchObject({ twoFactorRedirect: true });
}

async function replaceClassicPassword(
  replacement: Replacement,
  auth: Awaited<ReturnType<typeof fixture>>["auth"],
  owner: TestClient,
  resetTokens: string[],
) {
  let error: unknown;
  if (replacement === "change-password") {
    ({ error } = await owner.authClient.changePassword({
      currentPassword: CLASSIC_PASSWORD,
      newPassword: "classic-replacement",
    }));
  } else {
    const browser = createTestClient(auth);
    const requested = await browser.authClient.requestPasswordReset({
      email: CLASSIC_EMAIL,
      redirectTo: "/reset",
    });
    ({ error } = requested.error
      ? requested
      : await browser.authClient.resetPassword({
          newPassword: "classic-replacement",
          token: resetTokens.at(-1)!,
        }));
  }
  expect(error).toBeNull();
}

for (const replacement of ["reset", "change-password"] as const) {
  for (const factor of ["totp", "otp", "backup-code"] as const) {
    test(`a classic-password sign-in proven before Better Auth's ${replacement} cannot finish with ${factor}`, async () => {
      const { auth, db, otps, resetTokens } = await fixture({ classic: true });
      const { owner, uri, backupCode } = await classicOwner(auth);
      const secrets = { uri, backupCode, otps };
      const attacker = createTestClient(auth);
      await startClassicSignIn(attacker);
      await replaceClassicPassword(replacement, auth, owner, resetTokens);
      const sessions = db.session.length;
      const sentOtps = otps.length;
      const challengeCookies = new Map(attacker.cookies);

      const refused = await verifySecondFactor(attacker, factor, secrets);
      expect(refused.error).toMatchObject({ status: 409, code: "CREDENTIAL_CHANGED" });
      expect(otps).toHaveLength(sentOtps);
      expect(db.session).toHaveLength(sessions);
      expect((await attacker.authClient.getSession()).data).toBeNull();

      for (const [name, value] of challengeCookies) attacker.cookies.set(name, value);
      const replayed = await verifySecondFactor(attacker, factor, secrets);
      expect(replayed.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
      expect(db.session).toHaveLength(sessions);

      const browser = createTestClient(auth);
      await startClassicSignIn(browser, "classic-replacement");
      expect((await verifySecondFactor(browser, factor, secrets)).error).toBeNull();
      expect((await browser.authClient.getSession()).data?.user.email).toBe(CLASSIC_EMAIL);
    });
  }
}

test("a classic password change inside the sign-in, after its password check, leaves the challenge stale", async () => {
  const { auth, db, sessionCreation, resetTokens } = await fixture({ classic: true });
  const { owner, uri } = await classicOwner(auth);
  const attacker = createTestClient(auth);
  // The sign-in creates its session after checking the password and before the gate's challenge.
  sessionCreation.before = async () => {
    sessionCreation.before = undefined;
    await replaceClassicPassword("change-password", auth, owner, resetTokens);
  };
  await startClassicSignIn(attacker);
  expect(sessionCreation.before).toBeUndefined();
  const sessions = db.session.length;
  const refused = await attacker.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) });
  expect(refused.error).toMatchObject({ status: 409, code: "CREDENTIAL_CHANGED" });
  expect(db.session).toHaveLength(sessions);
  expect((await attacker.authClient.getSession()).data).toBeNull();
});

test("a classic password change during second-factor verification leaves no session", async () => {
  const { auth, db, sessionCreation, resetTokens } = await fixture({ classic: true });
  const { owner, uri } = await classicOwner(auth);
  const attacker = createTestClient(auth);
  await startClassicSignIn(attacker);
  const sessions = db.session.length;
  sessionCreation.before = async () => {
    sessionCreation.before = undefined;
    await replaceClassicPassword("change-password", auth, owner, resetTokens);
  };
  const verified = await attacker.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) });
  expect(sessionCreation.before).toBeUndefined();
  expect(verified.error).toMatchObject({ status: 409, code: "CREDENTIAL_CHANGED" });
  expect(db.session).toHaveLength(sessions);
  expect((await attacker.authClient.getSession()).data).toBeNull();
});

test("a classic-password 2FA sign-in cannot finish once an OPAQUE credential was attached", async () => {
  const { auth, db } = await fixture({ classic: true });
  const { owner, uri } = await classicOwner(auth);

  // Untouched: a classic challenge still completes.
  const control = createTestClient(auth);
  await startClassicSignIn(control);
  expect(
    (await control.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
  ).toBeNull();
  expect((await control.authClient.getSession()).data?.user.email).toBe(CLASSIC_EMAIL);

  const attacker = createTestClient(auth);
  await startClassicSignIn(attacker);
  const attached = await owner.authClient.opaque.attachCredential({
    currentPassword: CLASSIC_PASSWORD,
    newPassword: "attached-password",
  });
  expect(attached.error).toBeNull();
  const sessions = db.session.length;
  const challengeCookies = new Map(attacker.cookies);
  const refused = await attacker.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) });
  expect(refused.error).toMatchObject({ status: 409, code: "CREDENTIAL_CHANGED" });
  expect(db.session).toHaveLength(sessions);
  expect((await attacker.authClient.getSession()).data).toBeNull();
  for (const [name, value] of challengeCookies) attacker.cookies.set(name, value);
  const replayed = await attacker.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) });
  expect(replayed.error?.code).toBe("INVALID_TWO_FACTOR_COOKIE");
});

for (const origin of ["opaque", "classic"] as const) {
  test(`a challenge without a credential binding is refused (${origin} sign-in)`, async () => {
    const { browser: opaqueOwner, auth, db } = await fixture({ classic: true });
    const uri =
      origin === "opaque" ? await enableTotp(opaqueOwner) : (await classicOwner(auth)).uri;
    const browser = createTestClient(auth);
    if (origin === "opaque") await pendingSignIn(browser);
    else await startClassicSignIn(browser);
    const sessions = db.session.length;
    const markers = db.verification.filter((row) =>
      String(row.identifier).startsWith("opaque:two-factor-pending:"),
    );
    expect(markers).toHaveLength(1);
    db.verification.splice(db.verification.indexOf(markers[0]!), 1);

    const refused = await browser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) });
    expect(refused.error).toMatchObject({ status: 409, code: "CREDENTIAL_CHANGED" });
    expect(db.session).toHaveLength(sessions);
    expect((await browser.authClient.getSession()).data).toBeNull();
  });
}

test("the password proof challenge consults the account rate limit", async () => {
  const flows: string[] = [];
  const { browser } = await fixture({
    accountRateLimit: ({ flow }) => {
      flows.push(flow);
      return false;
    },
  });
  const refused = await browser.authClient.opaque.createPasswordProof({ password: PASSWORD });
  expect(refused.error).toMatchObject({ status: 429, code: "TOO_MANY_ATTEMPTS" });
  expect(flows).toEqual(["password-proof"]);
});

test("a password change after the second factor invalidates the credential-bound payload token", async () => {
  const { browser: owner, auth } = await fixture();
  const uri = await enableTotp(owner);
  await owner.authClient.signOut();
  const browser = createTestClient(auth);
  const pending = await pendingSignIn(browser);
  expect(
    (await browser.authClient.twoFactor.verifyTotp({ code: await totpCode(uri) })).error,
  ).toBeNull();
  await replacePassword("change-password", auth, browser);
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
  // Changing the password revoked every session and issued the caller a new one.
  const renewedCookie = [...browser.cookies].map(([name, value]) => `${name}=${value}`).join("; ");
  expect(renewedCookie).not.toBe(cookie);
  const staleComplete = await postJson(
    auth,
    OPAQUE_PATHS.passwordProofComplete,
    { stateId: staleChallenge.body!.stateId, loginFinalization: staleFinished.finishLoginRequest },
    { cookie: renewedCookie },
  );
  expect(staleComplete.body?.code).toBe("INVALID_PASSWORD");
});
