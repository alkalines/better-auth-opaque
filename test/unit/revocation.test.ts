import { client as opaqueProtocol } from "@serenity-kit/opaque";
import type { BetterAuthOptions, SecondaryStorage } from "better-auth";
import { beforeAll, describe, expect, test } from "vitest";
import { OPAQUE_PATHS } from "../../src/contract.ts";
import { sha256 } from "../../src/server/crypto.ts";
import {
  CHEAP_STRETCHING,
  createMemoryDb,
  createPayloadApp,
  createTestAuth,
  createTestClient,
  postJson,
  serverSetupForTests,
  type TestClient,
} from "./helpers.ts";

const EMAIL = "revocation@example.com";
const OLD = "old-password-1";
const NEW = "new-password-2";

let serverSetup: string;
beforeAll(async () => {
  serverSetup = await serverSetupForTests();
});

/** A Map-backed `SecondaryStorage` that, like real stores, only drops keys when told to. */
function createSecondaryStorage(): SecondaryStorage & { keys: () => string[] } {
  const entries = new Map<string, string>();
  return {
    keys: () => [...entries.keys()],
    get: (key) => entries.get(key) ?? null,
    set: (key, value) => {
      entries.set(key, value);
    },
    delete: (key) => {
      entries.delete(key);
    },
    getAndDelete: (key) => {
      const value = entries.get(key) ?? null;
      entries.delete(key);
      return value;
    },
    increment: (key) => {
      const next = Number(entries.get(key) ?? 0) + 1;
      entries.set(key, String(next));
      return next;
    },
  };
}

const passwordReset = { url: (token: string) => `http://localhost:3000/reset?token=${token}` };

async function setUp(options?: Partial<BetterAuthOptions>) {
  const db = createMemoryDb();
  const app = createPayloadApp();
  const auth = createTestAuth({
    db,
    options,
    opaque: { serverSetup, keyStretching: CHEAP_STRETCHING, hooks: app.hooks, passwordReset },
  });
  const owner = createTestClient(auth);
  const signUp = await owner.authClient.signUp.opaque({ email: EMAIL, password: OLD, name: "Rev" });
  expect(signUp.error).toBeNull();
  const userId = signUp.data!.user.id as string;
  const ctx = await auth.$context;
  const sessionRows = () => db.session.filter((row) => row.userId === userId);
  const issue = async (revokePrevious?: boolean) => {
    const { url } = await auth.api.createPasswordResetToken({
      body: { email: EMAIL, revokePrevious },
    });
    return new URL(url).searchParams.get("token")!;
  };
  const verify = async (token: string) =>
    (await createTestClient(auth).authClient.opaque.verifyResetToken({ token })).error?.code ??
    null;
  return {
    db,
    app,
    auth,
    owner,
    userId,
    ctx,
    sessionRows,
    issue,
    verify,
    ownerToken: signUp.data!.token as string,
  };
}

async function changePassword(owner: TestClient) {
  return owner.authClient.opaque.changePassword({ currentPassword: OLD, newPassword: NEW });
}

describe("password change revokes every session", () => {
  test(
    "sessions beyond the adapter's first page end and the caller continues on a new session",
    { timeout: 60_000 },
    async () => {
      const { auth, owner, userId, ctx, sessionRows, ownerToken } = await setUp();
      for (let i = 0; i < 120; i++) {
        await ctx.internalAdapter.createSession(userId);
      }
      const attacker = createTestClient(auth);
      expect(
        (await attacker.authClient.signIn.opaque({ email: EMAIL, password: OLD })).error,
      ).toBeNull();
      expect(sessionRows()).toHaveLength(122);

      expect((await changePassword(owner)).error).toBeNull();

      expect((await attacker.authClient.getSession()).data).toBeNull();
      expect((await owner.authClient.getSession()).data?.user.id).toBe(userId);
      expect(sessionRows()).toHaveLength(1);
      expect(sessionRows()[0]?.token).not.toBe(ownerToken);
    },
  );

  test("the replaced session token no longer authenticates", async () => {
    const { auth, owner, sessionRows, ownerToken } = await setUp();
    expect((await changePassword(owner)).error).toBeNull();

    expect(sessionRows().map((row) => row.token)).not.toContain(ownerToken);
    const replay = await auth.handler(
      new Request("http://localhost:3000/api/auth/get-session", {
        headers: { authorization: `Bearer ${ownerToken}` },
      }),
    );
    expect(await replay.json()).toBeNull();
  });

  test.each([false, true])(
    "secondary storage (storeSessionInDatabase: %s) is revoked exhaustively",
    async (storeSessionInDatabase) => {
      const storage = createSecondaryStorage();
      const { auth, owner, userId, ctx } = await setUp({
        secondaryStorage: storage,
        session: { storeSessionInDatabase },
      });
      for (let i = 0; i < 5; i++) {
        await ctx.internalAdapter.createSession(userId);
      }
      const attacker = createTestClient(auth);
      expect(
        (await attacker.authClient.signIn.opaque({ email: EMAIL, password: OLD })).error,
      ).toBeNull();
      const tokensBefore = (await ctx.internalAdapter.listSessions(userId)).map((s) => s.token);
      expect(tokensBefore.length).toBeGreaterThanOrEqual(7);

      expect((await changePassword(owner)).error).toBeNull();

      expect((await attacker.authClient.getSession()).data).toBeNull();
      expect((await owner.authClient.getSession()).data?.user.id).toBe(userId);
      for (const token of tokensBefore) {
        expect(storage.keys()).not.toContain(token);
      }
      expect(await ctx.internalAdapter.listSessions(userId)).toHaveLength(1);
    },
  );

  test("a remember-me opt-out survives the change", async () => {
    const { auth, owner, sessionRows } = await setUp();
    const shortLived = createTestClient(auth);
    expect(
      (
        await shortLived.authClient.signIn.opaque({
          email: EMAIL,
          password: OLD,
          rememberMe: false,
        })
      ).error,
    ).toBeNull();
    expect(
      (
        await shortLived.authClient.opaque.changePassword({
          currentPassword: OLD,
          newPassword: NEW,
        })
      ).error,
    ).toBeNull();

    expect(sessionRows()).toHaveLength(1);
    const lifetimeMs = new Date(sessionRows()[0]!.expiresAt as Date).getTime() - Date.now();
    expect(lifetimeMs).toBeLessThanOrEqual(24 * 60 * 60 * 1000);
    // The owner's own session was revoked too.
    expect((await owner.authClient.getSession()).data).toBeNull();
  });

  test("a failing activatePayload after the switch still revokes all sessions, caller included", async () => {
    const { app, auth, owner, sessionRows } = await setUp();
    const attacker = createTestClient(auth);
    expect(
      (await attacker.authClient.signIn.opaque({ email: EMAIL, password: OLD })).error,
    ).toBeNull();

    app.faults.add("activatePayload");
    const changed = await changePassword(owner);
    app.faults.clear();

    expect(changed.error).not.toBeNull();
    expect(sessionRows()).toHaveLength(0);
    expect((await attacker.authClient.getSession()).data).toBeNull();
    expect((await owner.authClient.getSession()).data).toBeNull();
    const signIn = await createTestClient(auth).authClient.signIn.opaque({
      email: EMAIL,
      password: NEW,
    });
    expect(signIn.error).toBeNull();
  });
});

describe("reset tokens are bound to the credential and revocable", () => {
  test("using one link invalidates the older link", async () => {
    const { auth, issue, verify } = await setUp();
    const older = await issue();
    const used = await issue();
    expect(await verify(older)).toBeNull();

    const reset = await createTestClient(auth).authClient.opaque.resetPassword({
      token: used,
      newPassword: NEW,
    });
    expect(reset.error).toBeNull();

    expect(await verify(older)).toBe("INVALID_RESET_TOKEN");
    expect(
      (
        await createTestClient(auth).authClient.opaque.resetPassword({
          token: older,
          newPassword: "attacker-password",
        })
      ).error?.code,
    ).toBe("INVALID_RESET_TOKEN");
  });

  test("a password change invalidates outstanding links", async () => {
    const { owner, issue, verify } = await setUp();
    const token = await issue();
    expect((await changePassword(owner)).error).toBeNull();
    expect(await verify(token)).toBe("INVALID_RESET_TOKEN");

    const fresh = await issue();
    expect(await verify(fresh)).toBeNull();
  });

  test("revokePrevious invalidates older links and the new one works", async () => {
    const { issue, verify } = await setUp();
    const first = await issue();
    const second = await issue();
    const replacement = await issue(true);

    expect(await verify(first)).toBe("INVALID_RESET_TOKEN");
    expect(await verify(second)).toBe("INVALID_RESET_TOKEN");
    expect(await verify(replacement)).toBeNull();
  });

  test("revokePasswordResetTokens invalidates every link and later links work", async () => {
    const { auth, issue, verify } = await setUp();
    const first = await issue();
    const second = await issue();

    await expect(auth.api.revokePasswordResetTokens({ body: { email: EMAIL } })).resolves.toEqual({
      status: true,
    });
    expect(await verify(first)).toBe("INVALID_RESET_TOKEN");
    expect(await verify(second)).toBe("INVALID_RESET_TOKEN");

    expect(await verify(await issue())).toBeNull();
  });

  test("revoking one user's links leaves other users' links alone", async () => {
    const { auth, issue, verify } = await setUp();
    const other = createTestClient(auth);
    expect(
      (
        await other.authClient.signUp.opaque({
          email: "other@example.com",
          password: OLD,
          name: "Other",
        })
      ).error,
    ).toBeNull();
    const { url } = await auth.api.createPasswordResetToken({
      body: { email: "other@example.com" },
    });
    const otherToken = new URL(url).searchParams.get("token")!;
    const ownToken = await issue();

    await auth.api.revokePasswordResetTokens({ body: { email: EMAIL } });

    expect(await verify(ownToken)).toBe("INVALID_RESET_TOKEN");
    expect(await verify(otherToken)).toBeNull();
  });

  test("revokePasswordResetTokens fails with USER_NOT_FOUND for unknown emails", async () => {
    const { auth } = await setUp();
    await expect(
      auth.api.revokePasswordResetTokens({ body: { email: "nobody@example.com" } }),
    ).rejects.toMatchObject({ body: { code: "USER_NOT_FOUND" } });
  });

  test("tokens without the version and epoch binding (0.1.x) fail closed", async () => {
    const { ctx, userId, verify } = await setUp();
    const token = "legacy-token-without-binding";
    await ctx.internalAdapter.createVerificationValue({
      identifier: `opaque:reset-token:${await sha256(token)}`,
      value: JSON.stringify({ userId }),
      expiresAt: new Date(Date.now() + 60_000),
    });
    expect(await verify(token)).toBe("INVALID_RESET_TOKEN");
  });

  test("the epoch row outlives the newest link", async () => {
    const { auth, db, userId } = await setUp();
    await auth.api.createPasswordResetToken({ body: { email: EMAIL } });
    const { expiresAt } = await auth.api.createPasswordResetToken({ body: { email: EMAIL } });

    const epochRows = db.verification.filter(
      (row) => row.identifier === `opaque:reset-epoch:${userId}`,
    );
    expect(epochRows).toHaveLength(1);
    expect(new Date(epochRows[0]!.expiresAt as Date).getTime()).toBeGreaterThanOrEqual(
      expiresAt.getTime(),
    );
  });

  test("the revoking endpoints are not reachable over HTTP", async () => {
    const { auth } = await setUp();
    for (const path of ["/create-password-reset-token", "/revoke-password-reset-tokens"]) {
      const response = await postJson(auth, path, { email: EMAIL, revokePrevious: true });
      expect({ path, status: response.status }).toEqual({ path, status: 404 });
    }
  });
});

describe("reset endpoints carry the first-login CSRF check", () => {
  const evil = { origin: "https://evil.example" };

  test("cookie-less cross-site requests are rejected; the trusted origin still resets", async () => {
    const { auth, issue } = await setUp({ advanced: { disableOriginCheck: false } });
    const token = await issue();
    const registrationRequest = opaqueProtocol.startRegistration({
      password: "x",
    }).registrationRequest;
    const requests: [string, Record<string, unknown>][] = [
      [OPAQUE_PATHS.resetVerify, { token }],
      [OPAQUE_PATHS.resetChallenge, { token, registrationRequest }],
      [OPAQUE_PATHS.resetComplete, { stateId: "x", registrationRecord: "AAAA" }],
    ];
    for (const [path, body] of requests) {
      const response = await postJson(auth, path, body, evil);
      expect({ path, status: response.status }).toEqual({ path, status: 403 });
    }

    const reset = await createTestClient(auth).authClient.opaque.resetPassword({
      token,
      newPassword: NEW,
    });
    expect(reset.error).toBeNull();
  });
});
