import { beforeAll, describe, expect, test } from "vitest";
import type { OpaqueHooks } from "../../src/contract.ts";
import {
  CHEAP_STRETCHING,
  createMemoryDb,
  createPayloadApp,
  createTestAuth,
  createTestClient,
  serverSetupForTests,
} from "./helpers.ts";

let serverSetup: string;

beforeAll(async () => {
  serverSetup = await serverSetupForTests();
});

/** A promise plus its resolver, to hold a hook open until the test releases it. */
function gate() {
  let open!: () => void;
  const opened = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { open, opened };
}

async function setUpUser() {
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
  const email = "race@example.com";
  const owner = createTestClient(auth);
  const signUp = await owner.authClient.signUp.opaque({
    email,
    password: "old-password",
    name: "Race",
    payload: { tag: "old" },
  });
  if (signUp.error) {
    throw new Error(`fixture sign-up failed: ${signUp.error.code}`);
  }
  const { url } = await auth.api.createPasswordResetToken({ body: { email } });
  const token = new URL(url).searchParams.get("token")!;
  return { app, db, auth, email, owner, token };
}

describe("concurrent credential replacement", () => {
  test("of two flows proven against the same version exactly one switches", async () => {
    const { app, auth, email, owner, token } = await setUpUser();

    // Hold both completes inside commitPayload until both got there, so both have passed every
    // check that happens before the switch.
    let arrivals = 0;
    const bothCommitting = gate();
    app.pauses.set("commitPayload", async () => {
      arrivals += 1;
      if (arrivals === 2) {
        bothCommitting.open();
      }
      await bothCommitting.opened;
    });

    const exportKeys = new Map<string, string>();
    const payloadFor = (tag: string) => async (exportKey: string) => {
      exportKeys.set(tag, exportKey);
      return { tag };
    };
    const [changed, reset] = await Promise.all([
      owner.authClient.opaque.changePassword({
        currentPassword: "old-password",
        newPassword: "changed-password",
        payload: payloadFor("changed"),
      }),
      createTestClient(auth).authClient.opaque.resetPassword({
        token,
        newPassword: "reset-password",
        payload: payloadFor("reset"),
      }),
    ]);
    app.pauses.clear();

    const outcomes = [
      { tag: "changed", password: "changed-password", error: changed.error?.code ?? null },
      { tag: "reset", password: "reset-password", error: reset.error?.code ?? null },
    ];
    const winners = outcomes.filter((outcome) => outcome.error === null);
    const losers = outcomes.filter((outcome) => outcome.error !== null);
    expect(winners).toHaveLength(1);
    expect(losers.map((loser) => loser.error)).toEqual(["CREDENTIAL_CHANGED"]);
    const winner = winners[0]!;
    const loser = losers[0]!;

    const browser = createTestClient(auth);
    const winning = await browser.authClient.signIn.opaque({ email, password: winner.password });
    expect(winning.error).toBeNull();
    expect(winning.data?.payload).toEqual({ tag: winner.tag });
    expect(winning.data?.exportKey).toBe(exportKeys.get(winner.tag));

    for (const password of [loser.password, "old-password"]) {
      const failed = await browser.authClient.signIn.opaque({ email, password });
      expect(failed.error?.code).toBe("INVALID_CREDENTIALS");
    }
  });

  test("a sign-in proven with the old password does not survive a concurrent reset", async () => {
    const { app, db, auth, email, token } = await setUpUser();

    // The sign-in has verified the old password and is loading its payload when the reset
    // switches the credential and revokes all sessions.
    const signInLoading = gate();
    const resetDone = gate();
    app.pauses.set("loadPayload", async () => {
      signInLoading.open();
      await resetDone.opened;
    });

    const attacker = createTestClient(auth);
    const signIn = attacker.authClient.signIn.opaque({ email, password: "old-password" });
    await signInLoading.opened;

    const reset = await createTestClient(auth).authClient.opaque.resetPassword({
      token,
      newPassword: "reset-password",
    });
    expect(reset.error).toBeNull();
    resetDone.open();

    const result = await signIn;
    expect(result.data).toBeNull();
    expect(result.error?.code).toBe("INVALID_CREDENTIALS");
    expect(db.session).toHaveLength(0);
    expect((await attacker.authClient.getSession()).data).toBeNull();
  });

  test("a password change whose replacement session loses to a reset leaves no session", async () => {
    const app = createPayloadApp();
    const db = createMemoryDb();
    // Hold the change's activatePayload (after its switch) open once; the reset's is not held.
    const changeSwitched = gate();
    const resetDone = gate();
    let armed = false;
    const hooks: OpaqueHooks = {
      ...app.hooks,
      activatePayload: async (input, ctx) => {
        if (armed) {
          armed = false;
          changeSwitched.open();
          await resetDone.opened;
        }
        await app.hooks.activatePayload?.(input, ctx);
      },
    };
    const auth = createTestAuth({
      db,
      opaque: {
        serverSetup,
        keyStretching: CHEAP_STRETCHING,
        hooks,
        passwordReset: { url: (token) => `http://localhost:3000/reset?token=${token}` },
      },
    });
    const email = "race@example.com";
    const owner = createTestClient(auth);
    const signUp = await owner.authClient.signUp.opaque({
      email,
      password: "old-password",
      name: "Race",
      payload: { tag: "old" },
    });
    expect(signUp.error).toBeNull();
    armed = true;

    const changing = owner.authClient.opaque.changePassword({
      currentPassword: "old-password",
      newPassword: "changed-password",
    });
    await changeSwitched.opened;

    const { url } = await auth.api.createPasswordResetToken({ body: { email } });
    const reset = await createTestClient(auth).authClient.opaque.resetPassword({
      token: new URL(url).searchParams.get("token")!,
      newPassword: "reset-password",
    });
    expect(reset.error).toBeNull();
    resetDone.open();

    const changed = await changing;
    expect(changed.error).toMatchObject({ status: 409, code: "CREDENTIAL_CHANGED" });
    expect(db.session).toHaveLength(0);
    expect((await owner.authClient.getSession()).data).toBeNull();

    const browser = createTestClient(auth);
    expect(
      (await browser.authClient.signIn.opaque({ email, password: "reset-password" })).error,
    ).toBeNull();
    expect(
      (await browser.authClient.signIn.opaque({ email, password: "changed-password" })).error?.code,
    ).toBe("INVALID_CREDENTIALS");
  });
});
