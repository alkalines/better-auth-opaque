import { beforeAll, describe, expect, test } from "vitest";
import {
  CHEAP_STRETCHING,
  createMemoryDb,
  createPayloadApp,
  createTestAuth,
  createTestClient,
  type FaultPoint,
  type MemoryDb,
  serverSetupForTests,
} from "./helpers.ts";

let serverSetup: string;

beforeAll(async () => {
  serverSetup = await serverSetupForTests();
});

function setUp(transactions: boolean) {
  const app = createPayloadApp();
  const db = createMemoryDb();
  const auth = createTestAuth({
    db,
    transactions,
    opaque: {
      serverSetup,
      keyStretching: CHEAP_STRETCHING,
      hooks: app.hooks,
      passwordReset: { url: (token) => `http://localhost:3000/reset?token=${token}` },
    },
    faults: app.faults,
    options: { databaseHooks: app.databaseHooks },
  });
  return { app, db, auth };
}

type Credential = { password: string; tag: string; exportKey?: string };

type SignInObservation =
  | { tag: string; error: string | undefined }
  | { tag: string; payload: unknown; exportKey: string };

/** Signs in with each credential from a fresh browser and records what came back. */
async function observeSignIns(
  auth: ReturnType<typeof createTestAuth>,
  email: string,
  credentials: Credential[],
): Promise<SignInObservation[]> {
  const observations: SignInObservation[] = [];
  for (const credential of credentials) {
    const result = await createTestClient(auth).authClient.signIn.opaque({
      email,
      password: credential.password,
    });
    observations.push(
      result.error
        ? { tag: credential.tag, error: result.error.code }
        : { tag: credential.tag, payload: result.data.payload, exportKey: result.data.exportKey },
    );
  }
  return observations;
}

/**
 * Exactly one credential works, and it returns the payload and export key registered with that
 * same credential; the others fail like any wrong password.
 */
function onlyWorking(credentials: Credential[], workingTag: string): SignInObservation[] {
  return credentials.map((credential) =>
    credential.tag === workingTag
      ? { tag: credential.tag, payload: { tag: credential.tag }, exportKey: credential.exportKey! }
      : { tag: credential.tag, error: "INVALID_CREDENTIALS" },
  );
}

function opaqueAccounts(db: MemoryDb) {
  return db.account.filter((account) => account.providerId === "opaque");
}

/** Failures before the account switch keep the old credential; after it, the new one. */
function expectedWorkingTag(fault: FaultPoint): string {
  const afterSwitch: FaultPoint[] = ["account.update.after-commit", "activatePayload"];
  return afterSwitch.includes(fault) ? "new" : "old";
}

/** A second browser signed in with the old password before the failing flow. */
async function signInElsewhere(
  auth: ReturnType<typeof createTestAuth>,
  email: string,
  old: Credential,
) {
  const phone = createTestClient(auth);
  const signIn = await phone.authClient.signIn.opaque({ email, password: old.password });
  if (signIn.error) {
    throw new Error(`fixture sign-in failed: ${signIn.error.code}`);
  }
  return phone;
}

async function registerUser(auth: ReturnType<typeof createTestAuth>, email: string) {
  const old: Credential = { password: "old-password", tag: "old" };
  const browser = createTestClient(auth);
  const signUp = await browser.authClient.signUp.opaque({
    email,
    password: old.password,
    name: "Fault",
    payload: async (exportKey: string) => {
      old.exportKey = exportKey;
      return { tag: old.tag };
    },
  });
  if (signUp.error) {
    throw new Error(`fixture sign-up failed: ${signUp.error.code}`);
  }
  return { browser, old };
}

describe.each([
  { mode: "with transactions", transactions: true },
  { mode: "without transactions (compensation only)", transactions: false },
])("injected failures $mode", ({ transactions }) => {
  const signUpFaults: FaultPoint[] = [
    "validatePayload",
    "user.create",
    "commitPayload",
    "account.create",
    "account.create.rejected",
    "activatePayload",
    "session.create",
  ];

  test.each(signUpFaults)("sign-up failing at %s leaves nothing behind", async (fault) => {
    const { app, db, auth } = setUp(transactions);
    const email = "signup-fault@example.com";

    app.faults.add(fault);
    const failed = await createTestClient(auth).authClient.signUp.opaque({
      email,
      password: "first-password",
      name: "Fault",
      payload: { tag: "first" },
    });
    expect(failed.error).not.toBeNull();
    expect(failed.data).toBeNull();
    app.faults.clear();

    expect(db.user.filter((user) => user.email === email)).toHaveLength(0);
    expect(opaqueAccounts(db)).toHaveLength(0);
    expect(db.session).toHaveLength(0);

    const retry: Credential = { password: "second-password", tag: "second" };
    const signUp = await createTestClient(auth).authClient.signUp.opaque({
      email,
      password: retry.password,
      name: "Fault",
      payload: async (exportKey: string) => {
        retry.exportKey = exportKey;
        return { tag: retry.tag };
      },
    });
    expect(signUp.error).toBeNull();
    expect(await observeSignIns(auth, email, [retry])).toEqual(onlyWorking([retry], "second"));
  });

  const credentialFaults: FaultPoint[] = [
    "validatePayload",
    "commitPayload",
    "account.update",
    "account.update.after-commit",
    "activatePayload",
  ];

  test.each(credentialFaults)(
    "password change failing at %s keeps a matching credential and payload",
    async (fault) => {
      const { app, auth } = setUp(transactions);
      const email = "change-fault@example.com";
      const { browser, old } = await registerUser(auth, email);
      const phone = await signInElsewhere(auth, email, old);
      const next: Credential = { password: "new-password", tag: "new" };

      app.faults.add(fault);
      const changed = await browser.authClient.opaque.changePassword({
        currentPassword: old.password,
        newPassword: next.password,
        payload: async (exportKey: string) => {
          next.exportKey = exportKey;
          return { tag: next.tag };
        },
      });
      expect(changed.error).not.toBeNull();
      expect(changed.data).toBeNull();
      app.faults.clear();

      // Sessions from the old password end exactly when the switch happened.
      const phoneSession = await phone.authClient.getSession();
      expect(phoneSession.data !== null).toBe(expectedWorkingTag(fault) === "old");
      expect(await observeSignIns(auth, email, [old, next])).toEqual(
        onlyWorking([old, next], expectedWorkingTag(fault)),
      );
    },
  );

  test.each(credentialFaults)(
    "password reset failing at %s keeps a matching credential and payload",
    async (fault) => {
      const { app, auth } = setUp(transactions);
      const email = "reset-fault@example.com";
      const { old } = await registerUser(auth, email);
      const phone = await signInElsewhere(auth, email, old);
      const next: Credential = { password: "new-password", tag: "new" };

      const { url } = await auth.api.createPasswordResetToken({ body: { email } });
      const token = new URL(url).searchParams.get("token")!;

      app.faults.add(fault);
      const reset = await createTestClient(auth).authClient.opaque.resetPassword({
        token,
        newPassword: next.password,
        payload: async (exportKey: string) => {
          next.exportKey = exportKey;
          return { tag: next.tag };
        },
      });
      expect(reset.error).not.toBeNull();
      expect(reset.data).toBeNull();
      app.faults.clear();

      // Sessions from the old password end exactly when the switch happened.
      const phoneSession = await phone.authClient.getSession();
      expect(phoneSession.data !== null).toBe(expectedWorkingTag(fault) === "old");
      expect(await observeSignIns(auth, email, [old, next])).toEqual(
        onlyWorking([old, next], expectedWorkingTag(fault)),
      );
    },
  );
});
