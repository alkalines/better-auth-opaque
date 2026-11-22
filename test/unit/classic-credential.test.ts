import { client as opaqueProtocol } from "@serenity-kit/opaque";
import { beforeAll, describe, expect, test } from "vitest";
import { opaque } from "../../src/index.ts";
import {
  type AuthUnderTest,
  CHEAP_STRETCHING,
  createMemoryDb,
  createTestAuth,
  createTestClient,
  expectNotSent,
  postJson,
  serverSetupForTests,
} from "./helpers.ts";

const CLASSIC_PASSWORD = "classic-password-123";
const OPAQUE_PASSWORD = "opaque-password-123";

let serverSetup: string;
beforeAll(async () => {
  serverSetup = await serverSetupForTests();
});

/**
 * Auth with `signIn.revealClassicCredential` and Better Auth's email/password enabled, plus a
 * classic-only user, an OPAQUE user that kept a classic row, and a user whose classic row has no
 * password (social-only).
 */
async function setUp(accountRateLimit?: (input: { key: string }) => boolean) {
  const db = createMemoryDb();
  const auth = createTestAuth({
    db,
    opaque: {
      serverSetup,
      keyStretching: CHEAP_STRETCHING,
      signIn: { revealClassicCredential: true },
      accountRateLimit,
    },
    options: { emailAndPassword: { enabled: true } },
  });

  const classic = await postJson(auth, "/sign-up/email", {
    email: "classic@example.com",
    password: CLASSIC_PASSWORD,
    name: "Classic",
  });
  const passwordless = await postJson(auth, "/sign-up/email", {
    email: "passwordless@example.com",
    password: CLASSIC_PASSWORD,
    name: "Passwordless",
  });
  const migrated = await createTestClient(auth).authClient.signUp.opaque({
    email: "migrated@example.com",
    password: OPAQUE_PASSWORD,
    name: "Migrated",
  });
  if (classic.status !== 200 || passwordless.status !== 200 || migrated.error) {
    throw new Error("classic-credential fixture setup failed");
  }

  const passwordlessId = db.user.find((user) => user.email === "passwordless@example.com")?.id;
  for (const account of db.account) {
    if (account.userId === passwordlessId) {
      account.password = null;
    }
  }
  // A classic row left behind by an interrupted removal, next to the OPAQUE credential.
  const migratedId = migrated.data.user.id;
  db.account.push({
    id: "leftover-classic",
    accountId: migratedId,
    providerId: "credential",
    userId: migratedId,
    password: "leftover-hash",
    createdAt: new Date(),
    updatedAt: new Date(),
  });

  return { auth, db };
}

function challenge(auth: AuthUnderTest, email: string) {
  const login = opaqueProtocol.startLogin({ password: "any-password" });
  return postJson(auth, "/sign-in/opaque/challenge", {
    email,
    loginRequest: login.startLoginRequest,
  });
}

describe("signIn.revealClassicCredential", () => {
  test("a classic-only user gets CLASSIC_CREDENTIAL without a sign-in state", async () => {
    const keys: string[] = [];
    const { auth, db } = await setUp(({ key }) => {
      keys.push(key);
      return true;
    });
    const statesBefore = db.verification.length;

    const response = await challenge(auth, "Classic@Example.com");

    expect(response.status).toBe(409);
    expect(response.body?.code).toBe("CLASSIC_CREDENTIAL");
    expect(db.verification.length).toBe(statesBefore);
    expect(keys).toHaveLength(1);
  });

  test("the client returns the code and sends no password", async () => {
    const { auth } = await setUp();
    const browser = createTestClient(auth);

    const result = await browser.authClient.signIn.opaque({
      email: "classic@example.com",
      password: CLASSIC_PASSWORD,
    });

    expect(result.error).toMatchObject({ status: 409, code: "CLASSIC_CREDENTIAL" });
    expectNotSent([browser], [CLASSIC_PASSWORD]);
  });

  test("unknown emails and passwordless classic rows still get the fake login", async () => {
    const { auth } = await setUp();

    for (const email of ["unknown@example.com", "passwordless@example.com"]) {
      expect((await challenge(auth, email)).status).toBe(200);
      const result = await createTestClient(auth).authClient.signIn.opaque({
        email,
        password: CLASSIC_PASSWORD,
      });
      expect(result.error).toMatchObject({ status: 401, code: "INVALID_CREDENTIALS" });
    }
  });

  test("an OPAQUE user with a leftover classic row signs in normally", async () => {
    const { auth } = await setUp();

    const result = await createTestClient(auth).authClient.signIn.opaque({
      email: "migrated@example.com",
      password: OPAQUE_PASSWORD,
    });

    expect(result.error).toBeNull();
    expect(result.data).toMatchObject({ user: { email: "migrated@example.com" } });
  });

  test("a refused account rate limit answers before the classic check", async () => {
    const { auth, db } = await setUp(() => false);
    const statesBefore = db.verification.length;

    const classic = await challenge(auth, "classic@example.com");
    const unknown = await challenge(auth, "unknown@example.com");

    expect(classic.status).toBe(429);
    expect(classic.body?.code).toBe("TOO_MANY_ATTEMPTS");
    expect(unknown).toEqual(classic);
    expect(db.verification.length).toBe(statesBefore);
  });

  test("an invalid option value throws at construction", () => {
    // Deliberately ill-typed: the options schema is the runtime guard for untyped callers.
    const notBoolean = { revealClassicCredential: "yes" } as unknown as {
      revealClassicCredential: boolean;
    };
    const unknownKey = { reveal: true } as unknown as { revealClassicCredential: boolean };

    expect(() => opaque({ serverSetup, signIn: notBoolean })).toThrow(/signIn/);
    expect(() => opaque({ serverSetup, signIn: unknownKey })).toThrow(/signIn/);
  });
});
