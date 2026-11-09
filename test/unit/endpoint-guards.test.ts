import { client as opaqueProtocol } from "@serenity-kit/opaque";
import { betterAuth, type BetterAuthOptions } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { beforeAll, describe, expect, test } from "vitest";
import { opaque } from "../../src/server/index.ts";
import {
  BASE_URL,
  CHEAP_STRETCHING,
  createMemoryDb,
  createTestAuth,
  createTestClient,
  postJson,
  SECRET,
  serverSetupForTests,
} from "./helpers.ts";

let serverSetup: string;
beforeAll(async () => {
  serverSetup = await serverSetupForTests();
});

const loginRequest = () => opaqueProtocol.startLogin({ password: "x" }).startLoginRequest;
const registrationRequest = () =>
  opaqueProtocol.startRegistration({ password: "x" }).registrationRequest;

function authWithOriginCheck() {
  return createTestAuth({
    db: createMemoryDb(),
    opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
    options: { advanced: { disableOriginCheck: false } },
  });
}

describe("first-login CSRF protection", () => {
  const evil = { origin: "https://evil.example" };

  test("cookie-less cross-site requests are rejected like native sign-in and sign-up", async () => {
    const auth = authWithOriginCheck();
    const requests: [string, unknown][] = [
      ["/sign-in/opaque/challenge", { email: "a@example.com", loginRequest: loginRequest() }],
      ["/sign-in/opaque/complete", { stateId: "x", loginFinalization: "AA" }],
      [
        "/sign-up/opaque/challenge",
        { email: "a@example.com", registrationRequest: registrationRequest() },
      ],
      ["/sign-up/opaque/complete", { stateId: "x", registrationRecord: "AA", name: "A" }],
    ];
    for (const [path, body] of requests) {
      const response = await postJson(auth, path, body, evil);
      expect({ path, status: response.status }).toEqual({ path, status: 403 });
    }
  });

  test("the trusted origin still signs up and signs in", async () => {
    const auth = authWithOriginCheck();
    const browser = createTestClient(auth);
    const signUp = await browser.authClient.signUp.opaque({
      email: "csrf@example.com",
      password: "pw-csrf",
      name: "C",
    });
    expect(signUp.error).toBeNull();
    const signIn = await createTestClient(auth).authClient.signIn.opaque({
      email: "csrf@example.com",
      password: "pw-csrf",
    });
    expect(signIn.error).toBeNull();
  });
});

describe("sign-up switch", () => {
  test("emailAndPassword.disableSignUp closes OPAQUE sign-up at the challenge", async () => {
    const db = createMemoryDb();
    const auth = createTestAuth({
      db,
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING },
      options: { emailAndPassword: { enabled: false, disableSignUp: true } },
    });
    const browser = createTestClient(auth);
    const result = await browser.authClient.signUp.opaque({
      email: "closed@example.com",
      password: "pw",
      name: "C",
    });
    expect(result.error?.code).toBe("SIGN_UP_DISABLED");
    expect(result.error?.status).toBe(400);
    expect(db.user).toHaveLength(0);
    expect(browser.requests.some((request) => request.url.endsWith("/complete"))).toBe(false);
  });

  test("the plugin option overrides the Better Auth flag in both directions", async () => {
    const open = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING, disableSignUp: false },
      options: { emailAndPassword: { enabled: true, disableSignUp: true } },
    });
    const opened = await createTestClient(open).authClient.signUp.opaque({
      email: "open@example.com",
      password: "pw",
      name: "O",
    });
    expect(opened.error).toBeNull();

    const closed = createTestAuth({
      db: createMemoryDb(),
      opaque: { serverSetup, keyStretching: CHEAP_STRETCHING, disableSignUp: true },
    });
    const refused = await createTestClient(closed).authClient.signUp.opaque({
      email: "closed@example.com",
      password: "pw",
      name: "C",
    });
    expect(refused.error?.code).toBe("SIGN_UP_DISABLED");
  });

  test("a challenge issued before sign-up was closed cannot complete", async () => {
    const db = createMemoryDb();
    const options = { serverSetup, keyStretching: CHEAP_STRETCHING };
    const before = createTestAuth({ db, opaque: options });
    const registration = opaqueProtocol.startRegistration({ password: "pw-late" });
    const challenge = await postJson(before, "/sign-up/opaque/challenge", {
      email: "late@example.com",
      registrationRequest: registration.registrationRequest,
    });
    expect(challenge.status).toBe(200);
    const { registrationRecord } = opaqueProtocol.finishRegistration({
      password: "pw-late",
      registrationResponse: challenge.body!.registrationResponse as string,
      clientRegistrationState: registration.clientRegistrationState,
      keyStretching: CHEAP_STRETCHING,
    });

    const after = createTestAuth({ db, opaque: { ...options, disableSignUp: true } });
    const complete = await postJson(after, "/sign-up/opaque/complete", {
      stateId: challenge.body!.stateId,
      registrationRecord,
      name: "L",
    });
    expect(complete.status).toBe(400);
    expect(complete.body?.code).toBe("SIGN_UP_DISABLED");
    expect(db.user).toHaveLength(0);
  });
});

describe("sign-in challenge database work", () => {
  for (const generateId of [undefined, "uuid", "serial"] as const) {
    test(`known, account-less and unknown emails run the same adapter reads (generateId: ${generateId ?? "default"})`, async () => {
      const db = createMemoryDb();
      let reads: string[] = [];
      const factory = memoryAdapter(db);
      type Read = { model: string; where?: { field: string }[] };
      const record = (method: string, args: Read) =>
        reads.push(`${method} ${args.model} ${(args.where ?? []).map((w) => w.field).join(",")}`);
      const counting = ((options: BetterAuthOptions) => {
        const adapter = factory(options);
        return {
          ...adapter,
          findOne: (args: Read) => {
            record("findOne", args);
            return adapter.findOne(args as Parameters<typeof adapter.findOne>[0]);
          },
          findMany: (args: Read) => {
            record("findMany", args);
            return adapter.findMany(args as Parameters<typeof adapter.findMany>[0]);
          },
        };
      }) as typeof factory;
      const auth = betterAuth({
        baseURL: BASE_URL,
        secret: SECRET,
        database: counting,
        rateLimit: { enabled: false },
        logger: { disabled: true },
        emailAndPassword: { enabled: true },
        advanced: generateId ? { database: { generateId } } : undefined,
        plugins: [opaque({ serverSetup, keyStretching: CHEAP_STRETCHING })],
      });
      expect(
        (
          await createTestClient(auth).authClient.signUp.opaque({
            email: "known@example.com",
            password: "pw-known",
            name: "K",
          })
        ).error,
      ).toBeNull();
      expect(
        (
          await postJson(auth, "/sign-up/email", {
            email: "password-only@example.com",
            password: "password-only-1",
            name: "P",
          })
        ).status,
      ).toBe(200);

      const readsFor = async (email: string) => {
        reads = [];
        const response = await postJson(auth, "/sign-in/opaque/challenge", {
          email,
          loginRequest: loginRequest(),
        });
        expect(response.status).toBe(200);
        return reads.toSorted();
      };
      const known = await readsFor("known@example.com");
      expect(known).toEqual(["findMany account userId", "findOne user email"]);
      expect(await readsFor("password-only@example.com")).toEqual(known);
      expect(await readsFor("unknown@example.com")).toEqual(known);
    });
  }
});

describe("server option validation", () => {
  test("invalid plain-data options fail at construction", () => {
    const invalid = [
      { keyStretching: { "argon2id-custom": { iterations: 0, memory: 1024, parallelism: 1 } } },
      { keyStretching: { "argon2id-custom": { iterations: 1, memory: 2 ** 21, parallelism: 1 } } },
      { keyStretching: { "argon2id-custom": { iterations: 1, memory: 16, parallelism: 4 } } },
      { keyStretching: "argon2" },
      { passwordReset: { url: () => "", expiresIn: 0 } },
      { passwordReset: { url: () => "", expiresIn: 8 * 24 * 60 * 60 } },
      { passwordReset: { expiresIn: 60 } },
      { attach: { freshSessionAge: -1 } },
      { serverIdentifier: "" },
    ];
    for (const options of invalid) {
      expect.soft(() => opaque({ serverSetup, ...options } as never)).toThrow(/invalid options/);
    }
  });

  test("hooks accept explicitly undefined members but not other non-functions", () => {
    expect(() => opaque({ serverSetup, hooks: { loadPayload: undefined } } as never)).not.toThrow();
    expect(() => opaque({ serverSetup, hooks: { loadPayload: 1 } } as never)).toThrow(
      /invalid options/,
    );
    expect(() => opaque({ serverSetup, absentUserId: "" } as never)).toThrow(/invalid options/);
  });
});

describe("per-account rate limit", () => {
  test("sign-in consults the hook with one key per email, also for unknown emails", async () => {
    const calls: { key: string; flow: string }[] = [];
    let allow = true;
    const auth = createTestAuth({
      db: createMemoryDb(),
      opaque: {
        serverSetup,
        keyStretching: CHEAP_STRETCHING,
        accountRateLimit: (input) => {
          calls.push(input);
          return allow;
        },
      },
    });
    expect(
      (
        await createTestClient(auth).authClient.signUp.opaque({
          email: "known@example.com",
          password: "pw-known",
          name: "K",
        })
      ).error,
    ).toBeNull();

    const challenge = (email: string) =>
      postJson(auth, "/sign-in/opaque/challenge", { email, loginRequest: loginRequest() });
    expect((await challenge("known@example.com")).status).toBe(200);
    expect((await challenge("KNOWN@example.com")).status).toBe(200);
    expect((await challenge("unknown@example.com")).status).toBe(200);
    expect(calls.map((call) => call.flow)).toEqual(["sign-in", "sign-in", "sign-in"]);
    expect(calls[1]?.key).toBe(calls[0]?.key);
    expect(calls[2]?.key).not.toBe(calls[0]?.key);
    expect(calls[0]?.key).not.toContain("known");

    allow = false;
    const refusedKnown = await challenge("known@example.com");
    const refusedUnknown = await challenge("unknown@example.com");
    expect(refusedKnown.status).toBe(429);
    expect(refusedKnown.body?.code).toBe("TOO_MANY_ATTEMPTS");
    expect(refusedUnknown).toEqual(refusedKnown);
  });
});

describe("registration record validation", () => {
  test("sign-up rejects a record serenity cannot load and creates no user", async () => {
    const db = createMemoryDb();
    const auth = createTestAuth({ db, opaque: { serverSetup, keyStretching: CHEAP_STRETCHING } });
    const challenge = await postJson(auth, "/sign-up/opaque/challenge", {
      email: "garbage@example.com",
      registrationRequest: registrationRequest(),
    });
    expect(challenge.status).toBe(200);
    const complete = await postJson(auth, "/sign-up/opaque/complete", {
      stateId: challenge.body!.stateId,
      registrationRecord: "A".repeat(256),
      name: "G",
    });
    expect(complete.status).toBe(400);
    expect(complete.body?.code).toBe("INVALID_OPAQUE_MESSAGE");
    expect(db.user).toHaveLength(0);
    expect(db.account).toHaveLength(0);
  });
});
