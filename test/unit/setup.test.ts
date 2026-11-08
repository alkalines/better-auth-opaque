import { describe, expect, test } from "vitest";
import { OPAQUE_PATHS } from "../../src/contract.ts";
import { opaque } from "../../src/server/index.ts";
import {
  CHEAP_STRETCHING,
  createMemoryDb,
  createTestAuth,
  createTestClient,
  postJson,
  serverSetupForTests,
} from "./helpers.ts";

describe("server setup", () => {
  test("constructing the plugin without a setup throws", () => {
    expect(() => opaque({ serverSetup: "" })).toThrow(/serverSetup/);
    expect(() => opaque({} as { serverSetup: string })).toThrow(/serverSetup/);
  });

  test("an invalid setup fails every flow closed", async () => {
    const db = createMemoryDb();
    const validSetup = await serverSetupForTests();

    // A session created while the setup was valid, to get past the session middleware.
    const valid = createTestAuth({
      db,
      opaque: { serverSetup: validSetup, keyStretching: CHEAP_STRETCHING },
    });
    const browser = createTestClient(valid);
    const signUp = await browser.authClient.signUp.opaque({
      email: "setup@example.com",
      password: "pw-setup",
      name: "Setup",
    });
    expect(signUp.error).toBeNull();
    const cookie = [...browser.cookies].map(([name, value]) => `${name}=${value}`).join("; ");

    // Same length and alphabet as a real setup, but not a valid one.
    const invalidSetup = "A".repeat(validSetup.length);
    const invalid = createTestAuth({
      db,
      opaque: {
        serverSetup: invalidSetup,
        keyStretching: CHEAP_STRETCHING,
        passwordReset: { url: (token) => `/reset?token=${token}` },
      },
    });

    const message = "AAAA";
    const bodies: Record<string, Record<string, unknown>> = {
      [OPAQUE_PATHS.signUpChallenge]: { email: "new@example.com", registrationRequest: message },
      [OPAQUE_PATHS.signUpComplete]: { stateId: "x", registrationRecord: message, name: "New" },
      [OPAQUE_PATHS.signInChallenge]: { email: "setup@example.com", loginRequest: message },
      [OPAQUE_PATHS.signInComplete]: { stateId: "x", loginFinalization: message },
      [OPAQUE_PATHS.signInPayload]: { payloadToken: "x" },
      [OPAQUE_PATHS.passwordProofChallenge]: { loginRequest: message },
      [OPAQUE_PATHS.passwordProofComplete]: { stateId: "x", loginFinalization: message },
      [OPAQUE_PATHS.changePasswordChallenge]: {
        loginRequest: message,
        registrationRequest: message,
      },
      [OPAQUE_PATHS.changePasswordComplete]: {
        stateId: "x",
        loginFinalization: message,
        registrationRecord: message,
      },
      [OPAQUE_PATHS.resetVerify]: { token: "x" },
      [OPAQUE_PATHS.resetChallenge]: { token: "x", registrationRequest: message },
      [OPAQUE_PATHS.resetComplete]: { stateId: "x", registrationRecord: message },
    };
    expect(Object.keys(bodies).toSorted()).toEqual(Object.values(OPAQUE_PATHS).toSorted());

    const verificationRowsBefore = db.verification.length;
    for (const [path, body] of Object.entries(bodies)) {
      const response = await postJson(invalid, path, body, { cookie });
      expect({ path, status: response.status, code: response.body?.code }).toEqual({
        path,
        status: 500,
        code: "INVALID_SERVER_SETUP",
      });
    }
    expect(db.verification.length).toBe(verificationRowsBefore);

    await expect(invalid.api.validateOpaqueSetup()).rejects.toMatchObject({
      body: { code: "INVALID_SERVER_SETUP" },
    });
    await expect(
      invalid.api.createPasswordResetToken({ body: { email: "setup@example.com" } }),
    ).rejects.toMatchObject({ body: { code: "INVALID_SERVER_SETUP" } });

    await expect(valid.api.validateOpaqueSetup()).resolves.toEqual({
      publicKey: expect.any(String),
    });
  });
});
