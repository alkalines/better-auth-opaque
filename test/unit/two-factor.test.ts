import { betterAuth } from "better-auth";
import { memoryAdapter } from "better-auth/adapters/memory";
import { twoFactor } from "better-auth/plugins";
import { expect, test } from "vitest";
import { opaque } from "../../src/server/index.ts";
import {
  BASE_URL,
  CHEAP_STRETCHING,
  createMemoryDb,
  createTestClient,
  SECRET,
  serverSetupForTests,
} from "./helpers.ts";

test("sign-in fails closed for users with two-factor authentication enabled", async () => {
  const db = { ...createMemoryDb(), twoFactor: [] };
  const auth = betterAuth({
    baseURL: BASE_URL,
    secret: SECRET,
    database: memoryAdapter(db),
    rateLimit: { enabled: false },
    logger: { disabled: true },
    plugins: [
      twoFactor(),
      opaque({ serverSetup: await serverSetupForTests(), keyStretching: CHEAP_STRETCHING }),
    ],
  });

  const email = "2fa@example.com";
  const signUp = await createTestClient(auth).authClient.signUp.opaque({
    email,
    password: "2fa-password",
    name: "Two Factor",
  });
  expect(signUp.error).toBeNull();

  // Enabling TOTP needs a verified authenticator; the stored flag is what Better Auth checks.
  const user = db.user.find((row) => row.email === email)!;
  user.twoFactorEnabled = true;
  const sessionsBefore = db.session.length;

  const browser = createTestClient(auth);
  const signIn = await browser.authClient.signIn.opaque({ email, password: "2fa-password" });
  expect(signIn.data).toBeNull();
  expect(signIn.error).toMatchObject({ status: 403, code: "TWO_FACTOR_NOT_SUPPORTED" });
  expect(db.session).toHaveLength(sessionsBefore);
  expect((await browser.authClient.getSession()).data).toBeNull();

  // Wrong passwords still get the generic error, so the flag reveals nothing without the password.
  const wrong = await browser.authClient.signIn.opaque({ email, password: "not-it" });
  expect(wrong.error?.code).toBe("INVALID_CREDENTIALS");
});
