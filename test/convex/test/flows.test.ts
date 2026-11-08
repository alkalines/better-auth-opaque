import { client as opaqueClient, ready } from "@serenity-kit/opaque";
import { describe, expect, it } from "vitest";
import {
  convexRun,
  createPasswordResetToken,
  createTestClient,
  describeUser,
  expectNotSent,
  payloadVersionsOf,
  postJson,
  tokenFromResetUrl,
  uniqueEmail,
} from "./support.ts";

/** What the app stores next to the credential: derived from the export key, as a real app would. */
const payloadFor = (label: string) => async (exportKey: string) => ({
  label,
  keyHint: exportKey.slice(0, 4),
});

async function signedUpUser(label: string) {
  const email = uniqueEmail(label);
  const password = `${label}-password-1`;
  const client = createTestClient();
  const signUp = await client.authClient.signUp.opaque({
    email,
    password,
    name: label,
    payload: payloadFor("v1"),
  });
  expect(signUp.error).toBeNull();
  return { email, password, client, signUp: signUp.data! };
}

describe("OPAQUE on the Convex default runtime", () => {
  it("signs up with a payload, then signs in with the same export key and the payload back", async () => {
    const { email, password, client, signUp } = await signedUpUser("signup");

    expect(signUp.user.email).toBe(email);
    expect(signUp.exportKey).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(client.cookies.size).toBeGreaterThan(0);

    const other = createTestClient();
    const signIn = await other.authClient.signIn.opaque({ email, password });
    expect(signIn.error).toBeNull();
    expect(signIn.data?.exportKey).toBe(signUp.exportKey);
    expect(signIn.data?.twoFactorRedirect).toBeUndefined();
    expect(signIn.data?.user?.id).toBe(signUp.user.id);
    expect(signIn.data?.payload).toEqual({ label: "v1", keyHint: signUp.exportKey.slice(0, 4) });

    const session = await other.authClient.getSession();
    expect(session.data?.user.id).toBe(signUp.user.id);

    // Neither the password nor the export key may ever be sent to the server.
    expectNotSent([client, other], [password, signUp.exportKey]);

    // Exactly one account, an OPAQUE one: sign-up never attaches to anything else.
    const stored = describeUser(email);
    expect(stored.users).toBe(1);
    expect(stored.accounts).toHaveLength(1);
    expect(stored.accounts[0]?.providerId).toBe("opaque");
  });

  it("rejects an app payload before writing anything", async () => {
    const email = uniqueEmail("invalid-payload");
    const { authClient } = createTestClient();
    const result = await authClient.signUp.opaque({
      email,
      password: "invalid-payload-password",
      name: "invalid",
      payload: { invalid: true },
    });

    expect(result.data).toBeNull();
    expect(result.error).not.toBeNull();
    expect(describeUser(email).users).toBe(0);
  });

  it("answers a wrong password and an unknown email identically", async () => {
    const { email, password } = await signedUpUser("enumeration");
    const { authClient } = createTestClient();

    const wrongPassword = await authClient.signIn.opaque({ email, password: `${password}-wrong` });
    const unknownEmail = await authClient.signIn.opaque({
      email: uniqueEmail("nobody"),
      password,
    });

    expect(wrongPassword.data).toBeNull();
    expect(unknownEmail.data).toBeNull();
    expect(unknownEmail.error).toEqual(wrongPassword.error);
    expect(wrongPassword.error?.code).toBe("INVALID_CREDENTIALS");
  });

  it("shapes the sign-in challenge the same for known and unknown emails", async () => {
    const { client, email, password } = await signedUpUser("challenge-shape");
    expectNotSent([client], [password]);
    await ready;
    const loginRequest = opaqueClient.startLogin({ password: "whatever" }).startLoginRequest;

    const known = await postJson("/sign-in/opaque/challenge", { email, loginRequest });
    const unknown = await postJson("/sign-in/opaque/challenge", {
      email: uniqueEmail("ghost"),
      loginRequest,
    });

    expect(unknown.status).toBe(known.status);
    expect(Object.keys(unknown.body ?? {}).toSorted()).toEqual(
      Object.keys(known.body ?? {}).toSorted(),
    );
    expect(unknown.body?.keyStretching).toEqual(known.body?.keyStretching);
  });

  it("changes the password: old stops working, new payload version is returned", async () => {
    const { email, password, client, signUp } = await signedUpUser("change");
    const otherBrowser = createTestClient();
    expect((await otherBrowser.authClient.signIn.opaque({ email, password })).error).toBeNull();

    const newPassword = `${password}-changed`;
    const change = await client.authClient.opaque.changePassword({
      currentPassword: password,
      newPassword,
      payload: payloadFor("v2"),
    });
    expect(change.error).toBeNull();
    expect(change.data?.exportKey).not.toBe(signUp.exportKey);

    const withOld = await createTestClient().authClient.signIn.opaque({ email, password });
    expect(withOld.data).toBeNull();
    expect(withOld.error?.code).toBe("INVALID_CREDENTIALS");

    const withNew = await createTestClient().authClient.signIn.opaque({
      email,
      password: newPassword,
    });
    expect(withNew.error).toBeNull();
    expect(withNew.data?.exportKey).toBe(change.data?.exportKey);
    expect(withNew.data?.payload).toEqual({
      label: "v2",
      keyHint: change.data?.exportKey.slice(0, 4),
    });

    // `activatePayload` removed the previous credential version's payload.
    expect(payloadVersionsOf(signUp.user.id)).toHaveLength(1);

    // The changing browser keeps its session; the other browser's session is revoked.
    expect((await client.authClient.getSession()).data?.user.id).toBe(signUp.user.id);
    expect((await otherBrowser.authClient.getSession()).data).toBeNull();

    expectNotSent([client], [password, newPassword, signUp.exportKey, change.data!.exportKey]);
  });

  it("refuses a password change with the wrong current password and keeps the old credential", async () => {
    const { email, password, client } = await signedUpUser("change-wrong");

    const change = await client.authClient.opaque.changePassword({
      currentPassword: `${password}-wrong`,
      newPassword: "never-applied-password",
      payload: payloadFor("never"),
    });
    expect(change.data).toBeNull();

    const signIn = await createTestClient().authClient.signIn.opaque({ email, password });
    expect(signIn.error).toBeNull();
    expect(signIn.data?.payload).toMatchObject({ label: "v1" });
  });

  it("resets the password with a single-use token created through the server-only API", async () => {
    const { email, password, client, signUp } = await signedUpUser("reset");
    const { authClient } = createTestClient();

    const { url, expiresAt } = createPasswordResetToken(email);
    const token = tokenFromResetUrl(url);
    expect(new Date(expiresAt).getTime()).toBeGreaterThan(Date.now());

    // Verifying does not consume the token and returns the current credential's payload.
    for (let attempt = 0; attempt < 2; attempt++) {
      const verified = await authClient.opaque.verifyResetToken({ token });
      expect(verified.error).toBeNull();
      expect(verified.data?.payload).toMatchObject({ label: "v1" });
    }

    const newPassword = `${password}-reset`;
    const reset = await authClient.opaque.resetPassword({
      token,
      newPassword,
      payload: payloadFor("v3"),
    });
    expect(reset.error).toBeNull();

    // The token was consumed by the first reset.
    const again = await authClient.opaque.resetPassword({
      token,
      newPassword: "attacker-password",
      payload: payloadFor("attacker"),
    });
    expect(again.data).toBeNull();
    expect((await authClient.opaque.verifyResetToken({ token })).data).toBeNull();

    const withOld = await createTestClient().authClient.signIn.opaque({ email, password });
    expect(withOld.data).toBeNull();

    const withNew = await createTestClient().authClient.signIn.opaque({
      email,
      password: newPassword,
    });
    expect(withNew.error).toBeNull();
    expect(withNew.data?.exportKey).toBe(reset.data?.exportKey);
    expect(withNew.data?.payload).toMatchObject({ label: "v3" });
    expect(payloadVersionsOf(signUp.user.id)).toHaveLength(1);

    // A reset revokes every session, including the one the user had before.
    expect((await client.authClient.getSession()).data).toBeNull();
  });

  it("does not create a reset token for an unknown email", () => {
    expect(() => createPasswordResetToken(uniqueEmail("no-such-user"))).toThrow(/User not found/);
  });

  it("keeps the server-only APIs off HTTP", async () => {
    const paths = [
      "/create-password-reset-token",
      "/validate-opaque-setup",
      "/opaque/create-password-reset-token",
      "/opaque/validate-setup",
    ];
    const responses = await Promise.all(
      paths.map((path) => postJson(path, { email: uniqueEmail("probe") })),
    );
    expect(responses.map((response) => response.status)).toEqual(paths.map(() => 404));
  });

  it("validates the server setup through the server-only boot check", () => {
    const { publicKey } = convexRun<{ publicKey: string }>("testSupport:validateOpaqueSetup");
    expect(publicKey).toMatch(/^[A-Za-z0-9_-]{20,}$/);
  });
});
