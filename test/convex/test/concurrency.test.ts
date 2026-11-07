import { client, ready } from "@serenity-kit/opaque";
import { describe, expect, it } from "vitest";
import {
  createPasswordResetToken,
  createTestClient,
  describeUser,
  postJson,
  tokenFromResetUrl,
  uniqueEmail,
} from "./support.ts";

/** Parallel requests per round; the state must be consumed by exactly one of them at most. */
const PARALLEL_COMPLETES = 2;
const ROUNDS = 4;
const CREDENTIAL_ROUNDS = 3;

/** The profile the server advertises, in the form serenity's client functions accept. */
type KeyStretching = Parameters<typeof client.finishLogin>[0]["keyStretching"];

type Challenge = { stateId: string; keyStretching: KeyStretching } & Record<string, unknown>;

async function challengeBody(path: string, body: unknown): Promise<Challenge> {
  const response = await postJson(path, body);
  expect(response.status, `${path} -> ${JSON.stringify(response.body)}`).toBe(200);
  return response.body as Challenge;
}

/** Fires the same request several times at once and returns each response status. */
async function raceCompletes(path: string, body: unknown): Promise<number[]> {
  const responses = await Promise.all(
    Array.from({ length: PARALLEL_COMPLETES }, () => postJson(path, body)),
  );
  return responses.map((response) => response.status);
}

describe("single-use state under parallel completes (real backend)", () => {
  it("lets at most one of two parallel /sign-in/opaque/complete calls succeed", async () => {
    await ready;
    const email = uniqueEmail("race-sign-in");
    const password = "race-sign-in-password";
    const signUp = await createTestClient().authClient.signUp.opaque({
      email,
      password,
      name: "race",
    });
    expect(signUp.error).toBeNull();

    const outcomes: number[][] = [];
    for (let round = 0; round < ROUNDS; round++) {
      const login = client.startLogin({ password });
      const challenge = await challengeBody("/sign-in/opaque/challenge", {
        email,
        loginRequest: login.startLoginRequest,
      });
      const finished = client.finishLogin({
        clientLoginState: login.clientLoginState,
        loginResponse: challenge.loginResponse as string,
        password,
        keyStretching: challenge.keyStretching,
      });
      expect(finished).toBeDefined();

      const statuses = await raceCompletes("/sign-in/opaque/complete", {
        stateId: challenge.stateId,
        loginFinalization: finished!.finishLoginRequest,
      });
      outcomes.push(statuses);
      expect(statuses.filter((status) => status === 200).length).toBeLessThanOrEqual(1);

      // The state is gone for good: a later replay of the same finalization fails too.
      const [replay] = await raceCompletes("/sign-in/opaque/complete", {
        stateId: challenge.stateId,
        loginFinalization: finished!.finishLoginRequest,
      });
      expect(replay).not.toBe(200);
    }
    console.log(`[concurrency] sign-in complete statuses per round: ${JSON.stringify(outcomes)}`);
  });

  it("creates at most one user from two parallel /sign-up/opaque/complete calls of one state", async () => {
    await ready;
    const outcomes: { statuses: number[]; users: number }[] = [];

    for (let round = 0; round < ROUNDS; round++) {
      const email = uniqueEmail("race-sign-up");
      const password = "race-sign-up-password";
      const registration = client.startRegistration({ password });
      const challenge = await challengeBody("/sign-up/opaque/challenge", {
        email,
        registrationRequest: registration.registrationRequest,
      });
      const { registrationRecord } = client.finishRegistration({
        password,
        registrationResponse: challenge.registrationResponse as string,
        clientRegistrationState: registration.clientRegistrationState,
        keyStretching: challenge.keyStretching,
      });

      const statuses = await raceCompletes("/sign-up/opaque/complete", {
        stateId: challenge.stateId,
        registrationRecord,
        name: "race",
      });
      const stored = describeUser(email);
      outcomes.push({ statuses, users: stored.users });

      const successes = statuses.filter((status) => status === 200).length;
      expect(successes).toBeLessThanOrEqual(1);
      expect(stored.users).toBeLessThanOrEqual(1);
      // A user exists exactly when a request reported success, and it has one OPAQUE account.
      expect(stored.users).toBe(successes);
      expect(stored.accounts.map((account) => account.providerId)).toEqual(
        Array.from({ length: stored.users }, () => "opaque"),
      );
    }
    console.log(`[concurrency] sign-up complete outcomes per round: ${JSON.stringify(outcomes)}`);
  });
});

type HttpResult = { status: number; body: Record<string, unknown> | null };

/** The `cookie` header of a test client's browser session. */
function cookieHeader(browser: { cookies: Map<string, string> }): Record<string, string> {
  return { cookie: [...browser.cookies].map(([name, value]) => `${name}=${value}`).join("; ") };
}

async function signedUpUser(label: string) {
  const email = uniqueEmail(label);
  const password = `${label}-old-password`;
  const browsers = [createTestClient(), createTestClient()];
  const signUp = await browsers[0]!.authClient.signUp.opaque({
    email,
    password,
    name: label,
    payload: { label: "old" },
  });
  expect(signUp.error).toBeNull();
  const secondSession = await browsers[1]!.authClient.signIn.opaque({ email, password });
  expect(secondSession.error).toBeNull();
  return { email, password, browsers };
}

/**
 * Runs a change-password challenge and finishes both OPAQUE halves locally, like the client
 * plugin does, but returns the complete request instead of sending it.
 */
async function prepareChange(
  browser: { cookies: Map<string, string> },
  input: { currentPassword: string; newPassword: string; payload: unknown },
) {
  const login = client.startLogin({ password: input.currentPassword });
  const registration = client.startRegistration({ password: input.newPassword });
  const response = await postJson(
    "/opaque/change-password/challenge",
    {
      loginRequest: login.startLoginRequest,
      registrationRequest: registration.registrationRequest,
    },
    cookieHeader(browser),
  );
  expect(response.status).toBe(200);
  const challenge = response.body as Challenge & {
    loginKeyStretching: KeyStretching;
  };
  const proven = client.finishLogin({
    clientLoginState: login.clientLoginState,
    loginResponse: challenge.loginResponse as string,
    password: input.currentPassword,
    keyStretching: challenge.loginKeyStretching,
  });
  const { registrationRecord } = client.finishRegistration({
    password: input.newPassword,
    registrationResponse: challenge.registrationResponse as string,
    clientRegistrationState: registration.clientRegistrationState,
    keyStretching: challenge.keyStretching,
  });
  return () =>
    postJson(
      "/opaque/change-password/complete",
      {
        stateId: challenge.stateId,
        loginFinalization: proven!.finishLoginRequest,
        registrationRecord,
        payload: input.payload,
      },
      cookieHeader(browser),
    );
}

/** Runs a reset challenge (which consumes the token) and returns the complete request. */
async function prepareReset(input: { token: string; newPassword: string; payload: unknown }) {
  const registration = client.startRegistration({ password: input.newPassword });
  const challenge = await challengeBody("/reset/opaque/challenge", {
    token: input.token,
    registrationRequest: registration.registrationRequest,
  });
  const { registrationRecord } = client.finishRegistration({
    password: input.newPassword,
    registrationResponse: challenge.registrationResponse as string,
    clientRegistrationState: registration.clientRegistrationState,
    keyStretching: challenge.keyStretching,
  });
  return () =>
    postJson("/reset/opaque/complete", {
      stateId: challenge.stateId,
      registrationRecord,
      payload: input.payload,
    });
}

/** Exactly one winner (200); the loser gets a 409 `CREDENTIAL_CHANGED`, never a server error. */
function expectOneWinner(results: HttpResult[]): number {
  const statuses = results.map((result) => result.status);
  const winners = results.flatMap((result, index) => (result.status === 200 ? [index] : []));
  expect(statuses).toContain(200);
  expect(winners).toHaveLength(1);

  const loser = results[1 - winners[0]!]!;
  expect(loser.status).toBe(409);
  expect(loser.body?.code).toBe("CREDENTIAL_CHANGED");
  return winners[0]!;
}

type SignInOutcome = { errorCode: string | null; payload: unknown };

const REJECTED: SignInOutcome = { errorCode: "INVALID_CREDENTIALS", payload: undefined };

function accepted(payload: unknown): SignInOutcome {
  return { errorCode: null, payload };
}

async function signInOutcome(email: string, password: string): Promise<SignInOutcome> {
  const result = await createTestClient().authClient.signIn.opaque({ email, password });
  return { errorCode: result.error?.code ?? null, payload: result.data?.payload };
}

describe("two credential replacements proven against the same version (real backend)", () => {
  it("lets exactly one of two parallel password changes win, the loser gets CREDENTIAL_CHANGED", async () => {
    await ready;
    const outcomes: number[][] = [];

    for (let round = 0; round < CREDENTIAL_ROUNDS; round++) {
      const { email, password, browsers } = await signedUpUser("race-change");
      const attempts = [
        { newPassword: `${password}-A`, payload: { label: "A" } },
        { newPassword: `${password}-B`, payload: { label: "B" } },
      ];
      // Both challenges see the same credential version before either complete runs.
      const completes = [
        await prepareChange(browsers[0]!, { currentPassword: password, ...attempts[0]! }),
        await prepareChange(browsers[1]!, { currentPassword: password, ...attempts[1]! }),
      ];

      const results = await Promise.all(completes.map((complete) => complete()));
      outcomes.push(results.map((result) => result.status));
      const winner = attempts[expectOneWinner(results)]!;
      const loser = attempts.find((attempt) => attempt !== winner)!;

      expect(await signInOutcome(email, winner.newPassword)).toEqual(accepted(winner.payload));
      expect(await signInOutcome(email, loser.newPassword)).toEqual(REJECTED);
      expect(await signInOutcome(email, password)).toEqual(REJECTED);
    }
    expect(outcomes).toHaveLength(CREDENTIAL_ROUNDS);
    console.log(`[concurrency] parallel change-password statuses: ${JSON.stringify(outcomes)}`);
  });

  it("lets exactly one of a password change and a reset win, the loser gets CREDENTIAL_CHANGED", async () => {
    await ready;
    const outcomes: number[][] = [];

    for (let round = 0; round < CREDENTIAL_ROUNDS; round++) {
      const { email, password, browsers } = await signedUpUser("race-reset");
      const changeAttempt = { newPassword: `${password}-change`, payload: { label: "change" } };
      const resetAttempt = { newPassword: `${password}-reset`, payload: { label: "reset" } };
      const token = tokenFromResetUrl(createPasswordResetToken(email).url);

      const completes = [
        await prepareChange(browsers[0]!, { currentPassword: password, ...changeAttempt }),
        await prepareReset({ token, ...resetAttempt }),
      ];

      const results = await Promise.all(completes.map((complete) => complete()));
      outcomes.push(results.map((result) => result.status));
      const winner = [changeAttempt, resetAttempt][expectOneWinner(results)]!;
      const loser = winner === changeAttempt ? resetAttempt : changeAttempt;

      expect(await signInOutcome(email, winner.newPassword)).toEqual(accepted(winner.payload));
      expect(await signInOutcome(email, loser.newPassword)).toEqual(REJECTED);
      expect(await signInOutcome(email, password)).toEqual(REJECTED);
    }
    expect(outcomes).toHaveLength(CREDENTIAL_ROUNDS);
    console.log(`[concurrency] change-vs-reset statuses: ${JSON.stringify(outcomes)}`);
  });
});
