import { BASE_ERROR_CODES } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { parseUserOutput } from "better-auth/db";
import {
  OPAQUE_ERROR_CODES,
  OPAQUE_PATHS,
  OPAQUE_PROVIDER_ID,
  signInChallengeBodySchema,
  signInCompleteBodySchema,
} from "../contract.ts";
import { findCredentialById, readCredential } from "./credential.ts";
import { hmacSha256 } from "./crypto.ts";
import { sendVerificationEmail } from "./email-password-parity.ts";
import type { OpaqueRuntime } from "./runtime.ts";
import { consumeState, createState } from "./state.ts";

/** The single sign-in failure: unknown email, no OPAQUE account, wrong password, stale proof. */
function invalidCredentials(): APIError {
  return APIError.from("UNAUTHORIZED", OPAQUE_ERROR_CODES.INVALID_CREDENTIALS);
}

/** `POST /sign-in/opaque/challenge` and `/sign-in/opaque/complete`. */
export function signInEndpoints(runtime: OpaqueRuntime) {
  const signInOpaqueChallenge = createAuthEndpoint(
    OPAQUE_PATHS.signInChallenge,
    {
      method: "POST",
      body: signInChallengeBodySchema,
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const email = ctx.body.email.toLowerCase();

      // Enumeration resistance: unknown emails and users without an OPAQUE credential get a fake
      // login keyed by a secret-derived identifier, so the response is stable per email and has
      // the same shape as a real one. The HMAC is computed on both paths to keep the work equal.
      const fakeIdentifier = await hmacSha256(ctx.context.secret, `opaque/fake/${email}`);
      const found = await ctx.context.internalAdapter.findUserByEmail(email, {
        includeAccounts: true,
      });
      const credential = readCredential(
        found?.accounts.find((account) => account.providerId === OPAQUE_PROVIDER_ID),
      );

      const { serverLoginState, loginResponse } = await runtime.startLogin(
        credential?.credentialId ?? fakeIdentifier,
        credential?.registrationRecord ?? null,
        ctx.body.loginRequest,
      );
      // The server login state never leaves the server; the client only gets the state id.
      const stateId = await createState(ctx, "sign-in", {
        serverLoginState,
        userId: credential?.userId ?? null,
        credentialId: credential?.credentialId ?? null,
        credentialVersion: credential?.credentialVersion ?? null,
      });

      return ctx.json({
        stateId,
        loginResponse,
        // Accounts keep the profile they registered with; fake logins use the current default.
        keyStretching: credential?.keyStretching ?? runtime.keyStretching,
        ...runtime.challengeIdentity,
      });
    },
  );

  const signInOpaqueComplete = createAuthEndpoint(
    OPAQUE_PATHS.signInComplete,
    {
      method: "POST",
      body: signInCompleteBodySchema,
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const state = await consumeState(ctx, "sign-in", ctx.body.stateId);

      // Fake states fail here exactly like wrong passwords: serenity rejects the finalization.
      const proven = await runtime.verifyLogin(state.serverLoginState, ctx.body.loginFinalization);
      if (!proven || state.credentialId === null) {
        throw invalidCredentials();
      }

      // The proof is only valid for the record it was made against; a password change or reset
      // since the challenge must not let the previous password in.
      const credential = await findCredentialById(ctx, state.credentialId);
      if (!credential || credential.credentialVersion !== state.credentialVersion) {
        throw invalidCredentials();
      }
      const user = await ctx.context.internalAdapter.findUserById(credential.userId);
      if (!user) {
        throw invalidCredentials();
      }

      // Same email verification gate as email/password sign-in; reached only with a valid proof.
      const options = ctx.context.options;
      if (options.emailAndPassword?.requireEmailVerification && !user.emailVerified) {
        if (!options.emailVerification?.sendVerificationEmail) {
          throw APIError.from("FORBIDDEN", BASE_ERROR_CODES.EMAIL_NOT_VERIFIED);
        }
        if (options.emailVerification.sendOnSignIn) {
          await sendVerificationEmail(ctx, user, undefined);
        }
        throw APIError.from("FORBIDDEN", BASE_ERROR_CODES.EMAIL_NOT_VERIFIED);
      }

      // Better Auth's two-factor plugin only intercepts its own sign-in paths, so a session issued
      // here would skip the second factor. Fail closed instead of creating one.
      if ("twoFactorEnabled" in user && user.twoFactorEnabled === true) {
        throw APIError.from("FORBIDDEN", OPAQUE_ERROR_CODES.TWO_FACTOR_NOT_SUPPORTED);
      }

      // Loaded before the session exists so a failing hook does not leave a session behind.
      const payload =
        (await runtime.hooks.loadPayload?.(
          { userId: user.id, credentialVersion: credential.credentialVersion, flow: "sign-in" },
          ctx,
        )) ?? null;

      const dontRememberMe = ctx.body.rememberMe === false;
      const session = await ctx.context.internalAdapter.createSession(user.id, dontRememberMe);
      if (!session) {
        ctx.context.logger.error("opaque: failed to create session");
        throw APIError.from("UNAUTHORIZED", BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION);
      }

      // A reset or change switches the credential and then revokes sessions; this flow creates the
      // session and then re-checks the credential. If the re-check ran before the switch, the
      // session existed before the revocation and is revoked by it; if it runs after, it sees the
      // new version and removes the session itself. Either way no session proven with a replaced
      // password survives.
      const current = await findCredentialById(ctx, state.credentialId);
      if (!current || current.credentialVersion !== state.credentialVersion) {
        await ctx.context.internalAdapter.deleteSession(session.token);
        throw invalidCredentials();
      }
      await setSessionCookie(ctx, { session, user }, dontRememberMe);

      return ctx.json({
        token: session.token,
        user: parseUserOutput(ctx.context.options, user),
        payload,
      });
    },
  );

  return { signInOpaqueChallenge, signInOpaqueComplete };
}
