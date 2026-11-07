// `runWithTransaction` is only exported by `@better-auth/core`; it is what lets internalAdapter
// writes (and the database hooks they run) join one transaction on adapters that support them.
import { runWithTransaction } from "@better-auth/core/context";
import { BASE_ERROR_CODES, type User } from "better-auth";
import { APIError, createAuthEndpoint, isAPIError } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { parseUserInput, parseUserOutput } from "better-auth/db";
import {
  OPAQUE_ACCOUNT_FIELDS,
  OPAQUE_PATHS,
  OPAQUE_PROVIDER_ID,
  signUpChallengeBodySchema,
  signUpCompleteBodySchema,
} from "../contract.ts";
import { assertPayloadSupported, validatePayload } from "./credential.ts";
import { randomToken } from "./crypto.ts";
import {
  hidesExistingEmails,
  sendVerificationEmail,
  syntheticSignUpResponse,
} from "./email-password-parity.ts";
import type { OpaqueRuntime } from "./runtime.ts";
import { consumeState, createState } from "./state.ts";

/** `POST /sign-up/opaque/challenge` and `/sign-up/opaque/complete`. */
export function signUpEndpoints(runtime: OpaqueRuntime) {
  const signUpOpaqueChallenge = createAuthEndpoint(
    OPAQUE_PATHS.signUpChallenge,
    {
      method: "POST",
      body: signUpChallengeBodySchema,
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const email = ctx.body.email.toLowerCase();

      // Same disclosure as email/password sign-up: when that route would answer
      // USER_ALREADY_EXISTS anyway, say so before the client spends a key-stretching round.
      if (!hidesExistingEmails(ctx)) {
        const existing = await ctx.context.internalAdapter.findUserByEmail(email);
        if (existing) {
          throw APIError.from(
            "UNPROCESSABLE_ENTITY",
            BASE_ERROR_CODES.USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
          );
        }
      }

      // The credential id is minted here and fixed for the account's lifetime; it is the OPAQUE
      // user identifier, so records never depend on the (changeable) email.
      const credentialId = randomToken();
      const registrationResponse = await runtime.createRegistrationResponse(
        credentialId,
        ctx.body.registrationRequest,
      );
      const stateId = await createState(ctx, "sign-up", {
        email,
        credentialId,
        keyStretching: runtime.keyStretching,
      });

      return ctx.json({
        stateId,
        registrationResponse,
        keyStretching: runtime.keyStretching,
        ...runtime.challengeIdentity,
      });
    },
  );

  const signUpOpaqueComplete = createAuthEndpoint(
    OPAQUE_PATHS.signUpComplete,
    {
      method: "POST",
      body: signUpCompleteBodySchema,
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const { hooks } = runtime;
      const {
        stateId,
        registrationRecord,
        name,
        image,
        callbackURL,
        rememberMe,
        payload,
        ...additionalFields
      } = ctx.body;

      // Input checks that need no state run before the state is consumed.
      assertPayloadSupported(hooks, payload);
      const additionalUserFields = parseUserInput(ctx.context.options, additionalFields, "create");

      const state = await consumeState(ctx, "sign-up", stateId);
      await validatePayload(hooks, { payload, flow: "sign-up" }, ctx);

      const hideExistingEmails = hidesExistingEmails(ctx);
      const duplicateResponse = () =>
        ctx.json(
          syntheticSignUpResponse(ctx, {
            email: state.email,
            name,
            image,
            additionalFields: additionalUserFields,
          }),
        );

      // Re-checked at complete: the email may have been registered since the challenge, and a
      // sign-up must never attach a credential to an existing user.
      const existing = await ctx.context.internalAdapter.findUserByEmail(state.email);
      if (existing) {
        ctx.context.logger.info("opaque: sign-up attempt for an existing email");
        if (!hideExistingEmails) {
          throw APIError.from(
            "UNPROCESSABLE_ENTITY",
            BASE_ERROR_CODES.USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL,
          );
        }
        const onExistingUserSignUp = ctx.context.options.emailAndPassword?.onExistingUserSignUp;
        if (onExistingUserSignUp) {
          await ctx.context.runInBackgroundOrAwait(
            onExistingUserSignUp({ user: existing.user }, ctx.request),
          );
        }
        return duplicateResponse();
      }

      const created = await runWithTransaction(ctx.context.adapter, async () => {
        let user: User;
        try {
          user = await ctx.context.internalAdapter.createUser(
            {
              email: state.email,
              name,
              image,
              ...additionalUserFields,
              emailVerified: false,
            },
            { method: "opaque" },
          );
        } catch (error) {
          if (isAPIError(error)) {
            // A database hook rejecting the user (403) is answered like a duplicate when
            // duplicates are hidden, as email/password sign-up does.
            if (error.statusCode === 403 && hideExistingEmails) {
              return null;
            }
            throw error;
          }
          ctx.context.logger.error("opaque: failed to create user", error);
          throw APIError.from("UNPROCESSABLE_ENTITY", BASE_ERROR_CODES.FAILED_TO_CREATE_USER);
        }
        if (!user) {
          throw APIError.from("UNPROCESSABLE_ENTITY", BASE_ERROR_CODES.FAILED_TO_CREATE_USER);
        }

        // Ordering: the payload is stored before the account exists, so a usable credential
        // always has its payload. Any failure from here on removes the user again; adapters with
        // transactions roll back as well, adapters without them (e.g. Convex) rely on this.
        try {
          const credentialVersion = randomToken();
          if (payload !== undefined && hooks.commitPayload) {
            await hooks.commitPayload(
              { userId: user.id, credentialVersion, payload, flow: "sign-up" },
              ctx,
            );
          }
          const account = await ctx.context.internalAdapter.createAccount({
            userId: user.id,
            providerId: OPAQUE_PROVIDER_ID,
            accountId: state.credentialId,
            [OPAQUE_ACCOUNT_FIELDS.registrationRecord]: registrationRecord,
            [OPAQUE_ACCOUNT_FIELDS.credentialVersion]: credentialVersion,
            [OPAQUE_ACCOUNT_FIELDS.keyStretching]: JSON.stringify(state.keyStretching),
          });
          // `null` when a database `account.create.before` hook rejected the row.
          if (!account) {
            throw APIError.from("UNPROCESSABLE_ENTITY", BASE_ERROR_CODES.FAILED_TO_CREATE_USER);
          }
          await hooks.activatePayload?.(
            {
              userId: user.id,
              credentialVersion,
              previousCredentialVersion: null,
              flow: "sign-up",
            },
            ctx,
          );

          const options = ctx.context.options;
          if (
            options.emailVerification?.sendOnSignUp ??
            options.emailAndPassword?.requireEmailVerification
          ) {
            await sendVerificationEmail(ctx, user, callbackURL);
          }

          if (hideExistingEmails) {
            return { user, session: null };
          }
          const session = await ctx.context.internalAdapter.createSession(
            user.id,
            rememberMe === false,
            undefined,
            undefined,
            { deferSecondaryStorageWrites: true },
          );
          if (!session) {
            throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION);
          }
          return { user, session };
        } catch (error) {
          try {
            await ctx.context.internalAdapter.deleteUser(user.id);
          } catch (cleanupError) {
            ctx.context.logger.error(
              "opaque: failed to remove user after failed sign-up",
              cleanupError,
            );
          }
          throw error;
        }
      });

      if (!created) {
        return duplicateResponse();
      }
      const user = parseUserOutput(ctx.context.options, created.user);
      if (!created.session) {
        return ctx.json({ token: null, user });
      }
      await setSessionCookie(
        ctx,
        { session: created.session, user: created.user },
        rememberMe === false,
      );
      return ctx.json({ token: created.session.token, user });
    },
  );

  return { signUpOpaqueChallenge, signUpOpaqueComplete };
}
