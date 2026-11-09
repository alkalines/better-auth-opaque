import { APIError, createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import {
  OPAQUE_ERROR_CODES,
  OPAQUE_PATHS,
  changePasswordChallengeBodySchema,
  changePasswordCompleteBodySchema,
} from "../contract.ts";
import { assertPayloadSupported, findCredentialByUserId, replaceCredential } from "./credential.ts";
import type { OpaqueRuntime } from "./runtime.ts";
import { reissueSession } from "./session.ts";
import { consumeState, createState } from "./state.ts";

/**
 * `POST /opaque/change-password/challenge` and `/opaque/change-password/complete`. Both require a
 * session read from the session store (not the cookie cache), and the complete call requires a
 * fresh OPAQUE proof of the current password, so a stolen session alone cannot change it.
 *
 * Like Better Auth's `changePassword` with `revokeOtherSessions`, a successful change deletes
 * every session of the user (exhaustively, including secondary storage) and signs the caller in
 * again with a new session, returned as `token` and set as the session cookie. When
 * `activatePayload` throws after the credential switched, all sessions are still revoked and the
 * error is returned without a replacement session: the new password is in effect, so the caller
 * signs in again. This avoids depending on cookies surviving a non-API error.
 */
export function changePasswordEndpoints(runtime: OpaqueRuntime) {
  const opaqueChangePasswordChallenge = createAuthEndpoint(
    OPAQUE_PATHS.changePasswordChallenge,
    {
      method: "POST",
      body: changePasswordChallengeBodySchema,
      use: [sensitiveSessionMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const { user } = ctx.context.session;
      await runtime.checkAccountRateLimit(ctx, user.email, "change-password");
      const userId = user.id;

      const credential = await findCredentialByUserId(ctx, userId);
      if (!credential) {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_NOT_FOUND);
      }

      const { serverLoginState, loginResponse } = await runtime.startLogin(
        credential.credentialId,
        credential.registrationRecord,
        ctx.body.loginRequest,
      );
      const registrationResponse = await runtime.createRegistrationResponse(
        credential.credentialId,
        ctx.body.registrationRequest,
      );
      // Bound to the user and the credential version the login is proven against.
      const stateId = await createState(ctx, "change-password", {
        userId,
        credentialId: credential.credentialId,
        credentialVersion: credential.credentialVersion,
        serverLoginState,
        keyStretching: runtime.keyStretching,
      });

      return ctx.json({
        stateId,
        loginResponse,
        loginKeyStretching: credential.keyStretching,
        registrationResponse,
        keyStretching: runtime.keyStretching,
        ...runtime.challengeIdentity,
      });
    },
  );

  const opaqueChangePasswordComplete = createAuthEndpoint(
    OPAQUE_PATHS.changePasswordComplete,
    {
      method: "POST",
      body: changePasswordCompleteBodySchema,
      use: [sensitiveSessionMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const { stateId, loginFinalization, registrationRecord, payload } = ctx.body;
      const session = ctx.context.session;
      assertPayloadSupported(runtime.hooks, payload);

      const state = await consumeState(ctx, "change-password", stateId);
      if (state.userId !== session.user.id) {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_STATE);
      }
      if (!(await runtime.verifyLogin(state.serverLoginState, loginFinalization))) {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_PASSWORD);
      }

      const credentialVersion = await replaceCredential(ctx, runtime, {
        flow: "change-password",
        credentialId: state.credentialId,
        expectedVersion: state.credentialVersion,
        registrationRecord,
        keyStretching: state.keyStretching,
        payload,
      });

      return ctx.json(
        await reissueSession(ctx, session.user, {
          credentialId: state.credentialId,
          credentialVersion,
        }),
      );
    },
  );

  return { opaqueChangePasswordChallenge, opaqueChangePasswordComplete };
}
