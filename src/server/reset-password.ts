import type { GenericEndpointContext } from "better-auth";
import { APIError, createAuthEndpoint } from "better-auth/api";
import {
  OPAQUE_ERROR_CODES,
  OPAQUE_PATHS,
  OPAQUE_PROVIDER_ID,
  createPasswordResetTokenBodySchema,
  resetChallengeBodySchema,
  resetCompleteBodySchema,
  resetVerifyBodySchema,
} from "../contract.ts";
import {
  assertPayloadSupported,
  findCredentialByUserId,
  readCredential,
  replaceCredential,
  type OpaqueCredential,
} from "./credential.ts";
import { randomToken, sha256 } from "./crypto.ts";
import type { OpaqueRuntime } from "./runtime.ts";
import { consumeState, createState } from "./state.ts";

type ResetTokenValue = { userId: string };

/** Reset tokens are stored only as their SHA-256, so a database leak does not yield usable links. */
async function resetTokenIdentifier(token: string): Promise<string> {
  return `opaque:reset-token:${await sha256(token)}`;
}

/**
 * Resolves the credential a reset token belongs to without consuming the token. Unknown, expired,
 * and orphaned tokens all fail with `INVALID_RESET_TOKEN`.
 */
async function findResetTarget(
  ctx: GenericEndpointContext,
  token: string,
): Promise<OpaqueCredential> {
  const row = await ctx.context.internalAdapter.findVerificationValue(
    await resetTokenIdentifier(token),
  );
  // `findVerificationValue` does not check expiry (unlike `consumeVerificationValue`), and rows
  // from secondary storage carry `expiresAt` as a string.
  if (!row || new Date(row.expiresAt).getTime() <= Date.now()) {
    throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_RESET_TOKEN);
  }
  const { userId } = JSON.parse(row.value) as ResetTokenValue;
  const credential = await findCredentialByUserId(ctx, userId);
  if (!credential) {
    throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_RESET_TOKEN);
  }
  return credential;
}

/**
 * Password reset: the server-only `createPasswordResetToken` plus `POST /reset/opaque/verify`,
 * `/reset/opaque/challenge`, and `/reset/opaque/complete`.
 */
export function resetPasswordEndpoints(runtime: OpaqueRuntime) {
  /**
   * Server-only (never routed over HTTP): mints a single-use reset token for the user owning an
   * OPAQUE account with this email and returns the link built by `passwordReset.url`. The app is
   * responsible for delivering it; unknown emails fail with `USER_NOT_FOUND`, so do not forward
   * that difference to unauthenticated callers.
   */
  const createPasswordResetToken = createAuthEndpoint.serverOnly(
    {
      method: "POST",
      body: createPasswordResetTokenBodySchema,
      metadata: { SERVER_ONLY: true },
    },
    async (ctx) => {
      const passwordReset = runtime.passwordReset;
      if (!passwordReset) {
        throw new Error("opaque(): createPasswordResetToken requires the `passwordReset` option.");
      }
      await runtime.requireServerPublicKey();

      const found = await ctx.context.internalAdapter.findUserByEmail(
        ctx.body.email.toLowerCase(),
        { includeAccounts: true },
      );
      const credential = readCredential(
        found?.accounts.find((account) => account.providerId === OPAQUE_PROVIDER_ID),
      );
      if (!credential) {
        throw APIError.from("NOT_FOUND", OPAQUE_ERROR_CODES.USER_NOT_FOUND);
      }

      const token = randomToken();
      const expiresAt = new Date(Date.now() + passwordReset.expiresIn * 1000);
      const value: ResetTokenValue = { userId: credential.userId };
      await ctx.context.internalAdapter.createVerificationValue({
        identifier: await resetTokenIdentifier(token),
        value: JSON.stringify(value),
        expiresAt,
      });

      return { url: passwordReset.url(token), expiresAt };
    },
  );

  const resetOpaqueVerify = createAuthEndpoint(
    OPAQUE_PATHS.resetVerify,
    {
      method: "POST",
      body: resetVerifyBodySchema,
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const credential = await findResetTarget(ctx, ctx.body.token);
      const payload =
        (await runtime.hooks.loadPayload?.(
          {
            userId: credential.userId,
            credentialVersion: credential.credentialVersion,
            flow: "reset-password",
          },
          ctx,
        )) ?? null;
      return ctx.json({ payload });
    },
  );

  const resetOpaqueChallenge = createAuthEndpoint(
    OPAQUE_PATHS.resetChallenge,
    {
      method: "POST",
      body: resetChallengeBodySchema,
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const credential = await findResetTarget(ctx, ctx.body.token);
      // Built before the token is consumed so a malformed request does not burn the link.
      const registrationResponse = await runtime.createRegistrationResponse(
        credential.credentialId,
        ctx.body.registrationRequest,
      );

      const consumed = await ctx.context.internalAdapter.consumeVerificationValue(
        await resetTokenIdentifier(ctx.body.token),
      );
      if (!consumed) {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_RESET_TOKEN);
      }

      const stateId = await createState(ctx, "reset-password", {
        userId: credential.userId,
        credentialId: credential.credentialId,
        credentialVersion: credential.credentialVersion,
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

  const resetOpaqueComplete = createAuthEndpoint(
    OPAQUE_PATHS.resetComplete,
    {
      method: "POST",
      body: resetCompleteBodySchema,
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const { stateId, registrationRecord, payload } = ctx.body;
      assertPayloadSupported(runtime.hooks, payload);

      const state = await consumeState(ctx, "reset-password", stateId);
      await replaceCredential(ctx, runtime, {
        flow: "reset-password",
        credentialId: state.credentialId,
        expectedVersion: state.credentialVersion,
        registrationRecord,
        keyStretching: state.keyStretching,
        payload,
        // Whoever knew the old password may hold sessions; a reset ends all of them.
        revokeSessions: () => ctx.context.internalAdapter.deleteUserSessions(state.userId),
      });

      return ctx.json({ status: true as const });
    },
  );

  return { createPasswordResetToken, resetOpaqueVerify, resetOpaqueChallenge, resetOpaqueComplete };
}
