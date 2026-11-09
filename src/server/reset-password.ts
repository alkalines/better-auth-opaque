import type { GenericEndpointContext } from "better-auth";
import { APIError, createAuthEndpoint, formCsrfMiddleware } from "better-auth/api";
import {
  OPAQUE_ERROR_CODES,
  OPAQUE_PATHS,
  OPAQUE_PROVIDER_ID,
  createPasswordResetTokenBodySchema,
  resetChallengeBodySchema,
  resetCompleteBodySchema,
  resetVerifyBodySchema,
  revokePasswordResetTokensBodySchema,
  type CredentialUpdateResponse,
} from "../contract.ts";
import {
  assertPayloadSupported,
  attachCredential,
  findCredentialByUserId,
  readCredential,
  replaceCredential,
  type OpaqueCredential,
} from "./credential.ts";
import { randomToken, sha256 } from "./crypto.ts";
import type { OpaqueRuntime } from "./runtime.ts";
import { consumeState, createState } from "./state.ts";

/**
 * Row stored under a reset token's hash. The token is valid only while the account still points
 * at `credentialVersion` and the user's epoch row still holds `epoch`. `credentialVersion: null`
 * is an enrolment link for a user without an OPAQUE credential, valid only while none exists.
 */
type ResetTokenValue = { userId: string; credentialVersion: string | null; epoch: string };

/** Reset tokens are stored only as their SHA-256, so a database leak does not yield usable links. */
async function resetTokenIdentifier(token: string): Promise<string> {
  return `opaque:reset-token:${await sha256(token)}`;
}

/**
 * Per-user revocation switch: one verification row holding a random epoch that every live reset
 * token carries. Deleting the row (or replacing its epoch) invalidates all outstanding tokens
 * without comparing clocks.
 */
function resetEpochIdentifier(userId: string): string {
  return `opaque:reset-epoch:${userId}`;
}

/** Decodes a token row. Rows without the version and epoch bindings (0.1.x) are rejected. */
function parseResetTokenValue(raw: string): ResetTokenValue | null {
  try {
    const value: unknown = JSON.parse(raw);
    if (typeof value !== "object" || value === null) {
      return null;
    }
    const { userId, credentialVersion, epoch } = value as Record<string, unknown>;
    if (
      typeof userId !== "string" ||
      (typeof credentialVersion !== "string" && credentialVersion !== null) ||
      typeof epoch !== "string"
    ) {
      return null;
    }
    return { userId, credentialVersion, epoch };
  } catch {
    return null;
  }
}

/** Whether a verification row is still live; secondary storage returns `expiresAt` as a string. */
function isLive(row: { expiresAt: Date | string }): boolean {
  return new Date(row.expiresAt).getTime() > Date.now();
}

/**
 * Returns the user's epoch for a token expiring at `tokenExpiresAt`, creating the epoch row when
 * none is live and extending it so it outlives the token. Concurrent first issuances may each
 * create a row; readers only honor the newest row, so the loser's link fails closed, and the next
 * revocation removes every duplicate.
 */
async function issueResetEpoch(
  ctx: GenericEndpointContext,
  userId: string,
  tokenExpiresAt: Date,
): Promise<string> {
  const { internalAdapter } = ctx.context;
  const identifier = resetEpochIdentifier(userId);

  const existing = await internalAdapter.findVerificationValue(identifier);
  if (existing && isLive(existing)) {
    if (new Date(existing.expiresAt).getTime() < tokenExpiresAt.getTime()) {
      await internalAdapter.updateVerificationByIdentifier(identifier, {
        expiresAt: tokenExpiresAt,
      });
    }
    return existing.value;
  }

  // An expired row only covers expired tokens, so replacing it revokes nothing live.
  await internalAdapter.consumeVerificationValue(identifier);
  const epoch = randomToken();
  await internalAdapter.createVerificationValue({
    identifier,
    value: epoch,
    expiresAt: tokenExpiresAt,
  });
  return epoch;
}

/**
 * Finds the user a link is for by email, or fails with `USER_NOT_FOUND`. Without
 * `allowEnrolment` the user must own an OPAQUE credential; with it, a user without any OPAQUE
 * account row qualifies too and gets `credentialVersion: null`.
 */
async function findResetSubject(
  ctx: GenericEndpointContext,
  email: string,
  allowEnrolment: boolean,
): Promise<{ userId: string; credentialVersion: string | null }> {
  const found = await ctx.context.internalAdapter.findUserByEmail(email.toLowerCase(), {
    includeAccounts: true,
  });
  const opaqueAccount = found?.accounts.find(
    (account) => account.providerId === OPAQUE_PROVIDER_ID,
  );
  const credential = readCredential(opaqueAccount);
  if (credential) {
    return { userId: credential.userId, credentialVersion: credential.credentialVersion };
  }
  if (found && allowEnrolment && !opaqueAccount) {
    return { userId: found.user.id, credentialVersion: null };
  }
  throw APIError.from("NOT_FOUND", OPAQUE_ERROR_CODES.USER_NOT_FOUND);
}

/** The single failure of every reset-token lookup, so callers cannot tell the causes apart. */
function invalidResetToken(): APIError {
  return APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_RESET_TOKEN);
}

/** What a valid reset token resolves to: the user and, unless it is an enrolment, the credential. */
type ResetTarget = { userId: string; credential: OpaqueCredential | null };

/**
 * Resolves the user and credential a reset token belongs to without consuming the token.
 * Unknown, expired, orphaned, revoked, and superseded tokens (the credential changed, or an
 * enrolment target gained an OPAQUE credential, after issuance) all fail with
 * `INVALID_RESET_TOKEN`.
 */
async function findResetTarget(ctx: GenericEndpointContext, token: string): Promise<ResetTarget> {
  const { internalAdapter } = ctx.context;

  const row = await internalAdapter.findVerificationValue(await resetTokenIdentifier(token));
  // `findVerificationValue` does not check expiry (unlike `consumeVerificationValue`).
  if (!row || !isLive(row)) {
    throw invalidResetToken();
  }
  const value = parseResetTokenValue(row.value);
  if (!value) {
    throw invalidResetToken();
  }

  const epochRow = await internalAdapter.findVerificationValue(resetEpochIdentifier(value.userId));
  if (!epochRow || !isLive(epochRow) || epochRow.value !== value.epoch) {
    throw invalidResetToken();
  }

  const credential = await findCredentialByUserId(ctx, value.userId);
  if ((credential?.credentialVersion ?? null) !== value.credentialVersion) {
    throw invalidResetToken();
  }
  if (!credential && !(await internalAdapter.findUserById(value.userId))) {
    throw invalidResetToken();
  }
  return { userId: value.userId, credential };
}

/**
 * Password reset: the server-only `createPasswordResetToken` and `revokePasswordResetTokens`
 * plus `POST /reset/opaque/verify`, `/reset/opaque/challenge`, and `/reset/opaque/complete`.
 * The three HTTP endpoints are cookie-less first-login surfaces and carry Better Auth's
 * `formCsrfMiddleware`, like `/sign-in/email`.
 */
export function resetPasswordEndpoints(runtime: OpaqueRuntime) {
  /**
   * Server-only (never routed over HTTP): mints a single-use reset token for the user owning an
   * OPAQUE account with this email and returns the link built by `passwordReset.url`. The app is
   * responsible for delivering it; unknown emails fail with `USER_NOT_FOUND`, so do not forward
   * that difference to unauthenticated callers.
   *
   * A token is bound to the credential version it was issued for, so any later password change
   * or reset invalidates it. Tokens issued by 0.1.x lack the binding and are rejected. Links of
   * one user are otherwise independent; `revokePrevious: true` first invalidates every
   * outstanding link (see `revokePasswordResetTokens`).
   *
   * `allowEnrolment: true` also issues a link for an existing user without an OPAQUE credential
   * (for example a classic email/password user who forgot the password before migrating). Using
   * it registers the first OPAQUE credential, removes the classic password when
   * `removeClassicCredential` is on, and revokes every session; it stops working as soon as the
   * user owns an OPAQUE credential. Without the flag such users get `USER_NOT_FOUND`.
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

      const subject = await findResetSubject(ctx, ctx.body.email, ctx.body.allowEnrolment === true);
      const { internalAdapter } = ctx.context;

      if (ctx.body.revokePrevious) {
        await internalAdapter.consumeVerificationValue(resetEpochIdentifier(subject.userId));
      }

      const token = randomToken();
      const expiresAt = new Date(Date.now() + passwordReset.expiresIn * 1000);
      const value: ResetTokenValue = {
        userId: subject.userId,
        credentialVersion: subject.credentialVersion,
        epoch: await issueResetEpoch(ctx, subject.userId, expiresAt),
      };
      await internalAdapter.createVerificationValue({
        identifier: await resetTokenIdentifier(token),
        value: JSON.stringify(value),
        expiresAt,
      });

      return { url: passwordReset.url(token), expiresAt };
    },
  );

  /**
   * Server-only (never routed over HTTP): invalidates every outstanding reset link, enrolment
   * links included, of the user with this email, for example when the app suspects the mailbox
   * was exposed. Unknown emails fail with `USER_NOT_FOUND` like `createPasswordResetToken`.
   * Links issued afterwards work normally.
   */
  const revokePasswordResetTokens = createAuthEndpoint.serverOnly(
    {
      method: "POST",
      body: revokePasswordResetTokensBodySchema,
      metadata: { SERVER_ONLY: true },
    },
    async (ctx): Promise<CredentialUpdateResponse> => {
      await runtime.requireServerPublicKey();
      const subject = await findResetSubject(ctx, ctx.body.email, true);
      await ctx.context.internalAdapter.consumeVerificationValue(
        resetEpochIdentifier(subject.userId),
      );
      return { status: true };
    },
  );

  const resetOpaqueVerify = createAuthEndpoint(
    OPAQUE_PATHS.resetVerify,
    {
      method: "POST",
      body: resetVerifyBodySchema,
      use: [formCsrfMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const target = await findResetTarget(ctx, ctx.body.token);
      const payload =
        (await runtime.hooks.loadPayload?.(
          {
            userId: target.userId,
            credentialVersion: target.credential?.credentialVersion ?? null,
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
      use: [formCsrfMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const target = await findResetTarget(ctx, ctx.body.token);
      // An enrolment registers under a fresh credential id; a reset keeps the existing one.
      const credentialId = target.credential?.credentialId ?? randomToken();
      // Built before the token is consumed so a malformed request does not burn the link.
      const registrationResponse = await runtime.createRegistrationResponse(
        credentialId,
        ctx.body.registrationRequest,
      );

      const consumed = await ctx.context.internalAdapter.consumeVerificationValue(
        await resetTokenIdentifier(ctx.body.token),
      );
      if (!consumed) {
        throw invalidResetToken();
      }

      const stateId = await createState(ctx, "reset-password", {
        userId: target.userId,
        credentialId,
        credentialVersion: target.credential?.credentialVersion ?? null,
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
      use: [formCsrfMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const { stateId, registrationRecord, payload } = ctx.body;
      assertPayloadSupported(runtime.hooks, payload);

      const state = await consumeState(ctx, "reset-password", stateId);
      if (state.credentialVersion === null) {
        await attachCredential(ctx, runtime, {
          flow: "reset-password",
          userId: state.userId,
          credentialId: state.credentialId,
          registrationRecord,
          keyStretching: state.keyStretching,
          payload,
          classicFingerprint: null,
        });
      } else {
        await replaceCredential(ctx, runtime, {
          flow: "reset-password",
          credentialId: state.credentialId,
          expectedVersion: state.credentialVersion,
          registrationRecord,
          keyStretching: state.keyStretching,
          payload,
        });
      }

      return ctx.json({ status: true as const });
    },
  );

  return {
    createPasswordResetToken,
    revokePasswordResetTokens,
    resetOpaqueVerify,
    resetOpaqueChallenge,
    resetOpaqueComplete,
  };
}
