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
  readCredentialRow,
  replaceCredential,
  type OpaqueCredentialRow,
} from "./credential.ts";
import { randomToken, sha256 } from "./crypto.ts";
import { MAX_RESET_EXPIRES_IN_SECONDS, type OpaqueRuntime } from "./runtime.ts";
import { consumeState, createState } from "./state.ts";

/**
 * Row stored under a reset token's hash. The token is valid only while the account still points
 * at `credentialVersion` and no revocation happened since issuance: `revocation` is the user's
 * revocation marker that was current at issuance, `null` when none was live (see
 * {@link isUnrevoked}). `credentialVersion: null` is an enrolment link for a user without an
 * OPAQUE credential, valid only while the user has no OPAQUE account row at all.
 */
type ResetTokenValue = {
  userId: string;
  credentialVersion: string | null;
  revocation: string | null;
};

/** Reset tokens are stored only as their SHA-256, so a database leak does not yield usable links. */
async function resetTokenIdentifier(token: string): Promise<string> {
  return `opaque:reset-token:${await sha256(token)}`;
}

/**
 * Per-user revocation marker: a verification row holding a random value, written anew by every
 * revocation. Readers only see the newest row (Better Auth returns the latest row per identifier,
 * and secondary storage keeps one value per key).
 */
function resetRevocationIdentifier(userId: string): string {
  return `opaque:reset-revocation:${userId}`;
}

/**
 * A marker must outlive every link issued before it and the reset state (5 minutes) started from
 * such a link; links live at most `MAX_RESET_EXPIRES_IN_SECONDS`. The extra hour covers the state.
 */
const REVOCATION_LIFETIME_MS = (MAX_RESET_EXPIRES_IN_SECONDS + 60 * 60) * 1000;

/** Decodes a token row. Rows without the version and revocation bindings (0.1.x) are rejected. */
function parseResetTokenValue(raw: string): ResetTokenValue | null {
  try {
    const value: unknown = JSON.parse(raw);
    if (typeof value !== "object" || value === null) {
      return null;
    }
    const { userId, credentialVersion, revocation } = value as Record<string, unknown>;
    if (
      typeof userId !== "string" ||
      (typeof credentialVersion !== "string" && credentialVersion !== null) ||
      (typeof revocation !== "string" && revocation !== null)
    ) {
      return null;
    }
    return { userId, credentialVersion, revocation };
  } catch {
    return null;
  }
}

/** Whether a verification row is still live; secondary storage returns `expiresAt` as a string. */
function isLive(row: { expiresAt: Date | string }): boolean {
  return new Date(row.expiresAt).getTime() > Date.now();
}

/** The user's current revocation marker, `null` when none is live. */
async function currentRevocation(
  ctx: GenericEndpointContext,
  userId: string,
): Promise<string | null> {
  const row = await ctx.context.internalAdapter.findVerificationValue(
    resetRevocationIdentifier(userId),
  );
  return row && isLive(row) ? row.value : null;
}

/**
 * Invalidates every reset link and pending reset state of the user. Issuance only reads the
 * marker, so concurrent issuances cannot invalidate each other's links, and no expiry has to be
 * extended.
 */
async function revokeResetLinks(ctx: GenericEndpointContext, userId: string): Promise<void> {
  await ctx.context.internalAdapter.createVerificationValue({
    identifier: resetRevocationIdentifier(userId),
    value: randomToken(),
    expiresAt: new Date(Date.now() + REVOCATION_LIFETIME_MS),
  });
}

/**
 * Whether no revocation happened since a link carrying `revocation` was issued. Every revocation
 * writes a fresh random marker that outlives everything issued before it, so a live marker other
 * than the link's means a later revocation, and no live marker means none happened while the link
 * or its reset state could still be valid. No clocks are compared.
 */
async function isUnrevoked(
  ctx: GenericEndpointContext,
  userId: string,
  revocation: string | null,
): Promise<boolean> {
  const current = await currentRevocation(ctx, userId);
  return current === null || current === revocation;
}

/**
 * Finds the user a link is for by email, or fails with `USER_NOT_FOUND`. Without
 * `allowEnrolment` the user must own an OPAQUE credential (a legacy key-stretching profile is
 * fine: a reset replaces it); with it, a user without any OPAQUE account row qualifies too and
 * gets `credentialVersion: null`.
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
  const credential = readCredentialRow(opaqueAccount);
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

/**
 * What a valid reset token resolves to: the user, the credential unless it is an enrolment, and
 * the revocation marker the token carries.
 */
type ResetTarget = {
  userId: string;
  credential: OpaqueCredentialRow | null;
  revocation: string | null;
};

/**
 * Resolves the user and credential a reset token belongs to without consuming the token.
 * Unknown, expired, orphaned, revoked, and superseded tokens (the credential changed, or an
 * enrolment target gained an OPAQUE account row, after issuance) all fail with
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
  if (!value || !(await isUnrevoked(ctx, value.userId, value.revocation))) {
    throw invalidResetToken();
  }

  const accounts = await internalAdapter.findAccounts(value.userId);
  const opaqueAccount = accounts.find((account) => account.providerId === OPAQUE_PROVIDER_ID);

  if (value.credentialVersion === null) {
    // An enrolment link dies with any OPAQUE row, also one whose fields do not decode: completing
    // it could only fail, after the link was consumed.
    if (opaqueAccount || !(await internalAdapter.findUserById(value.userId))) {
      throw invalidResetToken();
    }
    return { userId: value.userId, credential: null, revocation: value.revocation };
  }

  const credential = readCredentialRow(opaqueAccount);
  if (credential?.credentialVersion !== value.credentialVersion) {
    throw invalidResetToken();
  }
  return { userId: value.userId, credential, revocation: value.revocation };
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
      if (ctx.body.revokePrevious) {
        await revokeResetLinks(ctx, subject.userId);
      }

      const token = randomToken();
      const expiresAt = new Date(Date.now() + passwordReset.expiresIn * 1000);
      const value: ResetTokenValue = {
        userId: subject.userId,
        credentialVersion: subject.credentialVersion,
        revocation: await currentRevocation(ctx, subject.userId),
      };
      await ctx.context.internalAdapter.createVerificationValue({
        identifier: await resetTokenIdentifier(token),
        value: JSON.stringify(value),
        expiresAt,
      });

      return { url: passwordReset.url(token), expiresAt };
    },
  );

  /**
   * Server-only (never routed over HTTP): invalidates every outstanding reset link, enrolment
   * links included, and every reset already started from one (its complete call fails with
   * `INVALID_RESET_TOKEN`), of the user with this email, for example when the app suspects the
   * mailbox was exposed. Unknown emails fail with `USER_NOT_FOUND` like
   * `createPasswordResetToken`. Links issued afterwards work normally.
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
      await revokeResetLinks(ctx, subject.userId);
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
        revocation: target.revocation,
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
      // A revocation since the link was issued also cancels a reset already started from it.
      if (!(await isUnrevoked(ctx, state.userId, state.revocation))) {
        throw invalidResetToken();
      }
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
