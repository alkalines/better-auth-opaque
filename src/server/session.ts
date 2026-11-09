import { BASE_ERROR_CODES, type GenericEndpointContext, type User } from "better-auth";
import { APIError } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import { OPAQUE_ERROR_CODES, type ChangePasswordResponse } from "../contract.ts";
import { findCredentialById } from "./credential.ts";

/**
 * Signs the caller in again after a credential change revoked every session of the user (change
 * password and attach). Sets the new session cookie, like Better Auth's `changePassword` with
 * `revokeOtherSessions`, and returns the endpoint response. A sign-in with "don't remember me"
 * keeps its short session lifetime, read from the signed `dont_remember` cookie.
 *
 * `credential` is the credential this flow just installed. If a later change or reset replaced it
 * in the meantime, the session is deleted and the call fails with `CREDENTIAL_CHANGED`, so a
 * superseded password never yields a usable session.
 */
export async function reissueSession(
  ctx: GenericEndpointContext,
  user: User,
  credential: { credentialId: string; credentialVersion: string },
): Promise<ChangePasswordResponse> {
  const dontRememberMe = Boolean(
    await ctx.getSignedCookie(ctx.context.authCookies.dontRememberToken.name, ctx.context.secret),
  );
  const session = await ctx.context.internalAdapter.createSession(user.id, dontRememberMe);
  if (!session) {
    throw APIError.from("INTERNAL_SERVER_ERROR", BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION);
  }

  // Same create-then-recheck as sign-in: a change or reset that replaces the credential switches
  // and then revokes sessions. If this re-check runs before that switch, the session already
  // exists and is revoked by it; if it runs after, it sees the new version and removes the
  // session itself.
  const current = await findCredentialById(ctx, credential.credentialId);
  if (current?.credentialVersion !== credential.credentialVersion) {
    await ctx.context.internalAdapter.deleteSession(session.token);
    throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
  }

  await setSessionCookie(ctx, { session, user }, dontRememberMe);
  return { status: true, token: session.token };
}
