import { BASE_ERROR_CODES, type GenericEndpointContext, type User } from "better-auth";
import { APIError } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import type { ChangePasswordResponse } from "../contract.ts";

/**
 * Signs the caller in again after a credential change revoked every session of the user (change
 * password and attach). Sets the new session cookie, like Better Auth's `changePassword` with
 * `revokeOtherSessions`, and returns the endpoint response. A sign-in with "don't remember me"
 * keeps its short session lifetime, read from the signed `dont_remember` cookie.
 */
export async function reissueSession(
  ctx: GenericEndpointContext,
  user: User,
): Promise<ChangePasswordResponse> {
  const dontRememberMe = Boolean(
    await ctx.getSignedCookie(ctx.context.authCookies.dontRememberToken.name, ctx.context.secret),
  );
  const session = await ctx.context.internalAdapter.createSession(user.id, dontRememberMe);
  if (!session) {
    throw APIError.from("INTERNAL_SERVER_ERROR", BASE_ERROR_CODES.FAILED_TO_CREATE_SESSION);
  }
  await setSessionCookie(ctx, { session, user }, dontRememberMe);
  return { status: true, token: session.token };
}
