/**
 * Behavior the OPAQUE flows copy from Better Auth's email/password routes
 * (`better-auth/dist/api/routes/sign-up.mjs` and `sign-in.mjs`, 1.7.x) so that both sign-up paths
 * of one configuration reveal the same information about existing emails and treat email
 * verification the same way. Keep in sync when bumping the Better Auth peer range.
 */
import type { GenericEndpointContext, User } from "better-auth";
import { createEmailVerificationToken } from "better-auth/api";
import { buildSyntheticUserOutput, parseUserOutput } from "better-auth/db";

/**
 * Whether sign-up for an existing email must look like a successful sign-up without a session
 * (`requireEmailVerification` or `autoSignIn: false`). Otherwise Better Auth answers
 * `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`, revealing that the email exists; this is also when
 * new sign-ups skip the automatic session.
 */
export function hidesExistingEmails(ctx: GenericEndpointContext): boolean {
  const emailAndPassword = ctx.context.options.emailAndPassword;
  return (
    emailAndPassword?.requireEmailVerification === true || emailAndPassword?.autoSignIn === false
  );
}

/**
 * Response for a sign-up whose email already exists when {@link hidesExistingEmails} applies: a
 * synthetic user shaped like a real one (honoring `customSyntheticUser`) and no session token.
 */
export function syntheticSignUpResponse(
  ctx: GenericEndpointContext,
  input: {
    email: string;
    name: string;
    image: string | undefined;
    additionalFields: Record<string, unknown>;
  },
): { token: null; user: Record<string, unknown> } {
  const options = ctx.context.options;
  const now = new Date();
  const id = ctx.context.generateId({ model: "user" }) || crypto.randomUUID();
  const coreFields = {
    name: input.name,
    email: input.email,
    emailVerified: false,
    image: input.image ?? null,
    createdAt: now,
    updatedAt: now,
  };

  const customSyntheticUser = options.emailAndPassword?.customSyntheticUser;
  let syntheticUser: Record<string, unknown>;
  if (customSyntheticUser) {
    const additionalFields: Record<string, unknown> = {};
    for (const key of Object.keys(options.user?.additionalFields ?? {})) {
      if (key in input.additionalFields) {
        additionalFields[key] = input.additionalFields[key];
      }
    }
    syntheticUser = buildSyntheticUserOutput(
      options,
      customSyntheticUser({ coreFields, additionalFields, id }),
    );
  } else {
    syntheticUser = buildSyntheticUserOutput(options, {
      ...coreFields,
      ...input.additionalFields,
      id,
    });
  }

  return { token: null, user: parseUserOutput(options, syntheticUser as User) };
}

/** Sends Better Auth's verification email for `user`, exactly like email/password sign-up and sign-in. */
export async function sendVerificationEmail(
  ctx: GenericEndpointContext,
  user: User,
  callbackURL: string | undefined,
): Promise<void> {
  const send = ctx.context.options.emailVerification?.sendVerificationEmail;
  if (!send) {
    return;
  }

  const token = await createEmailVerificationToken(
    ctx.context.secret,
    user.email,
    undefined,
    ctx.context.options.emailVerification?.expiresIn,
    { userId: user.id },
  );
  const encodedCallbackURL = encodeURIComponent(callbackURL ?? "/");
  const url = `${ctx.context.baseURL}/verify-email?token=${token}&callbackURL=${encodedCallbackURL}`;
  await ctx.context.runInBackgroundOrAwait(send({ user, url, token }, ctx.request));
}
