import { BASE_ERROR_CODES, type BetterAuthPlugin, type GenericEndpointContext } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  getSessionFromCtx,
  sensitiveSessionMiddleware,
} from "better-auth/api";
import { deleteSessionCookie, expireCookie } from "better-auth/cookies";
import {
  OPAQUE_ERROR_CODES,
  OPAQUE_PATHS,
  OPAQUE_PROVIDER_ID,
  passwordProofChallengeBodySchema,
  passwordProofCompleteBodySchema,
  signInPayloadBodySchema,
} from "../contract.ts";
import { findCredentialById, findCredentialByUserId } from "./credential.ts";
import { randomToken, sha256 } from "./crypto.ts";
import type { OpaqueRuntime } from "./runtime.ts";
import { consumeState, createState } from "./state.ts";

/** The credential a first factor was proven against. */
type CredentialBinding = {
  userId: string;
  credentialId: string;
  credentialVersion: string;
};

type PendingSignIn = CredentialBinding & { sessionToken: string };

const managementPaths = [
  "/two-factor/enable",
  "/two-factor/disable",
  "/two-factor/get-totp-uri",
  "/two-factor/generate-backup-codes",
];

// Native endpoints that turn a pending `two_factor` cookie challenge into a session.
const challengeVerifyPaths = [
  "/two-factor/verify-totp",
  "/two-factor/verify-otp",
  "/two-factor/verify-backup-code",
];

// Native endpoints that act on a pending challenge: finishing it, or delivering a code for it.
const challengePaths = [...challengeVerifyPaths, "/two-factor/send-otp"];

// Better Auth's `TWO_FACTOR_COOKIE_NAME` and `TRUST_DEVICE_COOKIE_NAME`, which it does not export.
const TWO_FACTOR_COOKIE = "two_factor";
const TRUST_DEVICE_COOKIE = "trust_device";

/** What native two-factor code granted one user while a {@link recordNativeGrants} recording ran. */
type NativeGrants = {
  /** Identifiers of verification rows written with the user's id as value: challenges, trusted devices. */
  verifications: string[];
  /** Resolved names of the auth cookies the code asked for. */
  cookies: string[];
  /** Ends the recording and restores the request context. */
  stop: () => void;
};

/** A native second-factor challenge this request acts on, and what proved its first factor. */
type PendingChallenge = {
  /** The native identifier (`2fa-*`), the value of the signed `two_factor` cookie. */
  challenge: string;
  userId: string;
  issuedAt: Date;
  /** Set for OPAQUE sign-ins only; other sign-in methods proved a password this plugin never saw. */
  marker: { key: string; binding: CredentialBinding } | null;
};

// Better Auth preserves this request-local context between the endpoint and its hooks.
const pendingSignIns = new WeakMap<object, PendingSignIn>();
const signInGrants = new WeakMap<object, NativeGrants>();
const pendingVerifications = new WeakMap<
  object,
  { pending: PendingChallenge; grants: NativeGrants }
>();

/** Defers payload release until Better Auth's own second-factor gate has run. */
export function rememberTwoFactorSignIn(ctx: GenericEndpointContext, value: PendingSignIn): void {
  pendingSignIns.set(ctx.context, value);
}

/** Locate the installed plugin's gate rather than copying its trust-device and challenge policy. */
export function twoFactorSignInHook(ctx: Pick<GenericEndpointContext, "context">) {
  const plugin = ctx.context.getPlugin("two-factor");
  return plugin?.hooks?.after?.find((hook) =>
    hook.matcher({ path: "/sign-in/email", context: ctx.context }),
  );
}

/**
 * Records, until `stop`, the verification rows Better Auth writes with `userId` as value and the
 * auth cookie names it resolves. Native two-factor code keeps its identifiers to itself, and its
 * `setSignedCookie` belongs to a context better-call rebuilds for every middleware call, so the
 * recording wraps the two members of the auth context that code reaches them through instead.
 * `context` must be the request's own auth context: dispatch spreads the shared one per request,
 * so the wrappers never outlive or leak out of the request.
 */
function recordNativeGrants(
  context: GenericEndpointContext["context"],
  userId: string,
): NativeGrants {
  const { internalAdapter, createAuthCookie } = context;
  const grants: NativeGrants = {
    verifications: [],
    cookies: [],
    stop: () => {
      context.internalAdapter = internalAdapter;
      context.createAuthCookie = createAuthCookie;
    },
  };
  context.internalAdapter = {
    ...internalAdapter,
    createVerificationValue: async (data) => {
      const row = await internalAdapter.createVerificationValue(data);
      if (data.value === userId) grants.verifications.push(data.identifier);
      return row;
    },
  };
  context.createAuthCookie = (name, attributes) => {
    const cookie = createAuthCookie(name, attributes);
    grants.cookies.push(cookie.name);
    return cookie;
  };
  return grants;
}

/**
 * Loads the native challenge named by this request's signed `two_factor` cookie. `null` without a
 * valid cookie (a session-bound verify) or once the challenge is gone, which the native endpoint
 * refuses itself.
 */
async function findPendingChallenge(ctx: GenericEndpointContext): Promise<PendingChallenge | null> {
  const cookieName = ctx.context.createAuthCookie(TWO_FACTOR_COOKIE).name;
  const challenge = await ctx.getSignedCookie(cookieName, ctx.context.secret);
  if (!challenge) return null;
  const row = await ctx.context.internalAdapter.findVerificationValue(challenge);
  if (!row) return null;
  const key = `opaque:two-factor-pending:${await sha256(challenge)}`;
  const marker = await ctx.context.internalAdapter.findVerificationValue(key);
  return {
    challenge,
    userId: row.value,
    issuedAt: new Date(row.createdAt),
    marker: marker ? { key, binding: JSON.parse(marker.value) as CredentialBinding } : null,
  };
}

/**
 * Whether the password that proved the challenge's first factor may have been replaced. OPAQUE
 * sign-ins are bound exactly to their credential version. Other sign-in methods (a classic password)
 * are refused once the user's OPAQUE credential was created or switched at or after the challenge
 * was issued (attach, enrolment reset, change, reset all set the account's `updatedAt`); this
 * fallback compares server clocks.
 */
async function isCredentialReplaced(
  ctx: GenericEndpointContext,
  pending: PendingChallenge,
): Promise<boolean> {
  if (pending.marker) {
    const { credentialId, credentialVersion } = pending.marker.binding;
    const credential = await findCredentialById(ctx, credentialId);
    return credential?.credentialVersion !== credentialVersion;
  }
  const accounts = await ctx.context.internalAdapter.findAccounts(pending.userId);
  const opaqueAccount = accounts.find((account) => account.providerId === OPAQUE_PROVIDER_ID);
  if (!opaqueAccount) return false;
  return new Date(opaqueAccount.updatedAt).getTime() >= pending.issuedAt.getTime();
}

/**
 * One-use, hashed bearer tokens for deferred payloads and 2FA management authorization, and the
 * credential binding of pending second-factor sign-ins.
 *
 * The native gate stores its challenge (`2fa-*` → user id) without knowing which password proved
 * the first factor, and finishes it without asking this plugin. The OPAQUE sign-in hook therefore
 * stores `opaque:two-factor-pending:<sha256(challenge)>` → {@link CredentialBinding}; the challenge
 * hooks refuse to deliver a code for a challenge, finish it, or keep its session once the password
 * behind it was replaced (see {@link isCredentialReplaced}).
 */
export function twoFactorIntegration(runtime: OpaqueRuntime) {
  const hooks: NonNullable<BetterAuthPlugin["hooks"]> = {
    before: [
      {
        matcher: (ctx) => managementPaths.includes(ctx.path ?? ""),
        handler: createAuthMiddleware(async (ctx) => {
          const session = await getSessionFromCtx(ctx, { disableCookieCache: true });
          if (!session) return;
          const accounts = await ctx.context.internalAdapter.findAccounts(session.user.id);
          if (accounts.some((account) => account.providerId === "credential" && account.password)) {
            return;
          }
          if (!accounts.some((account) => account.providerId === OPAQUE_PROVIDER_ID)) return;
          const password: unknown = ctx.body?.password;
          if (typeof password !== "string" || password.length > 128) {
            throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_PASSWORD);
          }
          const row = await ctx.context.internalAdapter.consumeVerificationValue(
            `opaque:password-proof:${await sha256(password)}`,
          );
          if (!row) throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_PASSWORD);
          const proof = JSON.parse(row.value) as { userId: string; credentialVersion: string };
          const credential = await findCredentialByUserId(ctx, session.user.id);
          if (
            proof.userId !== session.user.id ||
            !credential ||
            credential.credentialVersion !== proof.credentialVersion
          ) {
            throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.INVALID_PASSWORD);
          }
        }),
      },
      {
        matcher: (ctx) => challengePaths.includes(ctx.path ?? ""),
        handler: createAuthMiddleware(async (ctx) => {
          const pending = await findPendingChallenge(ctx);
          if (!pending) return;
          if (await isCredentialReplaced(ctx, pending)) {
            // Retire the challenge so the second factor can no longer finish it, not even by retry.
            await ctx.context.internalAdapter.deleteVerificationByIdentifier(pending.challenge);
            if (pending.marker) {
              await ctx.context.internalAdapter.deleteVerificationByIdentifier(pending.marker.key);
            }
            expireCookie(ctx, ctx.context.createAuthCookie(TWO_FACTOR_COOKIE));
            throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
          }
          if (!challengeVerifyPaths.includes(ctx.path)) return;
          // The after-hook revokes what this verify grants if the password is replaced meanwhile.
          const grants = recordNativeGrants(ctx.context, pending.userId);
          pendingVerifications.set(ctx.context, { pending, grants });
        }),
      },
    ],
    after: [
      {
        matcher: (ctx) => ctx.path === OPAQUE_PATHS.signInComplete,
        // Return the middleware envelope unchanged: dispatch must merge its cookies and response.
        handler: async (ctx) => {
          const context = ctx as GenericEndpointContext;
          const state = pendingSignIns.get(context.context);
          if (!state) return { response: undefined };
          const hook = twoFactorSignInHook(context);
          if (!hook) throw APIError.from("FORBIDDEN", OPAQUE_ERROR_CODES.TWO_FACTOR_NOT_SUPPORTED);
          const grants = recordNativeGrants(context.context, state.userId);
          signInGrants.set(context.context, grants);
          try {
            return await hook.handler(ctx);
          } finally {
            grants.stop();
          }
        },
      },
      {
        matcher: (ctx) => ctx.path === OPAQUE_PATHS.signInComplete,
        handler: createAuthMiddleware(async (ctx) => {
          const state = pendingSignIns.get(ctx.context);
          if (!state) return;
          pendingSignIns.delete(ctx.context);
          const grants = signInGrants.get(ctx.context);
          signInGrants.delete(ctx.context);
          const returned: unknown = ctx.context.returned;
          if (!returned || typeof returned !== "object") return;
          if ("twoFactorRedirect" in returned && returned.twoFactorRedirect === true) {
            const maxAge =
              ctx.context.getPlugin("two-factor")?.options?.twoFactorCookieMaxAge ?? 600;
            const expiresAt = new Date(Date.now() + maxAge * 1000);
            const binding = JSON.stringify({
              userId: state.userId,
              credentialId: state.credentialId,
              credentialVersion: state.credentialVersion,
            } satisfies CredentialBinding);

            // The challenge is the one row the gate granted this user, under the cookie name the
            // challenge hooks read back. Anything else means the gate's mechanics changed, and a
            // challenge that cannot be bound must not be handed out.
            const challenges: string[] = [];
            const cookieName = ctx.context.createAuthCookie(TWO_FACTOR_COOKIE).name;
            if (grants?.cookies.includes(cookieName)) {
              for (const identifier of grants.verifications) {
                const row = await ctx.context.internalAdapter.findVerificationValue(identifier);
                if (row?.value === state.userId) challenges.push(identifier);
              }
            }
            const [challenge] = challenges;
            if (challenges.length !== 1 || !challenge) {
              throw APIError.from("FORBIDDEN", OPAQUE_ERROR_CODES.TWO_FACTOR_NOT_SUPPORTED);
            }
            await ctx.context.internalAdapter.createVerificationValue({
              identifier: `opaque:two-factor-pending:${await sha256(challenge)}`,
              value: binding,
              expiresAt,
            });

            const payloadToken = randomToken();
            await ctx.context.internalAdapter.createVerificationValue({
              identifier: `opaque:two-factor-payload:${await sha256(payloadToken)}`,
              value: binding,
              expiresAt,
            });
            return ctx.json({ ...returned, payloadToken });
          }
          // A hook error is not a trusted-device success, even if newSession still exists.
          if (
            !("token" in returned) ||
            returned.token !== state.sessionToken ||
            ctx.context.newSession?.session.token !== state.sessionToken
          )
            return;
          try {
            const payload =
              (await runtime.hooks.loadPayload?.(
                {
                  userId: state.userId,
                  credentialVersion: state.credentialVersion,
                  flow: "sign-in",
                },
                ctx,
              )) ?? null;
            return ctx.json({ ...returned, payload });
          } catch (error) {
            await ctx.context.internalAdapter.deleteSession(state.sessionToken);
            deleteSessionCookie(ctx);
            ctx.context.setNewSession(null);
            throw error;
          }
        }),
      },
      {
        matcher: (ctx) => challengeVerifyPaths.includes(ctx.path ?? ""),
        handler: createAuthMiddleware(async (ctx) => {
          const verification = pendingVerifications.get(ctx.context);
          if (!verification) return;
          pendingVerifications.delete(ctx.context);
          const { pending, grants } = verification;
          grants.stop();
          // A session-bound verify (enabling 2FA) or a wrong code leaves the challenge, and so its
          // marker, alive.
          if (await ctx.context.internalAdapter.findVerificationValue(pending.challenge)) return;
          if (pending.marker) {
            await ctx.context.internalAdapter.deleteVerificationByIdentifier(pending.marker.key);
          }

          // Same create-then-recheck as OPAQUE sign-in: a change, reset or attach that replaced
          // the password after the before-hook either revokes this session or is seen here.
          const created = ctx.context.newSession;
          if (!created || !(await isCredentialReplaced(ctx, pending))) return;
          await ctx.context.internalAdapter.deleteSession(created.session.token);
          deleteSessionCookie(ctx);
          ctx.context.setNewSession(null);
          // `trustDevice: true` also trusted this device; revoke it so the replaced password does
          // not leave a device that skips the second factor.
          for (const identifier of grants.verifications) {
            await ctx.context.internalAdapter.deleteVerificationByIdentifier(identifier);
          }
          if (grants.verifications.length > 0) {
            expireCookie(ctx, ctx.context.createAuthCookie(TRUST_DEVICE_COOKIE));
          }
          throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
        }),
      },
    ],
  };

  const opaqueSignInPayload = createAuthEndpoint(
    OPAQUE_PATHS.signInPayload,
    {
      method: "POST",
      body: signInPayloadBodySchema,
      use: [sensitiveSessionMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const row = await ctx.context.internalAdapter.consumeVerificationValue(
        `opaque:two-factor-payload:${await sha256(ctx.body.payloadToken)}`,
      );
      if (!row) throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_STATE);
      const state = JSON.parse(row.value) as CredentialBinding;
      const session = ctx.context.session;
      if (
        session.user.id !== state.userId ||
        session.session.createdAt.getTime() < new Date(row.createdAt).getTime()
      ) {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_STATE);
      }
      const credential = await findCredentialById(ctx, state.credentialId);
      if (!credential || credential.credentialVersion !== state.credentialVersion) {
        throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
      }
      const payload =
        (await runtime.hooks.loadPayload?.(
          { userId: state.userId, credentialVersion: state.credentialVersion, flow: "sign-in" },
          ctx,
        )) ?? null;
      return ctx.json({ payload });
    },
  );

  const opaquePasswordProofChallenge = createAuthEndpoint(
    OPAQUE_PATHS.passwordProofChallenge,
    {
      method: "POST",
      body: passwordProofChallengeBodySchema,
      use: [sensitiveSessionMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      await runtime.checkAccountRateLimit(ctx, ctx.context.session.user.email, "password-proof");
      const userId = ctx.context.session.user.id;
      const credential = await findCredentialByUserId(ctx, userId);
      if (!credential)
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_NOT_FOUND);
      const { serverLoginState, loginResponse } = await runtime.startLogin(
        credential.credentialId,
        credential.registrationRecord,
        ctx.body.loginRequest,
      );
      const stateId = await createState(ctx, "password-proof", {
        userId,
        credentialId: credential.credentialId,
        credentialVersion: credential.credentialVersion,
        serverLoginState,
      });
      return ctx.json({
        stateId,
        loginResponse,
        keyStretching: credential.keyStretching,
        ...runtime.challengeIdentity,
      });
    },
  );

  const opaquePasswordProofComplete = createAuthEndpoint(
    OPAQUE_PATHS.passwordProofComplete,
    {
      method: "POST",
      body: passwordProofCompleteBodySchema,
      use: [sensitiveSessionMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const state = await consumeState(ctx, "password-proof", ctx.body.stateId);
      const credential = await findCredentialById(ctx, state.credentialId);
      if (
        state.userId !== ctx.context.session.user.id ||
        !credential ||
        credential.credentialVersion !== state.credentialVersion ||
        !(await runtime.verifyLogin(state.serverLoginState, ctx.body.loginFinalization))
      ) {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_PASSWORD);
      }
      const proof = randomToken();
      await ctx.context.internalAdapter.createVerificationValue({
        identifier: `opaque:password-proof:${await sha256(proof)}`,
        value: JSON.stringify({ userId: state.userId, credentialVersion: state.credentialVersion }),
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      });
      return ctx.json({ proof });
    },
  );

  return {
    hooks,
    endpoints: { opaqueSignInPayload, opaquePasswordProofChallenge, opaquePasswordProofComplete },
  };
}
