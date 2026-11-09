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
import { findCredentialById, findCredentialByUserId, readCredential } from "./credential.ts";
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

/**
 * The passwords a user could prove when a second-factor challenge was issued: a hash of the
 * classic password hash (`null` without one) and the OPAQUE credential version (`null` without
 * one). Any change, reset, attach or removal of either changes the snapshot.
 */
type CredentialSnapshot = {
  userId: string;
  classicFingerprint: string | null;
  opaqueVersion: string | null;
};

/** A verification row written for an authenticated user of the request while recording. */
type NativeGrant = { identifier: string; userId: string; expiresAt: Date };

/** What native code granted while a {@link recordNativeGrants} recording ran. */
type NativeGrants = {
  /** Verification rows written with an authenticated user's id as value: challenges, trusted devices. */
  verifications: NativeGrant[];
  /** Resolved names of the auth cookies the code asked for. */
  cookies: string[];
  /** Stored password hashes a `password.verify` call accepted: what a first factor was proven against. */
  verifiedHashes: string[];
  /** Ends the recording and restores the request context. */
  stop: () => void;
};

/** A native second-factor challenge this request acts on. */
type PendingChallenge = {
  /** The native identifier (`2fa-*`), the value of the signed `two_factor` cookie. */
  challenge: string;
  markerKey: string;
  /** `null` when the challenge was never bound, or bound to another user: it is refused. */
  snapshot: CredentialSnapshot | null;
};

// Better Auth preserves this request-local context between the endpoint and its hooks.
const pendingSignIns = new WeakMap<object, PendingSignIn>();
const issuedChallenges = new WeakMap<object, { challenge: string | null; stop: () => void }>();
const pendingVerifications = new WeakMap<
  object,
  { pending: PendingChallenge & { snapshot: CredentialSnapshot }; grants: NativeGrants }
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
 * Records, until `stop`, the verification rows Better Auth writes with an authenticated user's id
 * as value (`userId`, and every user a session is created for while recording), the auth cookie
 * names it resolves, and the password hashes it verifies a password against; `onGrant` runs right
 * after each such row is written. Native two-factor code keeps its identifiers to itself, and its
 * `setSignedCookie` belongs to a context better-call rebuilds for every middleware call, so the
 * recording wraps the members of the auth context that code reaches them through instead.
 * `context` must be the request's own auth context: dispatch spreads the shared one per request,
 * so replacing (never mutating) its members keeps the wrappers inside the request.
 */
function recordNativeGrants(
  context: GenericEndpointContext["context"],
  input: {
    userId?: string;
    onGrant?: (grant: NativeGrant, grants: NativeGrants) => Promise<void>;
  },
): NativeGrants {
  const { internalAdapter, createAuthCookie, password } = context;
  const userIds = new Set(input.userId === undefined ? [] : [input.userId]);
  const grants: NativeGrants = {
    verifications: [],
    cookies: [],
    verifiedHashes: [],
    stop: () => {
      context.internalAdapter = internalAdapter;
      context.createAuthCookie = createAuthCookie;
      context.password = password;
    },
  };
  context.password = {
    ...password,
    verify: async (data) => {
      const verified = await password.verify(data);
      if (verified) grants.verifiedHashes.push(data.hash);
      return verified;
    },
  };
  context.internalAdapter = {
    ...internalAdapter,
    createSession: async (...args) => {
      const session = await internalAdapter.createSession(...args);
      userIds.add(session.userId);
      return session;
    },
    createVerificationValue: async (data) => {
      const row = await internalAdapter.createVerificationValue(data);
      if (userIds.has(data.value)) {
        const grant = {
          identifier: data.identifier,
          userId: data.value,
          expiresAt: data.expiresAt,
        };
        grants.verifications.push(grant);
        await input.onGrant?.(grant, grants);
      }
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

async function takeCredentialSnapshot(
  ctx: GenericEndpointContext,
  userId: string,
): Promise<CredentialSnapshot> {
  const accounts = await ctx.context.internalAdapter.findAccounts(userId);
  const classic = accounts.find((account) => account.providerId === "credential");
  const opaque = readCredential(
    accounts.find((account) => account.providerId === OPAQUE_PROVIDER_ID),
  );
  return {
    userId,
    classicFingerprint: classic?.password ? await sha256(classic.password) : null,
    opaqueVersion: opaque?.credentialVersion ?? null,
  };
}

async function challengeMarkerKey(challenge: string): Promise<string> {
  return `opaque:two-factor-pending:${await sha256(challenge)}`;
}

/**
 * Binds the challenge the native gate issues later in this request to the user's credential
 * snapshot, writing `opaque:two-factor-pending:<sha256(challenge)>` → {@link CredentialSnapshot}
 * with the challenge's expiry the moment the gate writes its row. The snapshot holds what the
 * first factor was proven against where this request shows it: the OPAQUE version the sign-in
 * proved (`opaqueVersion`), and the classic hash a single `password.verify` accepted. So a change
 * landing between that proof and the challenge leaves the challenge stale. The gate resolves its
 * `two_factor` cookie right before writing the challenge; a trusted device's row comes without it.
 * `challenge` is set once bound; the recording stops itself then.
 */
function bindIssuedChallenge(
  ctx: GenericEndpointContext,
  input: { userId?: string; opaqueVersion?: string },
): { challenge: string | null; stop: () => void } {
  const challengeCookie = ctx.context.createAuthCookie(TWO_FACTOR_COOKIE).name;
  const issued = { challenge: null as string | null, stop: () => {} };
  const grants = recordNativeGrants(ctx.context, {
    userId: input.userId,
    onGrant: async (grant, recorded) => {
      if (issued.challenge !== null || !recorded.cookies.includes(challengeCookie)) return;
      recorded.stop();
      const snapshot = await takeCredentialSnapshot(ctx, grant.userId);
      if (input.opaqueVersion !== undefined) snapshot.opaqueVersion = input.opaqueVersion;
      const [verifiedHash] = recorded.verifiedHashes;
      if (recorded.verifiedHashes.length === 1 && verifiedHash !== undefined) {
        snapshot.classicFingerprint = await sha256(verifiedHash);
      }
      await ctx.context.internalAdapter.createVerificationValue({
        identifier: await challengeMarkerKey(grant.identifier),
        value: JSON.stringify(snapshot),
        expiresAt: grant.expiresAt,
      });
      issued.challenge = grant.identifier;
    },
  });
  issued.stop = grants.stop;
  return issued;
}

/**
 * Loads the native challenge named by this request's signed `two_factor` cookie and its snapshot.
 * `null` without a valid cookie (a session-bound verify) or once the challenge is gone, which the
 * native endpoint refuses itself.
 */
async function findPendingChallenge(ctx: GenericEndpointContext): Promise<PendingChallenge | null> {
  const cookieName = ctx.context.createAuthCookie(TWO_FACTOR_COOKIE).name;
  const challenge = await ctx.getSignedCookie(cookieName, ctx.context.secret);
  if (!challenge) return null;
  const row = await ctx.context.internalAdapter.findVerificationValue(challenge);
  if (!row) return null;
  const markerKey = await challengeMarkerKey(challenge);
  const marker = await ctx.context.internalAdapter.findVerificationValue(markerKey);
  const snapshot = marker ? (JSON.parse(marker.value) as CredentialSnapshot) : null;
  return {
    challenge,
    markerKey,
    snapshot: snapshot?.userId === row.value ? snapshot : null,
  };
}

async function isCredentialReplaced(
  ctx: GenericEndpointContext,
  snapshot: CredentialSnapshot,
): Promise<boolean> {
  const current = await takeCredentialSnapshot(ctx, snapshot.userId);
  return (
    current.classicFingerprint !== snapshot.classicFingerprint ||
    current.opaqueVersion !== snapshot.opaqueVersion
  );
}

/**
 * One-use, hashed bearer tokens for deferred payloads and 2FA management authorization, and the
 * credential binding of pending second-factor sign-ins.
 *
 * The native gate stores its challenge (`2fa-*` → user id) without knowing which password proved
 * the first factor, and finishes it without asking this plugin. Every challenge it issues, for
 * OPAQUE and native sign-ins alike, is therefore bound to a {@link CredentialSnapshot}; the
 * challenge hooks refuse to deliver a code for a challenge, finish it, or keep its session once
 * the snapshot no longer matches, and refuse unbound challenges outright.
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
        // Native sign-ins the gate may challenge; the OPAQUE sign-in binds its own in an after-hook.
        matcher: (ctx) =>
          ctx.path !== OPAQUE_PATHS.signInComplete &&
          twoFactorSignInHook(ctx)?.matcher(ctx) === true,
        handler: createAuthMiddleware(async (ctx) => {
          bindIssuedChallenge(ctx, {});
        }),
      },
      {
        matcher: (ctx) => challengePaths.includes(ctx.path ?? ""),
        handler: createAuthMiddleware(async (ctx) => {
          const pending = await findPendingChallenge(ctx);
          if (!pending) return;
          const { snapshot } = pending;
          if (!snapshot || (await isCredentialReplaced(ctx, snapshot))) {
            // Retire the challenge so the second factor can no longer finish it, not even by retry.
            await ctx.context.internalAdapter.deleteVerificationByIdentifier(pending.challenge);
            await ctx.context.internalAdapter.deleteVerificationByIdentifier(pending.markerKey);
            expireCookie(ctx, ctx.context.createAuthCookie(TWO_FACTOR_COOKIE));
            throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
          }
          if (!challengeVerifyPaths.includes(ctx.path)) return;
          // The after-hook revokes what this verify grants if the password is replaced meanwhile.
          const grants = recordNativeGrants(ctx.context, { userId: snapshot.userId });
          pendingVerifications.set(ctx.context, { pending: { ...pending, snapshot }, grants });
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
          const issued = bindIssuedChallenge(context, {
            userId: state.userId,
            opaqueVersion: state.credentialVersion,
          });
          issuedChallenges.set(context.context, issued);
          try {
            return await hook.handler(ctx);
          } finally {
            issued.stop();
          }
        },
      },
      {
        matcher: (ctx) => ctx.path === OPAQUE_PATHS.signInComplete,
        handler: createAuthMiddleware(async (ctx) => {
          const state = pendingSignIns.get(ctx.context);
          if (!state) return;
          pendingSignIns.delete(ctx.context);
          const issued = issuedChallenges.get(ctx.context);
          issuedChallenges.delete(ctx.context);
          const returned: unknown = ctx.context.returned;
          if (!returned || typeof returned !== "object") return;
          if ("twoFactorRedirect" in returned && returned.twoFactorRedirect === true) {
            // A challenge that cannot be bound must not be handed out.
            if (!issued?.challenge) {
              throw APIError.from("FORBIDDEN", OPAQUE_ERROR_CODES.TWO_FACTOR_NOT_SUPPORTED);
            }
            const maxAge =
              ctx.context.getPlugin("two-factor")?.options?.twoFactorCookieMaxAge ?? 600;
            const payloadToken = randomToken();
            await ctx.context.internalAdapter.createVerificationValue({
              identifier: `opaque:two-factor-payload:${await sha256(payloadToken)}`,
              value: JSON.stringify({
                userId: state.userId,
                credentialId: state.credentialId,
                credentialVersion: state.credentialVersion,
              } satisfies CredentialBinding),
              expiresAt: new Date(Date.now() + maxAge * 1000),
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
          await ctx.context.internalAdapter.deleteVerificationByIdentifier(pending.markerKey);

          // Same create-then-recheck as OPAQUE sign-in: a change, reset or attach that replaced
          // the password after the before-hook either revokes this session or is seen here.
          const created = ctx.context.newSession;
          if (!created || !(await isCredentialReplaced(ctx, pending.snapshot))) return;
          await ctx.context.internalAdapter.deleteSession(created.session.token);
          deleteSessionCookie(ctx);
          ctx.context.setNewSession(null);
          // `trustDevice: true` also trusted this device; revoke it so the replaced password does
          // not leave a device that skips the second factor.
          for (const grant of grants.verifications) {
            await ctx.context.internalAdapter.deleteVerificationByIdentifier(grant.identifier);
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
