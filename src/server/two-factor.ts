import { BASE_ERROR_CODES, type BetterAuthPlugin, type GenericEndpointContext } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  createAuthMiddleware,
  getSessionFromCtx,
  sensitiveSessionMiddleware,
} from "better-auth/api";
import { deleteSessionCookie } from "better-auth/cookies";
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

type PendingSignIn = {
  userId: string;
  credentialId: string;
  credentialVersion: string;
  sessionToken: string;
};

const managementPaths = [
  "/two-factor/enable",
  "/two-factor/disable",
  "/two-factor/get-totp-uri",
  "/two-factor/generate-backup-codes",
];

// Better Auth preserves this request-local context between the endpoint and its after-hooks.
const pendingSignIns = new WeakMap<object, PendingSignIn>();

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

/** One-use, hashed bearer tokens for deferred payloads and 2FA management authorization. */
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
    ],
    after: [
      {
        matcher: (ctx) => ctx.path === OPAQUE_PATHS.signInComplete,
        // Return the middleware envelope unchanged: dispatch must merge its cookies and response.
        handler: async (ctx) => {
          const context = ctx as GenericEndpointContext;
          if (!pendingSignIns.has(context.context)) return { response: undefined };
          const hook = twoFactorSignInHook(context);
          if (!hook) throw APIError.from("FORBIDDEN", OPAQUE_ERROR_CODES.TWO_FACTOR_NOT_SUPPORTED);
          return hook.handler(ctx);
        },
      },
      {
        matcher: (ctx) => ctx.path === OPAQUE_PATHS.signInComplete,
        handler: createAuthMiddleware(async (ctx) => {
          const state = pendingSignIns.get(ctx.context);
          if (!state) return;
          pendingSignIns.delete(ctx.context);
          const returned: unknown = ctx.context.returned;
          if (!returned || typeof returned !== "object") return;
          if ("twoFactorRedirect" in returned && returned.twoFactorRedirect === true) {
            const payloadToken = randomToken();
            const maxAge =
              ctx.context.getPlugin("two-factor")?.options?.twoFactorCookieMaxAge ?? 600;
            await ctx.context.internalAdapter.createVerificationValue({
              identifier: `opaque:two-factor-payload:${await sha256(payloadToken)}`,
              value: JSON.stringify({
                userId: state.userId,
                credentialId: state.credentialId,
                credentialVersion: state.credentialVersion,
              }),
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
      const state = JSON.parse(row.value) as Omit<PendingSignIn, "sessionToken">;
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
