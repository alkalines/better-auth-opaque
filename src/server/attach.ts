import { BASE_ERROR_CODES } from "better-auth";
import { APIError, createAuthEndpoint, sensitiveSessionMiddleware } from "better-auth/api";
import {
  OPAQUE_ERROR_CODES,
  OPAQUE_PATHS,
  OPAQUE_PROVIDER_ID,
  attachChallengeBodySchema,
  attachCompleteBodySchema,
  removeClassicCredentialBodySchema,
  type CredentialUpdateResponse,
} from "../contract.ts";
import {
  assertPayloadSupported,
  attachCredential,
  classicAccountFingerprint,
  findCredentialByUserId,
  removeClassicAccounts,
} from "./credential.ts";
import { randomToken } from "./crypto.ts";
import type { OpaqueRuntime } from "./runtime.ts";
import { reissueSession } from "./session.ts";
import { consumeState, createState } from "./state.ts";

/**
 * Migration of classic Better Auth email/password users to OPAQUE: `POST /opaque/attach/challenge`
 * and `/opaque/attach/complete` (session required), plus the server-only
 * `auth.api.removeClassicCredential`.
 *
 * The server already holds a hash of the classic password, so attach does not run an OPAQUE
 * login: the challenge verifies `currentPassword` against that hash (or, when the app set
 * `attach.requireCurrentPassword: false`, accepts a session younger than
 * `attach.freshSessionAge`). The complete call registers the first OPAQUE credential, removes the
 * classic password (option `removeClassicCredential`), revokes every session, and signs the
 * caller in again with a new session, like change-password.
 *
 * Because the server learned the classic password, the client must not reuse it as the OPAQUE
 * password (`PASSWORD_REUSED`); a password the server has seen would let it derive the export key.
 */
export function attachEndpoints(runtime: OpaqueRuntime) {
  const opaqueAttachChallenge = createAuthEndpoint(
    OPAQUE_PATHS.attachChallenge,
    {
      method: "POST",
      body: attachChallengeBodySchema,
      use: [sensitiveSessionMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const { session, user } = ctx.context.session;
      await runtime.checkAccountRateLimit(ctx, user.email, "attach");

      // Any OPAQUE row blocks attach, including one that fails to decode.
      const { internalAdapter } = ctx.context;
      const accounts = await internalAdapter.findAccounts(user.id);
      if (accounts.some((account) => account.providerId === OPAQUE_PROVIDER_ID)) {
        throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS);
      }
      const classic = await internalAdapter.findCredentialAccount(user.id);
      if (!classic?.password) {
        throw APIError.from("BAD_REQUEST", BASE_ERROR_CODES.CREDENTIAL_ACCOUNT_NOT_FOUND);
      }

      const { currentPassword, registrationRequest } = ctx.body;
      if (currentPassword !== undefined) {
        const verified = await ctx.context.password.verify({
          hash: classic.password,
          password: currentPassword,
        });
        if (!verified) {
          throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_PASSWORD);
        }
      } else if (runtime.attach.requireCurrentPassword) {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_PASSWORD);
      } else if (
        Date.now() - new Date(session.createdAt).getTime() >
        runtime.attach.freshSessionAge * 1000
      ) {
        throw APIError.from("FORBIDDEN", BASE_ERROR_CODES.SESSION_NOT_FRESH);
      }

      const credentialId = randomToken();
      const registrationResponse = await runtime.createRegistrationResponse(
        credentialId,
        registrationRequest,
      );
      const stateId = await createState(ctx, "attach", {
        userId: user.id,
        credentialId,
        classicFingerprint: await classicAccountFingerprint(classic),
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

  const opaqueAttachComplete = createAuthEndpoint(
    OPAQUE_PATHS.attachComplete,
    {
      method: "POST",
      body: attachCompleteBodySchema,
      use: [sensitiveSessionMiddleware],
      metadata: { scope: "server" },
    },
    async (ctx) => {
      await runtime.requireServerPublicKey();
      const { stateId, registrationRecord, payload } = ctx.body;
      const { user } = ctx.context.session;
      assertPayloadSupported(runtime.hooks, payload);

      const state = await consumeState(ctx, "attach", stateId);
      if (state.userId !== user.id) {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_STATE);
      }

      const credentialVersion = await attachCredential(ctx, runtime, {
        flow: "attach",
        userId: user.id,
        credentialId: state.credentialId,
        registrationRecord,
        keyStretching: state.keyStretching,
        payload,
        classicFingerprint: state.classicFingerprint,
      });

      return ctx.json(
        await reissueSession(ctx, user, { credentialId: state.credentialId, credentialVersion }),
      );
    },
  );

  /**
   * Server-only (never routed over HTTP): deletes the user's classic `credential` accounts, but
   * only once the user has an OPAQUE credential (`OPAQUE_ACCOUNT_NOT_FOUND` otherwise). Use it
   * to finish a migration that ran with `removeClassicCredential: false`.
   */
  const removeClassicCredential = createAuthEndpoint.serverOnly(
    {
      method: "POST",
      body: removeClassicCredentialBodySchema,
      metadata: { SERVER_ONLY: true },
    },
    async (ctx): Promise<CredentialUpdateResponse> => {
      await runtime.requireServerPublicKey();
      if (!(await findCredentialByUserId(ctx, ctx.body.userId))) {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_NOT_FOUND);
      }
      await removeClassicAccounts(ctx, ctx.body.userId);
      return { status: true };
    },
  );

  return { opaqueAttachChallenge, opaqueAttachComplete, removeClassicCredential };
}
