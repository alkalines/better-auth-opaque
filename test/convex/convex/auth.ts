import { opaque } from "@alkalines/better-auth-opaque";
import { createClient, type GenericCtx } from "@convex-dev/better-auth";
import { convex } from "@convex-dev/better-auth/plugins";
import { betterAuth, type BetterAuthOptions } from "better-auth/minimal";
import { components, internal } from "./_generated/api";
import type { DataModel } from "./_generated/dataModel";
import authConfig from "./auth.config";
import authSchema from "./betterAuth/schema";

export const authComponent = createClient<DataModel, typeof authSchema>(components.betterAuth, {
  local: { schema: authSchema },
});

/** Payload hooks run inside HTTP actions only, where `runMutation`/`runQuery` exist. */
function requireActionCtx(ctx: GenericCtx<DataModel>) {
  if (!("runMutation" in ctx) || !("runQuery" in ctx)) {
    throw new Error("OPAQUE payload hooks need an action or mutation context");
  }
  return ctx;
}

/**
 * Better Auth options of the app. The OPAQUE plugin throws without `serverSetup`, so a deployment
 * missing `OPAQUE_SERVER_SETUP` fails to push instead of running with a generated setup.
 */
export const createAuthOptions = (
  ctx: GenericCtx<DataModel>,
  serverSetup: string | undefined = process.env.OPAQUE_SERVER_SETUP,
) => {
  return {
    baseURL: process.env.CONVEX_SITE_URL,
    trustedOrigins: [process.env.SITE_URL ?? "http://localhost:3000"],
    database: authComponent.adapter(ctx),
    // The tests drive many sign-ins per minute from one address.
    rateLimit: { enabled: false },
    plugins: [
      convex({ authConfig }),
      opaque({
        serverSetup: serverSetup!,
        hooks: {
          validatePayload: ({ payload }) => {
            if (typeof payload === "object" && payload !== null && "invalid" in payload) {
              throw new Error("payload rejected by the app");
            }
          },
          commitPayload: async ({ userId, credentialVersion, payload }) => {
            const { runMutation } = requireActionCtx(ctx);
            await runMutation(internal.payloads.commit, { userId, credentialVersion, payload });
          },
          activatePayload: async ({ userId, previousCredentialVersion }) => {
            const { runMutation } = requireActionCtx(ctx);
            await runMutation(internal.payloads.activate, { userId, previousCredentialVersion });
          },
          loadPayload: async ({ userId, credentialVersion }) => {
            // `null` only for enrolment reset links, which these tests do not issue.
            if (credentialVersion === null) return null;
            const { runQuery } = requireActionCtx(ctx);
            return await runQuery(internal.payloads.load, { userId, credentialVersion });
          },
        },
        passwordReset: {
          url: (token) => `${process.env.SITE_URL}/reset-password?token=${token}`,
        },
      }),
    ],
  } satisfies BetterAuthOptions;
};

/**
 * Placeholder for the two code paths that only read Better Auth's schema: the component adapter
 * (component modules cannot read the deployment's environment variables) and the schema
 * generation CLI (it runs without them). It is not a valid serenity setup, so a server that
 * somehow used it would fail closed with `INVALID_SERVER_SETUP`.
 */
const SCHEMA_ONLY_SERVER_SETUP = "schema-only: not a server setup";

/** Options for schema consumers; see {@link SCHEMA_ONLY_SERVER_SETUP}. */
export const createSchemaAuthOptions = (ctx: GenericCtx<DataModel>) =>
  createAuthOptions(ctx, SCHEMA_ONLY_SERVER_SETUP);

export const createAuth = (ctx: GenericCtx<DataModel>) => betterAuth(createAuthOptions(ctx));
