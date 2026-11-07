import { v } from "convex/values";
import { components } from "./_generated/api";
import { internalAction, internalQuery } from "./_generated/server";
import { createAuth } from "./auth";

/**
 * Server-only token creation for the tests. `auth.api.createPasswordResetToken` is Better Auth
 * `SERVER_ONLY`, so it is reachable only through this internal action (callable with an admin
 * key or the Convex CLI, never over HTTP).
 */
export const createPasswordResetToken = internalAction({
  args: { email: v.string() },
  handler: async (ctx, args): Promise<{ url: string; expiresAt: string }> => {
    const auth = createAuth(ctx);
    const { url, expiresAt } = await auth.api.createPasswordResetToken({
      body: { email: args.email },
    });
    // Convex values cannot carry a Date.
    return { url, expiresAt: expiresAt.toISOString() };
  },
});

/** Boot check from the contract: resolves the server public key for the configured setup. */
export const validateOpaqueSetup = internalAction({
  args: {},
  handler: async (ctx): Promise<{ publicKey: string }> => {
    const auth = createAuth(ctx);
    return await auth.api.validateOpaqueSetup();
  },
});

/** How many users and accounts exist for an email, read straight from the component's tables. */
export const describeUser = internalQuery({
  args: { email: v.string() },
  handler: async (ctx, args) => {
    const users = await ctx.runQuery(components.betterAuth.adapter.findMany, {
      model: "user",
      where: [{ field: "email", value: args.email }],
      paginationOpts: { numItems: 100, cursor: null },
    });
    const accounts = [];
    for (const user of users.page) {
      const found = await ctx.runQuery(components.betterAuth.adapter.findMany, {
        model: "account",
        where: [{ field: "userId", value: String(user._id) }],
        paginationOpts: { numItems: 100, cursor: null },
      });
      for (const account of found.page) {
        accounts.push({
          userId: String(user._id),
          providerId: String(account.providerId),
          credentialVersion: account.opaqueCredentialVersion ?? null,
        });
      }
    }
    return { users: users.page.length, accounts };
  },
});
