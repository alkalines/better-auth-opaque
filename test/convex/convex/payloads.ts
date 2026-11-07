import { v } from "convex/values";
import { internalMutation, internalQuery } from "./_generated/server";

/** Stores the payload for one credential version; idempotent per `(userId, credentialVersion)`. */
export const commit = internalMutation({
  args: { userId: v.string(), credentialVersion: v.string(), payload: v.any() },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("payloads")
      .withIndex("by_user_and_version", (q) =>
        q.eq("userId", args.userId).eq("credentialVersion", args.credentialVersion),
      )
      .unique();
    if (existing) {
      await ctx.db.patch(existing._id, { payload: args.payload });
      return;
    }
    await ctx.db.insert("payloads", args);
  },
});

/**
 * Deletes the payload of the version the account just switched away from. Only that version:
 * deleting every other version could remove a concurrent registration's committed payload.
 */
export const activate = internalMutation({
  args: { userId: v.string(), previousCredentialVersion: v.union(v.string(), v.null()) },
  handler: async (ctx, args) => {
    const { previousCredentialVersion } = args;
    if (previousCredentialVersion === null) {
      return;
    }
    const previous = await ctx.db
      .query("payloads")
      .withIndex("by_user_and_version", (q) =>
        q.eq("userId", args.userId).eq("credentialVersion", previousCredentialVersion),
      )
      .unique();
    if (previous) {
      await ctx.db.delete(previous._id);
    }
  },
});

/** The payload committed for exactly this credential version, or `null`. */
export const load = internalQuery({
  args: { userId: v.string(), credentialVersion: v.string() },
  handler: async (ctx, args) => {
    const row = await ctx.db
      .query("payloads")
      .withIndex("by_user_and_version", (q) =>
        q.eq("userId", args.userId).eq("credentialVersion", args.credentialVersion),
      )
      .unique();
    return row?.payload ?? null;
  },
});

/** Test support: every stored version of a user's payloads. */
export const versionsOf = internalQuery({
  args: { userId: v.string() },
  handler: async (ctx, args) => {
    const rows = await ctx.db
      .query("payloads")
      .withIndex("by_user_and_version", (q) => q.eq("userId", args.userId))
      .collect();
    return rows.map((row) => row.credentialVersion);
  },
});
