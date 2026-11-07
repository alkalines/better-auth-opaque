import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

/**
 * App-owned tables (the Better Auth tables live in the `betterAuth` component). `payloads` holds
 * the app payload per `(userId, credentialVersion)` written by the OPAQUE hooks.
 */
export default defineSchema({
  payloads: defineTable({
    userId: v.string(),
    credentialVersion: v.string(),
    payload: v.any(),
  }).index("by_user_and_version", ["userId", "credentialVersion"]),
});
