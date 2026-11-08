import "dotenv/config";
import { opaque } from "@alkalines/better-auth-opaque";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { betterAuth } from "better-auth";
import { prismaAdapter } from "better-auth/adapters/prisma";
import { twoFactor } from "better-auth/plugins";
import { PrismaClient } from "../generated/prisma/client";

const prisma = new PrismaClient({
  adapter: new PrismaLibSql({ url: process.env.DATABASE_URL ?? "file:./dev.db" }),
});

const origin = process.env.BETTER_AUTH_URL ?? "http://localhost:3000";

export const auth = betterAuth({
  baseURL: origin,
  secret: process.env.BETTER_AUTH_SECRET,
  database: prismaAdapter(prisma, { provider: "sqlite" }),
  plugins: [
    twoFactor({ allowPasswordless: true, issuer: "better-auth-opaque example" }),
    opaque({
      // Fails closed when unset or invalid; generate one with `bun run create-setup`.
      serverSetup: process.env.OPAQUE_SERVER_SETUP!,
      passwordReset: {
        url: (token) => `${origin}/reset?token=${token}`,
      },
      hooks: {
        // The demo payload is the AES-GCM wrapped data key `{ iv, wrappedKey }`.
        validatePayload: ({ payload }) => {
          const candidate = payload as { iv?: unknown; wrappedKey?: unknown } | undefined;
          if (typeof candidate?.iv !== "string" || typeof candidate.wrappedKey !== "string") {
            throw new Error("Payload must be { iv, wrappedKey }");
          }
        },
        commitPayload: async ({ userId, credentialVersion, payload }) => {
          const serialized = JSON.stringify(payload);
          await prisma.demoPayload.upsert({
            where: { userId_credentialVersion: { userId, credentialVersion } },
            create: { userId, credentialVersion, payload: serialized },
            update: { payload: serialized },
          });
        },
        // Only the replaced version is deleted: removing "every other version" could drop the
        // payload of a concurrent registration that is about to become current.
        activatePayload: async ({ userId, previousCredentialVersion }) => {
          if (previousCredentialVersion === null) {
            return;
          }
          await prisma.demoPayload.deleteMany({
            where: { userId, credentialVersion: previousCredentialVersion },
          });
        },
        loadPayload: async ({ userId, credentialVersion }) => {
          const row = await prisma.demoPayload.findUnique({
            where: { userId_credentialVersion: { userId, credentialVersion } },
          });
          return row ? (JSON.parse(row.payload) as unknown) : null;
        },
      },
    }),
  ],
});
