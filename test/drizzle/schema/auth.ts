import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { opaque } from "../../../src/server/index.ts";
import { ID_FORMATS, type IdFormat } from "../test/id-formats.ts";

// Static instance for Better Auth schema generation only (`scripts/generate-schema.ts`); nothing
// else may import this file. Generation never touches a database, so the adapter gets no client.

const format = (process.env.SCHEMA_ID_FORMAT ?? "text") as IdFormat;
if (!ID_FORMATS.includes(format)) {
  throw new Error(`SCHEMA_ID_FORMAT must be one of ${ID_FORMATS.join(", ")}`);
}

export const auth = betterAuth({
  database: drizzleAdapter({}, { provider: "pg" }),
  // Same table set as the tests: sessions in Redis and Postgres, verification in Redis only.
  secondaryStorage: {
    get: () => null,
    set: () => {},
    delete: () => {},
    getAndDelete: () => null,
    increment: () => 0,
  },
  session: { storeSessionInDatabase: true },
  advanced: format === "text" ? undefined : { database: { generateId: format } },
  // Not a serenity setup: only the plugin's schema is read here.
  plugins: [opaque({ serverSetup: "schema-only: not a server setup" })],
});
