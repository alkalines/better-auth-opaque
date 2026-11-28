import { redisStorage } from "@better-auth/redis-storage";
import type { BetterAuthOptions } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { eq, getTableColumns } from "drizzle-orm";
import { PgTable } from "drizzle-orm/pg-core";
import { drizzle } from "drizzle-orm/postgres-js";
import { Redis } from "ioredis";
import postgres from "postgres";
import type { Row, TestBackend, TestDb } from "../../unit/helpers.ts";
import * as serialSchema from "../generated/schema-serial.ts";
import * as textSchema from "../generated/schema-text.ts";
import * as uuidSchema from "../generated/schema-uuid.ts";
import type { IdFormat } from "./id-formats.ts";

const SCHEMAS: Record<IdFormat, Record<string, unknown>> = {
  text: textSchema,
  uuid: uuidSchema,
  serial: serialSchema,
};

/** What every test database of one run shares; produced by `global-setup.ts`. */
export type DrizzleRun = {
  databaseUrl: string;
  redisUrl: string;
  /** Names this run's Postgres schemas (`<prefix>_…`) and Redis keys (`<prefix>:…`). */
  prefix: string;
  /** DDL per id format; `"public".` marks the target schema (see {@link createTables}). */
  ddl: Record<IdFormat, string[]>;
};

function tableOf(format: IdFormat, model: string): PgTable {
  const table = SCHEMAS[format][model];
  if (!(table instanceof PgTable)) {
    throw new Error(`no Drizzle table for model "${model}"`);
  }
  return table;
}

/**
 * Creates the Better Auth tables in a new Postgres schema. drizzle-kit writes foreign keys as
 * `REFERENCES "public"."user"`, so those references are pointed at the new schema; everything
 * else is unqualified and lands there through `search_path`.
 */
async function createTables(admin: postgres.Sql, schemaName: string, ddl: string[]) {
  await admin.begin(async (transaction) => {
    await transaction.unsafe(`CREATE SCHEMA "${schemaName}"`);
    await transaction.unsafe(`SET LOCAL search_path TO "${schemaName}"`);
    for (const statement of ddl) {
      await transaction.unsafe(statement.replaceAll('"public".', `"${schemaName}".`));
    }
  });
}

/**
 * The test backend of `test/drizzle`: every test database is its own Postgres schema behind
 * Better Auth's Drizzle adapter (postgres.js driver, transactions on) plus its own Redis key
 * prefix as `secondaryStorage`, with sessions in both stores (`storeSessionInDatabase`) and
 * verification values in Redis only (Better Auth's default with secondary storage).
 *
 * `close` ends this worker's connections; `global-setup.ts` drops the schemas and keys afterwards.
 */
export function createDrizzleBackend(run: DrizzleRun): {
  create: TestBackend;
  close: () => Promise<void>;
} {
  const admin = postgres(run.databaseUrl, { max: 1, onnotice: () => {} });
  const redis = new Redis(run.redisUrl);
  const clients: postgres.Sql[] = [];

  const create: TestBackend = async ({ generateId }): Promise<TestDb> => {
    const format: IdFormat = generateId ?? "text";
    const name = `${run.prefix}_${crypto.randomUUID().replaceAll("-", "").slice(0, 16)}`;
    await createTables(admin, name, run.ddl[format]);

    // Several connections, so concurrent flows (and a flow held open inside a transaction)
    // do not queue behind each other; idle ones close so finished tests release them.
    const client = postgres(run.databaseUrl, {
      max: 4,
      idle_timeout: 1,
      connection: { search_path: name },
      onnotice: () => {},
    });
    clients.push(client);
    const db = drizzle({ client, schema: SCHEMAS[format] });
    const storage = redisStorage({ client: redis, keyPrefix: `${run.prefix}:${name}:` });

    const options: Partial<BetterAuthOptions> = {
      secondaryStorage: storage,
      session: { storeSessionInDatabase: true },
    };
    if (generateId) {
      options.advanced = { database: { generateId } };
    }

    /**
     * Verification values in Redis. They carry no `id` (Better Auth only generates one for
     * database rows), so their Redis key (without the prefix) serves as the row id.
     */
    const verificationRows = async () => {
      const rows: Row[] = [];
      for (const key of await storage.listKeys()) {
        const value = key.startsWith("verification:") ? await storage.get(key) : null;
        // A value can expire between listing and reading.
        if (value !== null) {
          rows.push({ ...(JSON.parse(value) as Row), id: key });
        }
      }
      return rows;
    };

    return {
      database: drizzleAdapter(db, { provider: "pg", schema: SCHEMAS[format], transaction: true }),
      options,
      rows: async (model) => {
        if (model === "verification") {
          return verificationRows();
        }
        return (await db.select().from(tableOf(format, model))) as Row[];
      },
      insert: async (model, row) => {
        await db.insert(tableOf(format, model)).values(row);
      },
      update: async (model, id, values) => {
        if (model === "verification") {
          const stored = typeof id === "string" ? await storage.get(id) : null;
          if (stored === null) {
            return;
          }
          const updated = { ...(JSON.parse(stored) as Row), ...values };
          const expiresAt = new Date(updated.expiresAt as string | Date).getTime();
          const ttlSeconds = Math.floor((expiresAt - Date.now()) / 1000);
          // Redis drops a value once its TTL runs out, so an expiry in the past deletes it.
          if (ttlSeconds > 0) {
            await storage.set(id as string, JSON.stringify(updated), ttlSeconds);
          } else {
            await storage.delete(id as string);
          }
          return;
        }
        const table = tableOf(format, model);
        const idColumn = getTableColumns(table).id;
        if (!idColumn) {
          throw new Error(`model "${model}" has no id column`);
        }
        await db.update(table).set(values).where(eq(idColumn, id));
      },
    };
  };

  const close = async () => {
    await Promise.all(clients.map((client) => client.end()));
    await admin.end();
    redis.disconnect();
  };

  return { create, close };
}
