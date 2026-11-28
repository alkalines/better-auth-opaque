/**
 * Once per Vitest run: checks Postgres and Redis, creates the test database when it does not exist
 * yet, generates the DDL of every schema variant with drizzle-kit, and hands both to the test
 * workers (`inject("drizzleRun")`). Afterwards it drops this run's Postgres schemas and Redis keys.
 */
import { redisStorage } from "@better-auth/redis-storage";
import { generateDrizzleJson, generateMigration } from "drizzle-kit/api";
import { Redis } from "ioredis";
import postgres from "postgres";
import type { TestProject } from "vitest/node";
import * as serialSchema from "../generated/schema-serial.ts";
import * as textSchema from "../generated/schema-text.ts";
import * as uuidSchema from "../generated/schema-uuid.ts";
import type { DrizzleRun } from "./backend.ts";
import type { IdFormat } from "./id-formats.ts";

declare module "vitest" {
  export interface ProvidedContext {
    drizzleRun: DrizzleRun;
  }
}

const DEFAULT_DATABASE_URL = "postgres://radium:radium@localhost:5432/opaque_test";
const DEFAULT_REDIS_URL = "redis://localhost:6379";

/** Creates the database named in the URL through the server's `postgres` database if missing. */
async function ensureDatabase(databaseUrl: string): Promise<void> {
  const url = new URL(databaseUrl);
  const name = decodeURIComponent(url.pathname.slice(1));
  url.pathname = "/postgres";
  const maintenance = postgres(url.toString(), { max: 1, onnotice: () => {} });
  try {
    const existing = await maintenance`SELECT 1 FROM pg_database WHERE datname = ${name}`;
    if (existing.length === 0) {
      await maintenance.unsafe(`CREATE DATABASE "${name.replaceAll('"', '""')}"`);
    }
  } finally {
    await maintenance.end();
  }
}

async function generateDdl(schema: Record<string, unknown>): Promise<string[]> {
  return generateMigration(generateDrizzleJson({}), generateDrizzleJson(schema));
}

export default async function setup(project: TestProject) {
  const databaseUrl = process.env.DATABASE_URL ?? DEFAULT_DATABASE_URL;
  const redisUrl = process.env.REDIS_URL ?? DEFAULT_REDIS_URL;
  // Unique per run, so runs on Node and Bun (or two checkouts) never share schemas or keys.
  const prefix = `opaque_${Date.now().toString(36)}${crypto.randomUUID().slice(0, 4)}`;

  await ensureDatabase(databaseUrl);
  const redis = new Redis(redisUrl, { maxRetriesPerRequest: 1 });
  await redis.ping();

  const ddl: Record<IdFormat, string[]> = {
    text: await generateDdl(textSchema),
    uuid: await generateDdl(uuidSchema),
    serial: await generateDdl(serialSchema),
  };
  project.provide("drizzleRun", { databaseUrl, redisUrl, prefix, ddl });

  return async () => {
    const sql = postgres(databaseUrl, { max: 1, onnotice: () => {} });
    try {
      const schemas = await sql`
        SELECT nspname FROM pg_namespace WHERE starts_with(nspname, ${`${prefix}_`})`;
      for (const { nspname } of schemas) {
        await sql.unsafe(`DROP SCHEMA "${nspname}" CASCADE`);
      }
      await redisStorage({ client: redis, keyPrefix: `${prefix}:` }).clear();
    } finally {
      await sql.end();
      redis.disconnect();
    }
  };
}
