// Per test file: runs the unit suite's `createTestDb` against Postgres + Redis instead of memory.
import { afterAll, inject } from "vitest";
import { useTestBackend } from "../../unit/helpers.ts";
import { createDrizzleBackend } from "./backend.ts";

// `scripts/run.ts` names the runtime it launched; a run claimed for Bun must really be Bun.
const expectedRuntime = process.env.OPAQUE_TEST_RUNTIME;
const actualRuntime = process.versions.bun ? "bun" : "node";
if (expectedRuntime && expectedRuntime !== actualRuntime) {
  throw new Error(`expected the ${expectedRuntime} runtime, running on ${actualRuntime}`);
}

const backend = createDrizzleBackend(inject("drizzleRun"));
useTestBackend(backend.create);
afterAll(backend.close);
