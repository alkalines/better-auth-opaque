// `getCurrentAdapter` comes from `@better-auth/core`, the same module as `runWithTransaction`:
// it returns the transaction-bound adapter when a transaction is open.
import { getCurrentAdapter } from "@better-auth/core/context";
import { BASE_ERROR_CODES, type Account, type GenericEndpointContext } from "better-auth";
import { APIError, isAPIError } from "better-auth/api";
import * as z from "zod";
import {
  OPAQUE_ACCOUNT_FIELDS,
  OPAQUE_ERROR_CODES,
  OPAQUE_PROVIDER_ID,
  keyStretchingSchema,
  type OpaqueHooks,
  type OpaqueKeyStretching,
  type OpaqueRegistrationFlow,
  type OpaqueCredentialChangeFlow,
} from "../contract.ts";
import { randomToken, sha256 } from "./crypto.ts";
import type { OpaqueRuntime } from "./runtime.ts";

/** `providerId` of Better Auth's own email/password `account` row. */
const CLASSIC_PROVIDER_ID = "credential";

/**
 * An OPAQUE account row's identity and current registration, without its key-stretching profile:
 * enough to replace the credential, not to log in with it.
 */
export type OpaqueCredentialRow = {
  /** Primary key of the `account` row. */
  accountRowId: string;
  userId: string;
  /** `accountId`, fixed for the account's lifetime; the OPAQUE `userIdentifier`. */
  credentialId: string;
  registrationRecord: string;
  credentialVersion: string;
};

/** An OPAQUE account row with its plugin fields decoded, usable for a login. */
export type OpaqueCredential = OpaqueCredentialRow & {
  keyStretching: OpaqueKeyStretching;
};

/**
 * Every profile a stored account may carry: the current schema plus the unbounded Argon2id
 * parameters 0.1.x accepted. Legacy profiles are recognized only so that a reset can replace
 * them; logins keep requiring {@link keyStretchingSchema}.
 */
const storedKeyStretchingSchema = z.union([
  keyStretchingSchema,
  z.strictObject({
    "argon2id-custom": z.strictObject({
      iterations: z.int().min(1),
      memory: z.int().min(1),
      parallelism: z.int().min(1),
    }),
  }),
]);

/**
 * Splits an OPAQUE account row into its decoded fields and its stored profile, parsed as JSON but
 * not validated. Rows of other providers and rows with missing or non-JSON fields yield `null`.
 */
function decodeOpaqueAccount(
  account: Account | null | undefined,
): { row: OpaqueCredentialRow; storedKeyStretching: unknown } | null {
  if (!account || account.providerId !== OPAQUE_PROVIDER_ID) {
    return null;
  }

  const fields = account as Account & Record<string, unknown>;
  const registrationRecord = fields[OPAQUE_ACCOUNT_FIELDS.registrationRecord];
  const credentialVersion = fields[OPAQUE_ACCOUNT_FIELDS.credentialVersion];
  const storedKeyStretching = fields[OPAQUE_ACCOUNT_FIELDS.keyStretching];
  if (
    typeof registrationRecord !== "string" ||
    typeof credentialVersion !== "string" ||
    typeof storedKeyStretching !== "string"
  ) {
    return null;
  }

  let parsedKeyStretching: unknown;
  try {
    parsedKeyStretching = JSON.parse(storedKeyStretching);
  } catch {
    return null;
  }

  return {
    row: {
      accountRowId: account.id,
      userId: account.userId,
      credentialId: account.accountId,
      registrationRecord,
      credentialVersion,
    },
    storedKeyStretching: parsedKeyStretching,
  };
}

/**
 * Decodes an OPAQUE account row for a reset, which replaces the registration without a login, so
 * a legacy 0.1.x profile outside the current bounds is accepted. Rows of other providers and
 * rows with missing or corrupt plugin fields yield `null`.
 */
export function readCredentialRow(account: Account | null | undefined): OpaqueCredentialRow | null {
  const decoded = decodeOpaqueAccount(account);
  if (!decoded || !storedKeyStretchingSchema.safeParse(decoded.storedKeyStretching).success) {
    return null;
  }
  return decoded.row;
}

/**
 * Decodes an account row into a credential a login can use. Rows of other providers, OPAQUE rows
 * with missing or corrupt plugin fields, and rows whose profile is outside the current bounds
 * yield `null`, so sign-in treats them like unknown users instead of failing differently.
 */
export function readCredential(account: Account | null | undefined): OpaqueCredential | null {
  const decoded = decodeOpaqueAccount(account);
  if (!decoded) {
    return null;
  }
  const keyStretching = keyStretchingSchema.safeParse(decoded.storedKeyStretching);
  if (!keyStretching.success) {
    return null;
  }
  return { ...decoded.row, keyStretching: keyStretching.data };
}

/** Finds the user's OPAQUE credential, if any. */
export async function findCredentialByUserId(
  ctx: GenericEndpointContext,
  userId: string,
): Promise<OpaqueCredential | null> {
  const accounts = await ctx.context.internalAdapter.findAccounts(userId);
  return readCredential(accounts.find((account) => account.providerId === OPAQUE_PROVIDER_ID));
}

/** Finds the OPAQUE account row with this fixed credential id (`accountId`), if any. */
function findOpaqueAccount(ctx: GenericEndpointContext, credentialId: string) {
  return ctx.context.internalAdapter.findAccountByKey({
    providerId: OPAQUE_PROVIDER_ID,
    accountId: credentialId,
  });
}

/** Finds the credential by its fixed credential id (`accountId`). */
export async function findCredentialById(
  ctx: GenericEndpointContext,
  credentialId: string,
): Promise<OpaqueCredential | null> {
  return readCredential(await findOpaqueAccount(ctx, credentialId));
}

/** Rejects a payload the server could not store; runs before any state is consumed or written. */
export function assertPayloadSupported(hooks: OpaqueHooks, payload: unknown): void {
  if (payload !== undefined && !hooks.commitPayload) {
    throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.PAYLOAD_NOT_SUPPORTED);
  }
}

/**
 * Runs `validatePayload`. API errors pass through so apps control the response; anything else
 * becomes `INVALID_PAYLOAD` without exposing the original error to the client.
 */
export async function validatePayload(
  hooks: OpaqueHooks,
  input: { payload: unknown; flow: OpaqueRegistrationFlow; userId?: string },
  ctx: GenericEndpointContext,
): Promise<void> {
  if (!hooks.validatePayload) {
    return;
  }
  try {
    await hooks.validatePayload(input, ctx);
  } catch (error) {
    if (isAPIError(error)) {
      throw error;
    }
    ctx.context.logger.warn("opaque: validatePayload rejected a payload", error);
    throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_PAYLOAD);
  }
}

/**
 * Runs a step that must not stop later steps from running and records its failure. The callers
 * rethrow the first recorded error once every step ran.
 */
async function collectError(errors: unknown[], step: () => Promise<unknown> | unknown) {
  try {
    await step();
  } catch (error) {
    errors.push(error);
  }
}

/**
 * The steps after a credential switch: `activatePayload`, the optional `beforeRevocation` step,
 * revocation of every session of the user (sessions created with the old password must not
 * survive), and `onCredentialChanged` with the revocation outcome. Each step runs even if an
 * earlier one threw; the first error is rethrown afterwards.
 */
async function finishCredentialChange(
  ctx: GenericEndpointContext,
  hooks: OpaqueHooks,
  change: {
    userId: string;
    previousCredentialVersion: string | null;
    credentialVersion: string;
    flow: OpaqueCredentialChangeFlow;
  },
  errors: unknown[],
  beforeRevocation?: () => Promise<void>,
): Promise<void> {
  await collectError(errors, () => hooks.activatePayload?.(change, ctx));
  if (beforeRevocation) {
    await collectError(errors, beforeRevocation);
  }

  let sessionsRevoked = false;
  await collectError(errors, async () => {
    await ctx.context.internalAdapter.deleteUserSessions(change.userId);
    sessionsRevoked = true;
  });
  await collectError(errors, () =>
    hooks.onCredentialChanged?.({ ...change, sessionsRevoked }, ctx),
  );

  if (errors.length > 0) {
    throw errors[0];
  }
}

/**
 * Replaces the registration of an existing credential (password change and reset) and returns the
 * new credential version.
 *
 * Ordering keeps the account usable after a failure at any step: the new payload is committed
 * under a fresh version while the account still points at the old one, then one compare-and-set
 * update switches record, version, and profile together, and only then may the app drop the old
 * payload. Before the switch the old password keeps working with the old payload; after it the
 * new password works with the new payload.
 *
 * Fails with `CREDENTIAL_CHANGED` when the account no longer points at `expectedVersion`, both
 * before any hook runs and atomically at the switch, so of two flows proven against the same
 * version exactly one wins. The account may carry a legacy profile outside the current bounds:
 * a reset is how such accounts recover. Once the switch happened, the remaining steps run as
 * described in {@link finishCredentialChange}.
 */
export async function replaceCredential(
  ctx: GenericEndpointContext,
  runtime: OpaqueRuntime,
  input: {
    flow: Extract<OpaqueCredentialChangeFlow, "change-password" | "reset-password">;
    credentialId: string;
    expectedVersion: string;
    registrationRecord: string;
    keyStretching: OpaqueKeyStretching;
    payload: unknown;
  },
): Promise<string> {
  const { hooks } = runtime;

  await runtime.validateRegistrationRecord(input.credentialId, input.registrationRecord);

  // Early check so a stale flow fails before the app commits a payload it can never activate.
  const current = readCredentialRow(await findOpaqueAccount(ctx, input.credentialId));
  if (!current || current.credentialVersion !== input.expectedVersion) {
    throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
  }
  const userId = current.userId;

  await validatePayload(hooks, { payload: input.payload, flow: input.flow, userId }, ctx);

  const credentialVersion = randomToken();
  if (input.payload !== undefined && hooks.commitPayload) {
    await hooks.commitPayload(
      { userId, credentialVersion, payload: input.payload, flow: input.flow },
      ctx,
    );
  }

  // The switch is a compare-and-set on the version, through the adapter directly (joining an
  // open transaction): `internalAdapter.updateAccount` cannot take a version condition. As a
  // consequence, Better Auth `account.update` database hooks do not run for this write.
  const errors: unknown[] = [];
  let switched: boolean;
  try {
    const adapter = await getCurrentAdapter(ctx.context.adapter);
    const updated = await adapter.update({
      model: "account",
      where: [
        { field: "id", value: current.accountRowId },
        { field: OPAQUE_ACCOUNT_FIELDS.credentialVersion, value: input.expectedVersion },
      ],
      update: {
        [OPAQUE_ACCOUNT_FIELDS.registrationRecord]: input.registrationRecord,
        [OPAQUE_ACCOUNT_FIELDS.credentialVersion]: credentialVersion,
        [OPAQUE_ACCOUNT_FIELDS.keyStretching]: JSON.stringify(input.keyStretching),
        updatedAt: new Date(),
      },
    });
    switched = updated !== null;
  } catch (error) {
    // The write may have committed before the error (e.g. a failing after-write step); the
    // account row is the source of truth for whether the old password is gone.
    errors.push(error);
    const after = await findCredentialById(ctx, input.credentialId);
    switched = after?.credentialVersion === credentialVersion;
  }

  if (!switched) {
    throw errors[0] ?? APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
  }

  await finishCredentialChange(
    ctx,
    hooks,
    {
      userId,
      previousCredentialVersion: input.expectedVersion,
      credentialVersion,
      flow: input.flow,
    },
    errors,
  );
  return credentialVersion;
}

/**
 * Removes every classic Better Auth `credential` account of the user (the password hash a
 * migration to OPAQUE makes obsolete).
 */
export async function removeClassicAccounts(
  ctx: GenericEndpointContext,
  userId: string,
): Promise<void> {
  const { internalAdapter } = ctx.context;
  const accounts = await internalAdapter.findAccounts(userId);
  for (const account of accounts) {
    if (account.providerId === CLASSIC_PROVIDER_ID) {
      await internalAdapter.deleteAccount(account.id);
    }
  }
}

/**
 * Fingerprint of a classic account for compare-and-set across a challenge and its complete call:
 * changes whenever the password hash or the row's `updatedAt` changes, without keeping the hash
 * in the state row.
 */
export async function classicAccountFingerprint(account: Account): Promise<string> {
  return sha256(`${account.id}\n${account.password}\n${new Date(account.updatedAt).getTime()}`);
}

/**
 * Adds the first OPAQUE credential to an existing user and returns its credential version:
 * `attach` (the signed-in user proved their classic password) and a reset-link enrolment
 * (`flow: "reset-password"`, no classic fingerprint).
 *
 * Order: re-check that the user still has no OPAQUE account and, for attach, that the classic
 * account still matches `classicFingerprint` (`CREDENTIAL_CHANGED` otherwise) → `validatePayload`
 * → `commitPayload` → create the account → re-check both conditions → `activatePayload` → remove
 * the classic account (option `removeClassicCredential`) → revoke every session →
 * `onCredentialChanged`.
 *
 * The re-check after the insert resolves races without comparing clocks or holding locks. When
 * any other OPAQUE row exists, or the classic password changed while the hooks ran, or the
 * re-check itself fails, this flow deletes its own row and fails, before anything irreversible
 * happened (the classic account and the sessions are still intact). Two rows can therefore never
 * both survive; if both flows insert before either re-checks, both fail and no row remains, and
 * the client retries. A classic change after the re-check is ordered after this attach.
 *
 * Once the re-check passed, the remaining steps run as described in
 * {@link finishCredentialChange} (the credential stays).
 */
export async function attachCredential(
  ctx: GenericEndpointContext,
  runtime: OpaqueRuntime,
  input: {
    flow: Extract<OpaqueCredentialChangeFlow, "attach" | "reset-password">;
    userId: string;
    credentialId: string;
    registrationRecord: string;
    keyStretching: OpaqueKeyStretching;
    payload: unknown;
    /** From the attach challenge; `null` for a reset enrolment, which has no classic proof. */
    classicFingerprint: string | null;
  },
): Promise<string> {
  const { hooks } = runtime;
  const { internalAdapter } = ctx.context;
  const { userId } = input;

  await runtime.validateRegistrationRecord(input.credentialId, input.registrationRecord);

  const opaqueRows = async () =>
    (await internalAdapter.findAccounts(userId)).filter(
      (account) => account.providerId === OPAQUE_PROVIDER_ID,
    );
  // Attach only: the classic password the challenge proved must still be the current one.
  const classicChanged = async () => {
    if (input.classicFingerprint === null) {
      return false;
    }
    const classic = await internalAdapter.findCredentialAccount(userId);
    return !classic || (await classicAccountFingerprint(classic)) !== input.classicFingerprint;
  };

  if ((await opaqueRows()).length > 0) {
    throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS);
  }
  if (await classicChanged()) {
    throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
  }

  await validatePayload(hooks, { payload: input.payload, flow: input.flow, userId }, ctx);

  const credentialVersion = randomToken();
  if (input.payload !== undefined && hooks.commitPayload) {
    await hooks.commitPayload(
      { userId, credentialVersion, payload: input.payload, flow: input.flow },
      ctx,
    );
  }

  const errors: unknown[] = [];
  let created: Account | null;
  try {
    created = await internalAdapter.createAccount({
      userId,
      providerId: OPAQUE_PROVIDER_ID,
      accountId: input.credentialId,
      [OPAQUE_ACCOUNT_FIELDS.registrationRecord]: input.registrationRecord,
      [OPAQUE_ACCOUNT_FIELDS.credentialVersion]: credentialVersion,
      [OPAQUE_ACCOUNT_FIELDS.keyStretching]: JSON.stringify(input.keyStretching),
    });
  } catch (error) {
    // The row may have been written before the error (a failing after-write step).
    errors.push(error);
    created = (await opaqueRows()).find((row) => row.accountId === input.credentialId) ?? null;
  }
  if (!created) {
    // `null` when a database `account.create.before` hook rejected the row.
    throw (
      errors[0] ?? APIError.from("UNPROCESSABLE_ENTITY", BASE_ERROR_CODES.FAILED_TO_CREATE_USER)
    );
  }

  const mine = created;
  let conflict: unknown;
  try {
    if ((await opaqueRows()).some((row) => row.id !== mine.id)) {
      conflict = APIError.from("CONFLICT", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS);
    } else if (await classicChanged()) {
      conflict = APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
    }
  } catch (error) {
    // Without a completed re-check the row must not stay: it would block every retry while the
    // classic password and the old sessions keep working.
    conflict = error;
  }
  if (conflict !== undefined) {
    await internalAdapter.deleteAccount(mine.id);
    throw conflict;
  }

  await finishCredentialChange(
    ctx,
    hooks,
    { userId, previousCredentialVersion: null, credentialVersion, flow: input.flow },
    errors,
    runtime.removeClassicCredential ? () => removeClassicAccounts(ctx, userId) : undefined,
  );
  return credentialVersion;
}
