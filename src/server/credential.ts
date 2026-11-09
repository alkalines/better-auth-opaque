// `getCurrentAdapter` comes from `@better-auth/core`, the same module as `runWithTransaction`:
// it returns the transaction-bound adapter when a transaction is open.
import { getCurrentAdapter } from "@better-auth/core/context";
import { BASE_ERROR_CODES, type Account, type GenericEndpointContext } from "better-auth";
import { APIError, isAPIError } from "better-auth/api";
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

/** An OPAQUE account row with its plugin fields decoded. */
export type OpaqueCredential = {
  /** Primary key of the `account` row. */
  accountRowId: string;
  userId: string;
  /** `accountId`, fixed for the account's lifetime; the OPAQUE `userIdentifier`. */
  credentialId: string;
  registrationRecord: string;
  credentialVersion: string;
  keyStretching: OpaqueKeyStretching;
};

/**
 * Decodes an account row into a credential. Rows of other providers and OPAQUE rows with missing
 * or corrupt plugin fields yield `null`, so sign-in treats them like unknown users instead of
 * failing differently.
 */
export function readCredential(account: Account | null | undefined): OpaqueCredential | null {
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

  let keyStretching: OpaqueKeyStretching;
  try {
    keyStretching = keyStretchingSchema.parse(JSON.parse(storedKeyStretching));
  } catch {
    return null;
  }

  return {
    accountRowId: account.id,
    userId: account.userId,
    credentialId: account.accountId,
    registrationRecord,
    credentialVersion,
    keyStretching,
  };
}

/** Finds the user's OPAQUE credential, if any. */
export async function findCredentialByUserId(
  ctx: GenericEndpointContext,
  userId: string,
): Promise<OpaqueCredential | null> {
  const accounts = await ctx.context.internalAdapter.findAccounts(userId);
  return readCredential(accounts.find((account) => account.providerId === OPAQUE_PROVIDER_ID));
}

/** Finds the credential by its fixed credential id (`accountId`). */
export async function findCredentialById(
  ctx: GenericEndpointContext,
  credentialId: string,
): Promise<OpaqueCredential | null> {
  const account = await ctx.context.internalAdapter.findAccountByKey({
    providerId: OPAQUE_PROVIDER_ID,
    accountId: credentialId,
  });
  return readCredential(account);
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
 * Replaces the registration of an existing credential (password change and reset).
 *
 * Ordering keeps the account usable after a failure at any step: the new payload is committed
 * under a fresh version while the account still points at the old one, then one compare-and-set
 * update switches record, version, and profile together, and only then may the app drop the old
 * payload. Before the switch the old password keeps working with the old payload; after it the
 * new password works with the new payload.
 *
 * Fails with `CREDENTIAL_CHANGED` when the account no longer points at `expectedVersion`, both
 * before any hook runs and atomically at the switch, so of two flows proven against the same
 * version exactly one wins. Once the switch happened, `activatePayload`, the revocation of every
 * session of the user (sessions created with the old password must not survive), and
 * `onCredentialChanged` all run even if an earlier step threw; the first error is rethrown
 * afterwards.
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
): Promise<void> {
  const { hooks } = runtime;

  await runtime.validateRegistrationRecord(input.credentialId, input.registrationRecord);

  // Early check so a stale flow fails before the app commits a payload it can never activate.
  const current = await findCredentialById(ctx, input.credentialId);
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

  const credentialChange = {
    userId,
    previousCredentialVersion: input.expectedVersion,
    credentialVersion,
    flow: input.flow,
  };
  await collectError(errors, () => hooks.activatePayload?.(credentialChange, ctx));
  await collectError(errors, () => ctx.context.internalAdapter.deleteUserSessions(userId));
  await collectError(errors, () => hooks.onCredentialChanged?.(credentialChange, ctx));

  if (errors.length > 0) {
    throw errors[0];
  }
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
 * Adds the first OPAQUE credential to an existing user: `attach` (the signed-in user proved their
 * classic password) and a reset-link enrolment (`flow: "reset-password"`, no classic fingerprint).
 *
 * Order: re-check that the user still has no OPAQUE account and, for attach, that the classic
 * account still matches `classicFingerprint` (`CREDENTIAL_CHANGED` otherwise) → `validatePayload`
 * → `commitPayload` → create the account → re-check for a concurrent creation → `activatePayload`
 * → remove the classic account (option `removeClassicCredential`) → revoke every session →
 * `onCredentialChanged`.
 *
 * Concurrent first credentials are resolved after the insert without comparing clocks: when any
 * other OPAQUE row exists, this flow deletes its own row and fails with `OPAQUE_ACCOUNT_EXISTS`,
 * before anything irreversible happened (the classic account is still intact). Two rows can
 * therefore never both survive. If both flows insert before either re-checks, both fail and no
 * row remains; the client retries.
 *
 * Once the account row exists, the remaining steps all run even if one throws, and the first
 * error is rethrown afterwards (the credential stays).
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
): Promise<void> {
  const { hooks } = runtime;
  const { internalAdapter } = ctx.context;
  const { userId } = input;

  await runtime.validateRegistrationRecord(input.credentialId, input.registrationRecord);

  const opaqueRows = async () =>
    (await internalAdapter.findAccounts(userId)).filter(
      (account) => account.providerId === OPAQUE_PROVIDER_ID,
    );
  if ((await opaqueRows()).length > 0) {
    throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS);
  }
  if (input.classicFingerprint !== null) {
    const classic = await internalAdapter.findCredentialAccount(userId);
    if (!classic || (await classicAccountFingerprint(classic)) !== input.classicFingerprint) {
      throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.CREDENTIAL_CHANGED);
    }
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
  const otherRowExists = (await opaqueRows()).some((row) => row.id !== mine.id);
  if (otherRowExists) {
    await internalAdapter.deleteAccount(mine.id);
    throw APIError.from("CONFLICT", OPAQUE_ERROR_CODES.OPAQUE_ACCOUNT_EXISTS);
  }

  const credentialChange = {
    userId,
    previousCredentialVersion: null,
    credentialVersion,
    flow: input.flow,
  };
  await collectError(errors, () => hooks.activatePayload?.(credentialChange, ctx));
  if (runtime.removeClassicCredential) {
    await collectError(errors, () => removeClassicAccounts(ctx, userId));
  }
  await collectError(errors, () => internalAdapter.deleteUserSessions(userId));
  await collectError(errors, () => hooks.onCredentialChanged?.(credentialChange, ctx));

  if (errors.length > 0) {
    throw errors[0];
  }
}
