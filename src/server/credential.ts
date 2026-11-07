// `getCurrentAdapter` comes from `@better-auth/core`, the same module as `runWithTransaction`:
// it returns the transaction-bound adapter when a transaction is open.
import { getCurrentAdapter } from "@better-auth/core/context";
import type { Account, GenericEndpointContext } from "better-auth";
import { APIError, isAPIError } from "better-auth/api";
import {
  OPAQUE_ACCOUNT_FIELDS,
  OPAQUE_ERROR_CODES,
  OPAQUE_PROVIDER_ID,
  keyStretchingSchema,
  type OpaqueHooks,
  type OpaqueKeyStretching,
  type OpaqueRegistrationFlow,
} from "../contract.ts";
import { randomToken } from "./crypto.ts";
import type { OpaqueRuntime } from "./runtime.ts";

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
 * version exactly one wins. Once the switch happened, `activatePayload` and `revokeSessions`
 * both run even if an earlier step threw, because sessions created with the old password must
 * not survive; the first error is rethrown afterwards.
 */
export async function replaceCredential(
  ctx: GenericEndpointContext,
  runtime: OpaqueRuntime,
  input: {
    flow: Exclude<OpaqueRegistrationFlow, "sign-up">;
    credentialId: string;
    expectedVersion: string;
    registrationRecord: string;
    keyStretching: OpaqueKeyStretching;
    payload: unknown;
    revokeSessions: () => Promise<void>;
  },
): Promise<void> {
  const { hooks } = runtime;

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

  try {
    await hooks.activatePayload?.(
      {
        userId,
        credentialVersion,
        previousCredentialVersion: input.expectedVersion,
        flow: input.flow,
      },
      ctx,
    );
  } catch (error) {
    errors.push(error);
  }
  await input.revokeSessions();

  if (errors.length > 0) {
    throw errors[0];
  }
}
