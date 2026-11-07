import type { GenericEndpointContext } from "better-auth";
import { APIError } from "better-auth/api";
import { OPAQUE_ERROR_CODES, type OpaqueKeyStretching } from "../contract.ts";
import { randomToken } from "./crypto.ts";

/** Lifetime of every challenge state row. */
const STATE_LIFETIME_MS = 5 * 60 * 1000;

/**
 * Server-held state between a challenge and its complete call, per flow. Rows live in Better
 * Auth's `verification` table under `opaque:<flow>:<stateId>`; the client only ever sees the
 * random `stateId`. Login states contain serenity's server login state, which must never leave
 * the server.
 */
export type OpaqueStates = {
  "sign-up": {
    email: string;
    credentialId: string;
    keyStretching: OpaqueKeyStretching;
  };
  /** `null` ids mark the fake login used for unknown emails and users without an OPAQUE account. */
  "sign-in": {
    serverLoginState: string;
    userId: string | null;
    credentialId: string | null;
    credentialVersion: string | null;
  };
  "change-password": {
    userId: string;
    credentialId: string;
    credentialVersion: string;
    serverLoginState: string;
    keyStretching: OpaqueKeyStretching;
  };
  "reset-password": {
    userId: string;
    credentialId: string;
    credentialVersion: string;
    keyStretching: OpaqueKeyStretching;
  };
};

type StateFlow = keyof OpaqueStates;

function stateIdentifier(flow: StateFlow, stateId: string): string {
  return `opaque:${flow}:${stateId}`;
}

/** Stores a single-use state row valid for five minutes and returns its random `stateId`. */
export async function createState<F extends StateFlow>(
  ctx: GenericEndpointContext,
  flow: F,
  value: OpaqueStates[F],
): Promise<string> {
  const stateId = randomToken();
  await ctx.context.internalAdapter.createVerificationValue({
    identifier: stateIdentifier(flow, stateId),
    value: JSON.stringify(value),
    expiresAt: new Date(Date.now() + STATE_LIFETIME_MS),
  });
  return stateId;
}

/**
 * Atomically consumes a state row. Missing, already consumed, and expired rows all fail with
 * `INVALID_STATE`; a consumed row is gone even if the rest of the flow fails, so the client has to
 * start over with a new challenge.
 */
export async function consumeState<F extends StateFlow>(
  ctx: GenericEndpointContext,
  flow: F,
  stateId: string,
): Promise<OpaqueStates[F]> {
  const row = await ctx.context.internalAdapter.consumeVerificationValue(
    stateIdentifier(flow, stateId),
  );
  if (!row) {
    throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_STATE);
  }
  return JSON.parse(row.value) as OpaqueStates[F];
}
