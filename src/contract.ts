/**
 * Shared contract between the OPAQUE server plugin (`src/server/`) and the client plugin
 * (`src/client/`): endpoint paths, request/response schemas, error codes, stored field names,
 * key-stretching profiles, and the hook interface apps implement on the server.
 *
 * This module is imported by the client entry, so it must stay free of server code: runtime
 * imports are limited to `zod`; Better Auth is imported for types only.
 *
 * Every OPAQUE protocol message on the wire is the base64url string produced by
 * `@serenity-kit/opaque`. The password never appears in any schema here, and neither does the
 * export key: the client derives the export key locally and only reveals it to the caller after
 * the matching `complete` endpoint succeeded.
 */
import type { GenericEndpointContext, RawError } from "better-auth";
import * as z from "zod";

/** Better Auth plugin id shared by the server and client plugins. */
export const OPAQUE_PLUGIN_ID = "opaque";

/**
 * `providerId` of the Better Auth `account` row holding an OPAQUE credential. The row's
 * `accountId` is the credential id minted at sign-up, which is also the OPAQUE `userIdentifier`.
 */
export const OPAQUE_PROVIDER_ID = "opaque";

/** Endpoint paths, relative to the Better Auth base path. All endpoints are `POST`. */
export const OPAQUE_PATHS = {
  signUpChallenge: "/sign-up/opaque/challenge",
  signUpComplete: "/sign-up/opaque/complete",
  signInChallenge: "/sign-in/opaque/challenge",
  signInComplete: "/sign-in/opaque/complete",
  signInPayload: "/sign-in/opaque/payload",
  passwordProofChallenge: "/opaque/password-proof/challenge",
  passwordProofComplete: "/opaque/password-proof/complete",
  changePasswordChallenge: "/opaque/change-password/challenge",
  changePasswordComplete: "/opaque/change-password/complete",
  resetVerify: "/reset/opaque/verify",
  resetChallenge: "/reset/opaque/challenge",
  resetComplete: "/reset/opaque/complete",
  attachChallenge: "/opaque/attach/challenge",
  attachComplete: "/opaque/attach/complete",
} as const;

/**
 * Stable error codes. Changing a key or the meaning of a code is a breaking change.
 *
 * Sign-in deliberately has a single failure code, `INVALID_CREDENTIALS`, for unknown emails,
 * emails without an OPAQUE account, and wrong passwords; the client reports a local login
 * failure (wrong password or fake record) with the same code, status, and message as the server.
 *
 * Sign-up for an email that already exists reuses Better Auth's own email/password behavior and
 * error codes so that both sign-up paths leak exactly the same information.
 */
export const OPAQUE_ERROR_CODES = {
  /** `serverSetup` is not a valid serenity server setup. Every flow fails closed with this code. */
  INVALID_SERVER_SETUP: {
    code: "INVALID_SERVER_SETUP",
    message: "OPAQUE server setup is invalid",
  },
  /** Sign-in failed: unknown email, no OPAQUE account, or wrong password. */
  INVALID_CREDENTIALS: {
    code: "INVALID_CREDENTIALS",
    message: "Invalid email or password",
  },
  /**
   * OPAQUE sign-up is disabled by `opaque({ disableSignUp })` or, when that option is unset, by
   * Better Auth's `emailAndPassword.disableSignUp`.
   */
  SIGN_UP_DISABLED: {
    code: "SIGN_UP_DISABLED",
    message: "Sign up is disabled",
  },
  /** A current-password proof failed, including a missing, expired, used, or stale management proof. */
  INVALID_PASSWORD: {
    code: "INVALID_PASSWORD",
    message: "Invalid password",
  },
  /** A challenge state or deferred sign-in payload token is missing, consumed, or expired. */
  INVALID_STATE: {
    code: "INVALID_STATE",
    message: "OPAQUE state is invalid or expired",
  },
  /**
   * A protocol message from the client could not be decoded by serenity. Sign-in returns this
   * for malformed requests regardless of whether the email exists.
   */
  INVALID_OPAQUE_MESSAGE: {
    code: "INVALID_OPAQUE_MESSAGE",
    message: "Invalid OPAQUE protocol message",
  },
  /**
   * The reset token does not exist, was already used, expired, or was revoked; also returned by
   * reset complete when the link was revoked after the reset started.
   */
  INVALID_RESET_TOKEN: {
    code: "INVALID_RESET_TOKEN",
    message: "Password reset token is invalid or expired",
  },
  /**
   * A server-only reset API found no matching user: `createPasswordResetToken` without
   * `allowEnrolment` needs a user with an OPAQUE account, with it any existing user;
   * `revokePasswordResetTokens` needs an existing user.
   */
  USER_NOT_FOUND: {
    code: "USER_NOT_FOUND",
    message: "User not found",
  },
  /** The signed-in user has no OPAQUE account to change the password of. */
  OPAQUE_ACCOUNT_NOT_FOUND: {
    code: "OPAQUE_ACCOUNT_NOT_FOUND",
    message: "No OPAQUE account for this user",
  },
  /**
   * The credential changed between the challenge and the complete call (also when it was
   * replaced again before the caller's new session was issued), or a second-factor sign-in
   * started with a password that has since been replaced; start over.
   */
  CREDENTIAL_CHANGED: {
    code: "CREDENTIAL_CHANGED",
    message: "Credential changed during the operation",
  },
  /**
   * Sign-in proved the password, but 2FA is enabled without a usable Better Auth two-factor
   * sign-in hook. This is a server misconfiguration; no session or payload is returned.
   * Only returned after a valid password proof, so it does not reveal whether an email exists.
   */
  TWO_FACTOR_NOT_SUPPORTED: {
    code: "TWO_FACTOR_NOT_SUPPORTED",
    message: "Two-factor authentication is not configured for OPAQUE sign-in",
  },
  /** The client sent a payload but the server has no `commitPayload` hook. */
  PAYLOAD_NOT_SUPPORTED: {
    code: "PAYLOAD_NOT_SUPPORTED",
    message: "Payload is not supported by this server",
  },
  /** `validatePayload` rejected the payload; nothing was written. */
  INVALID_PAYLOAD: {
    code: "INVALID_PAYLOAD",
    message: "Invalid payload",
  },
  /**
   * Client-side only: the server advertised a key-stretching profile that the client's policy
   * (`opaqueClient({ keyStretching })`) does not allow, for a registration or a login. Nothing was
   * derived and nothing was sent to `complete`.
   */
  KEY_STRETCHING_MISMATCH: {
    code: "KEY_STRETCHING_MISMATCH",
    message: "Server key stretching profile is not allowed by the client configuration",
  },
  /**
   * Client-side only: a challenge response did not match the contract schema, or serenity could
   * not process it. Nothing was sent to `complete`.
   */
  INVALID_SERVER_RESPONSE: {
    code: "INVALID_SERVER_RESPONSE",
    message: "Invalid response from the authentication server",
  },
  /**
   * Attach: the signed-in user already has an OPAQUE credential (also returned when a concurrent
   * attach or enrolment won the race). Use change-password instead.
   */
  OPAQUE_ACCOUNT_EXISTS: {
    code: "OPAQUE_ACCOUNT_EXISTS",
    message: "This user already has an OPAQUE account",
  },
  /**
   * Client-side only: `attachCredential` was called with a new password equal to the classic
   * password. The server knows the classic password, so reusing it would let the server derive
   * the export key. Nothing was sent.
   */
  PASSWORD_REUSED: {
    code: "PASSWORD_REUSED",
    message: "The new password must differ from the current password",
  },
  /** The app's `accountRateLimit` hook refused another attempt for this account (HTTP 429). */
  TOO_MANY_ATTEMPTS: {
    code: "TOO_MANY_ATTEMPTS",
    message: "Too many attempts, try again later",
  },
} as const satisfies Record<string, RawError>;

/** Union of every stable OPAQUE error code. */
export type OpaqueErrorCode = keyof typeof OPAQUE_ERROR_CODES;

/**
 * Additional fields the plugin adds to Better Auth's `account` model.
 *
 * - `registrationRecord`: serenity registration record (base64url). Never returned by the API.
 * - `opaqueCredentialVersion`: opaque random id of the credential the record belongs to; app
 *   payloads are stored per version through the hooks.
 * - `opaqueKeyStretching`: JSON-serialized {@link OpaqueKeyStretching} used at registration, so
 *   accounts keep working after the server default changes.
 */
export const OPAQUE_ACCOUNT_FIELDS = {
  registrationRecord: "registrationRecord",
  credentialVersion: "opaqueCredentialVersion",
  keyStretching: "opaqueKeyStretching",
} as const;

/**
 * Bounds of a custom Argon2id profile. The maxima keep a profile within what serenity's wasm32
 * build can run (memory just below the 2 GiB of `"rfc-recommended"`, the largest profile serenity
 * ships, beyond which it reports browser crashes) and cap the work a server can ask of a client.
 * Memory is in KiB; RFC 9106 requires at least 8 KiB per lane.
 */
export const ARGON2ID_CUSTOM_LIMITS = {
  maxIterations: 64,
  maxMemory: 2 ** 21 - 1,
  maxParallelism: 64,
} as const;

/**
 * Serenity key-stretching profile applied by the client to the OPRF output (Argon2id).
 * Named profiles are serenity's; the custom form takes Argon2id parameters directly, within
 * {@link ARGON2ID_CUSTOM_LIMITS}, so a profile that passes this schema never makes serenity throw.
 */
export const keyStretchingSchema = z.union([
  z.literal("rfc-recommended"),
  z.literal("rfc-draft-recommended"),
  z.literal("memory-constrained"),
  z.strictObject({
    "argon2id-custom": z
      .strictObject({
        iterations: z.int().min(1).max(ARGON2ID_CUSTOM_LIMITS.maxIterations),
        memory: z.int().min(8).max(ARGON2ID_CUSTOM_LIMITS.maxMemory),
        parallelism: z.int().min(1).max(ARGON2ID_CUSTOM_LIMITS.maxParallelism),
      })
      .refine((params) => params.memory >= 8 * params.parallelism, {
        message: "memory must be at least 8 KiB per lane",
      }),
  }),
]);

/** Serenity key-stretching profile; structurally identical to serenity's `KeyStretchingFunctionConfig`. */
export type OpaqueKeyStretching = z.infer<typeof keyStretchingSchema>;

/** Profile used for new registrations when the server option is not set. */
export const DEFAULT_KEY_STRETCHING: OpaqueKeyStretching = "rfc-recommended";

/** A serenity protocol message, record, or state: unpadded base64url. */
const opaqueMessageSchema = z
  .string()
  .min(1)
  .max(4096)
  .regex(/^[A-Za-z0-9_-]+$/);

/** Opaque reference to a server-held, single-use state row. */
const stateIdSchema = z.string().min(1).max(128);

/** Password reset token as delivered in the reset URL (256 random bits, base64url). */
const resetTokenSchema = z.string().min(1).max(128);

/**
 * App payload committed with a new credential. The plugin treats it as opaque JSON and passes it
 * to the hooks unchanged; apps typically send data encrypted under a key derived from the export
 * key and validate it in `validatePayload`.
 */
const payloadSchema = z.unknown();

/**
 * Fields every registration-capable challenge returns besides the protocol message.
 * `serverIdentifier` is present only when the server option is set; the client must pass it to
 * serenity as `identifiers.server` or the protocol fails.
 */
const registrationChallengeFields = {
  stateId: stateIdSchema,
  registrationResponse: opaqueMessageSchema,
  keyStretching: keyStretchingSchema,
  serverIdentifier: z.string().optional(),
};

// Sign-up

/** `POST /sign-up/opaque/challenge`: starts a registration for a new user. */
export const signUpChallengeBodySchema = z.object({
  email: z.email(),
  registrationRequest: opaqueMessageSchema,
});

/** Response of `/sign-up/opaque/challenge`. `stateId` is valid for 5 minutes and single use. */
export const signUpChallengeResponseSchema = z.object(registrationChallengeFields);

/**
 * `POST /sign-up/opaque/complete`. Unknown keys are Better Auth user `additionalFields` and are
 * validated against the auth configuration by the server, like email/password sign-up.
 */
export const signUpCompleteBodySchema = z.looseObject({
  stateId: stateIdSchema,
  registrationRecord: opaqueMessageSchema,
  name: z.string(),
  image: z.string().optional(),
  callbackURL: z.string().optional(),
  rememberMe: z.boolean().optional(),
  payload: payloadSchema.optional(),
});

// Sign-in

/** `POST /sign-in/opaque/challenge`. The response shape is identical for unknown emails. */
export const signInChallengeBodySchema = z.object({
  email: z.email(),
  loginRequest: opaqueMessageSchema,
});

/**
 * Response of `/sign-in/opaque/challenge`. `keyStretching` is the account's stored profile, or
 * the server default for unknown emails. The server login state stays on the server; `stateId`
 * only references it.
 */
export const signInChallengeResponseSchema = z.object({
  stateId: stateIdSchema,
  loginResponse: opaqueMessageSchema,
  keyStretching: keyStretchingSchema,
  serverIdentifier: z.string().optional(),
});

/** `POST /sign-in/opaque/complete`. */
export const signInCompleteBodySchema = z.object({
  stateId: stateIdSchema,
  loginFinalization: opaqueMessageSchema,
  rememberMe: z.boolean().optional(),
});

/** Fetches the credential-bound payload after Better Auth verifies the second factor. Single use. */
export const signInPayloadBodySchema = z.object({ payloadToken: stateIdSchema });

/** Starts a session-bound OPAQUE login to authorize one two-factor management operation. */
export const passwordProofChallengeBodySchema = z.object({ loginRequest: opaqueMessageSchema });

/** The proof challenge uses the same login parameters as sign-in, without an email. */
export const passwordProofChallengeResponseSchema = signInChallengeResponseSchema;

/** Completes a password proof; neither password nor export key is transmitted. */
export const passwordProofCompleteBodySchema = z.object({
  stateId: stateIdSchema,
  loginFinalization: opaqueMessageSchema,
});

// Password change (requires a session)

/**
 * `POST /opaque/change-password/challenge`: one round trip carrying both a login for the current
 * password and a registration for the new one.
 */
export const changePasswordChallengeBodySchema = z.object({
  loginRequest: opaqueMessageSchema,
  registrationRequest: opaqueMessageSchema,
});

/**
 * Response of `/opaque/change-password/challenge`. `loginKeyStretching` is the current account's
 * stored profile; `keyStretching` is the profile for the new registration.
 */
export const changePasswordChallengeResponseSchema = z.object({
  ...registrationChallengeFields,
  loginResponse: opaqueMessageSchema,
  loginKeyStretching: keyStretchingSchema,
});

/** `POST /opaque/change-password/complete`. */
export const changePasswordCompleteBodySchema = z.object({
  stateId: stateIdSchema,
  loginFinalization: opaqueMessageSchema,
  registrationRecord: opaqueMessageSchema,
  payload: payloadSchema.optional(),
});

// Password reset

/** `POST /reset/opaque/verify`: checks a reset token without consuming it. */
export const resetVerifyBodySchema = z.object({
  token: resetTokenSchema,
});

/** `POST /reset/opaque/challenge`: consumes the reset token and starts the new registration. */
export const resetChallengeBodySchema = z.object({
  token: resetTokenSchema,
  registrationRequest: opaqueMessageSchema,
});

/** Response of `/reset/opaque/challenge`. */
export const resetChallengeResponseSchema = z.object(registrationChallengeFields);

/** `POST /reset/opaque/complete`. */
export const resetCompleteBodySchema = z.object({
  stateId: stateIdSchema,
  registrationRecord: opaqueMessageSchema,
  payload: payloadSchema.optional(),
});

/**
 * Body of the server-only `auth.api.createPasswordResetToken`. `revokePrevious` invalidates every
 * reset link issued earlier for the same user before minting the new one. `allowEnrolment` also
 * issues a link for an existing user without an OPAQUE credential (e.g. a classic email/password
 * user); completing it creates the user's first OPAQUE credential.
 */
export const createPasswordResetTokenBodySchema = z.object({
  email: z.email(),
  revokePrevious: z.boolean().optional(),
  allowEnrolment: z.boolean().optional(),
});

/** Body of the server-only `auth.api.revokePasswordResetTokens`. */
export const revokePasswordResetTokensBodySchema = z.object({
  email: z.email(),
});

// Attach (requires a session of a user with a classic Better Auth password)

/**
 * `POST /opaque/attach/challenge`: starts the registration of a first OPAQUE credential for the
 * signed-in user. `currentPassword` is the user's classic Better Auth password (which the server
 * already stores a hash of); it is required unless the server allows fresh sessions instead.
 */
export const attachChallengeBodySchema = z.object({
  registrationRequest: opaqueMessageSchema,
  currentPassword: z.string().min(1).max(1024).optional(),
});

/** Response of `/opaque/attach/challenge`. */
export const attachChallengeResponseSchema = z.object(registrationChallengeFields);

/** `POST /opaque/attach/complete`. */
export const attachCompleteBodySchema = z.object({
  stateId: stateIdSchema,
  registrationRecord: opaqueMessageSchema,
  payload: payloadSchema.optional(),
});

/**
 * Body of the server-only `auth.api.removeClassicCredential`: deletes the user's classic
 * `credential` account once an OPAQUE credential exists, e.g. to finish an interrupted migration.
 */
export const removeClassicCredentialBodySchema = z.object({
  userId: z.string().min(1),
});

// Responses carrying app payloads

/**
 * Response of `/sign-in/opaque/complete`. A pending second factor never includes a session or
 * payload; retain its single-use `payloadToken` until verification succeeds.
 */
export type SignInCompleteResponse<TUser = Record<string, unknown>> =
  | {
      token: string;
      user: TUser;
      payload: unknown;
      twoFactorRedirect?: false;
      twoFactorMethods?: never;
      payloadToken?: never;
    }
  | {
      twoFactorRedirect: true;
      twoFactorMethods: string[];
      payloadToken: string;
      token?: never;
      user?: never;
      payload?: never;
    };

/** Payload for the credential proved before 2FA; requires a new authenticated session. */
export type SignInPayloadResponse = { payload: unknown };

/** Single-use, five-minute authorization passed as `password` to a two-factor management call. */
export type PasswordProofResponse = { proof: string };

/**
 * Response of `/sign-up/opaque/complete`, matching Better Auth email/password sign-up: `token`
 * is `null` when no session is created (for example when email verification is required).
 */
export type SignUpCompleteResponse<TUser = Record<string, unknown>> = {
  token: string | null;
  user: TUser;
};

/** Response of `/reset/opaque/verify`: `loadPayload` output for the current credential. */
export type ResetVerifyResponse = {
  payload: unknown;
};

/** Response of `/reset/opaque/complete` and the server-only `revokePasswordResetTokens`. */
export type CredentialUpdateResponse = {
  status: true;
};

/**
 * Response of `/opaque/change-password/complete` and `/opaque/attach/complete`. Every session of
 * the user is revoked and the caller gets a new one: `token` is its session token (also set as
 * the session cookie).
 */
export type ChangePasswordResponse = {
  status: true;
  token: string;
};

/** Response of the server-only `auth.api.createPasswordResetToken`. */
export type CreatePasswordResetTokenResponse = {
  url: string;
  expiresAt: Date;
};

// Hooks

/**
 * Flow that triggered a hook. Reset verification and reset completion both use
 * `"reset-password"`. `"attach"` adds a first OPAQUE credential to a user who signs in with a
 * classic Better Auth password (`/opaque/attach/*`).
 */
export type OpaqueFlow = "sign-up" | "sign-in" | "change-password" | "reset-password" | "attach";

/** Flows that create a new credential and may carry a payload. */
export type OpaqueRegistrationFlow = Exclude<OpaqueFlow, "sign-in">;

/** Flows that put a new credential on an existing user, reported by `onCredentialChanged`. */
export type OpaqueCredentialChangeFlow = Exclude<OpaqueRegistrationFlow, "sign-up">;

/** Endpoint context passed to every hook as the second argument. */
export type OpaqueHookContext = GenericEndpointContext;

/**
 * App hooks for data that must stay consistent with the OPAQUE credential, typically material
 * encrypted under a key derived from the export key. A credential version is an opaque random
 * string minted per registration; payloads are stored per version so a failure at any step leaves
 * the payload of the credential the account record points to intact.
 *
 * Call order for registrations: `validatePayload` → `commitPayload` → account record update →
 * `activatePayload`. A throw before the account record update aborts the flow and the account
 * keeps pointing at the previous credential (for sign-up, the plugin deletes the user it created).
 * A throw from `activatePayload` is returned to the client, but the new credential stays active.
 *
 * During sign-up the hooks run while the plugin's database transaction is open (when the adapter
 * supports transactions). App writes join it only when they go through Better Auth's current
 * adapter; writes through a separate client are not rolled back and must tolerate a failed sign-up.
 */
export type OpaqueHooks = {
  /**
   * Rejects a payload before anything is written. Throw (preferably a Better Auth `APIError`) to
   * reject; the client receives the thrown error, or `INVALID_PAYLOAD` for non-API errors.
   * Called even when the client sent no payload (`payload` is `undefined`), so apps can require
   * one. `userId` is absent during sign-up because the user does not exist yet.
   */
  validatePayload?: (
    input: { payload: unknown; flow: OpaqueRegistrationFlow; userId?: string },
    ctx: OpaqueHookContext,
  ) => Promise<void> | void;
  /**
   * Stores the payload for `credentialVersion` without replacing payloads of other versions;
   * the account still points at the previous version when this runs. Required when the client
   * sends a payload. Must be idempotent per `(userId, credentialVersion)`.
   */
  commitPayload?: (
    input: {
      userId: string;
      credentialVersion: string;
      payload: unknown;
      flow: OpaqueRegistrationFlow;
    },
    ctx: OpaqueHookContext,
  ) => Promise<void> | void;
  /**
   * Called after the account record points to `credentialVersion`. `previousCredentialVersion`
   * is the version the record pointed to right before this switch (`null` on sign-up, on attach,
   * and on a reset that enrols a user without an OPAQUE credential).
   *
   * Delete only the payload of `previousCredentialVersion`, never "every version except
   * `credentialVersion`": activation runs after the switch, so a delayed activation of an older
   * switch, or a concurrent flow that already committed its payload but has not switched yet,
   * would otherwise lose the payload the record points to or one that is about to be. Payloads of
   * flows that lost a race stay behind; clean them up separately if needed. A failure here does
   * not roll back the credential change.
   */
  activatePayload?: (
    input: {
      userId: string;
      credentialVersion: string;
      previousCredentialVersion: string | null;
      flow: OpaqueRegistrationFlow;
    },
    ctx: OpaqueHookContext,
  ) => Promise<void> | void;
  /**
   * Loads the payload returned by sign-in complete and reset verify. `credentialVersion` is the
   * version the account record points to, so the result matches the credential the client just
   * used even if `activatePayload` never ran. It is `null` only for reset verify of an enrolment
   * link (`createPasswordResetToken({ allowEnrolment: true })` for a user without an OPAQUE
   * credential), so apps can return recovery material that is not bound to a credential. The
   * return value is sent to the client as-is.
   */
  loadPayload?: (
    input: {
      userId: string;
      credentialVersion: string | null;
      flow: Extract<OpaqueFlow, "sign-in" | "reset-password">;
    },
    ctx: OpaqueHookContext,
  ) => Promise<unknown> | unknown;
  /**
   * Called once per credential change of an existing user (password change, reset, attach) after
   * the account points at `credentialVersion` and the plugin tried to revoke every session of the
   * user, also when `activatePayload` failed. Use it for audit logs or notifying other devices. A
   * throw is returned to the client but does not roll anything back.
   *
   * `sessionsRevoked` is `false` when the revocation failed (its error is returned to the client):
   * sessions created with the previous password may then still be live, so revoke them yourself,
   * e.g. by retrying `ctx.context.internalAdapter.deleteUserSessions(userId)`. Revocation deletes
   * session rows only: with Better Auth's `session.cookieCache`, a revoked session stays usable
   * from its cache cookie until the cache entry expires, unless `cookieCache.version` changes, for
   * example a per-user version this hook bumps.
   */
  onCredentialChanged?: (
    input: {
      userId: string;
      flow: OpaqueCredentialChangeFlow;
      previousCredentialVersion: string | null;
      credentialVersion: string;
      /** Whether every session of the user was revoked. */
      sessionsRevoked: boolean;
    },
    ctx: OpaqueHookContext,
  ) => Promise<void> | void;
};
