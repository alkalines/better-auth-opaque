import type * as Serenity from "@serenity-kit/opaque";
import type { GenericEndpointContext } from "better-auth";
import { APIError } from "better-auth/api";
import * as z from "zod";
import {
  DEFAULT_KEY_STRETCHING,
  OPAQUE_ERROR_CODES,
  keyStretchingSchema,
  type OpaqueHookContext,
  type OpaqueHooks,
  type OpaqueKeyStretching,
} from "../contract.ts";
import { hmacSha256, randomToken } from "./crypto.ts";

/** Password-guessing surfaces that consult {@link OpaqueOptions.accountRateLimit}. */
export type OpaqueRateLimitedFlow = "sign-in" | "password-proof" | "change-password" | "attach";

/** Options of the `opaque` server plugin. */
export type OpaqueOptions = {
  /**
   * Serenity server setup from `better-auth-opaque create-setup`. Required. It holds the server's
   * long-term OPRF seed and key pair: treat it like a database encryption key, keep a backup, and
   * never rotate it casually, because every stored registration record depends on it. A missing
   * value throws at construction; an invalid value makes every flow fail with
   * `INVALID_SERVER_SETUP` (check at boot with `auth.api.validateOpaqueSetup()`).
   */
  serverSetup: string;
  /**
   * Key-stretching profile for new registrations (sign-up, password change, reset). Defaults to
   * `"rfc-recommended"`. Each account stores the profile it was registered with and sign-in uses
   * the stored one, so changing this default only affects future registrations.
   */
  keyStretching?: OpaqueKeyStretching;
  /**
   * Optional OPAQUE server identity bound into every registration record. Unset by default (the
   * protocol then uses the server public key). Changing, adding, or removing it after accounts
   * exist makes **every existing record unusable**; treat it as permanent.
   */
  serverIdentifier?: string;
  /** App hooks that keep app payloads consistent with credential versions. */
  hooks?: OpaqueHooks;
  /**
   * Per-account throttle for the password-guessing surfaces, complementing Better Auth's per-IP
   * rate limit (which does not stop guessing from many IPs). Called before each attempt with
   * `key`, an HMAC-SHA-256 of the lowercased email under the Better Auth secret: stable per
   * account, computed the same way for unknown emails so the hook's decision cannot reveal
   * whether an email exists, and not reversible to the email. Return `false` to refuse the
   * attempt with `TOO_MANY_ATTEMPTS` (429). Typically backed by a shared store with a sliding
   * window; the plugin keeps no counters itself.
   */
  accountRateLimit?: (
    input: { key: string; flow: OpaqueRateLimitedFlow },
    ctx: OpaqueHookContext,
  ) => boolean | Promise<boolean>;
  /**
   * `/opaque/attach/*`: lets a signed-in user with a classic Better Auth password add a first
   * OPAQUE credential (migration). The classic password is required by default.
   */
  attach?: {
    /**
     * Require the classic password at the attach challenge. Defaults to `true`. When `false`, a
     * session younger than `freshSessionAge` may attach without it, so a stolen fresh session can
     * replace the user's password; only disable this for flows that attach right after sign-in.
     */
    requireCurrentPassword?: boolean;
    /** Maximum session age in seconds when the classic password is not presented. Defaults to 600. */
    freshSessionAge?: number;
  };
  /**
   * Delete the user's classic `credential` account once an OPAQUE credential was attached or
   * created by an enrolment reset, so the old password stops working. Defaults to `true`.
   */
  removeClassicCredential?: boolean;
  /**
   * Rejects OPAQUE sign-up (challenge and complete) with `SIGN_UP_DISABLED`. Defaults to Better
   * Auth's `emailAndPassword.disableSignUp`, so closing registration there closes it here too.
   */
  disableSignUp?: boolean;
  /** Enables `auth.api.createPasswordResetToken`; the app delivers the URL itself. */
  passwordReset?: {
    /** Token lifetime in seconds, at most 7 days. Defaults to 3600. */
    expiresIn?: number;
    /** Builds the link sent to the user from the raw token (only its SHA-256 is stored). */
    url: (token: string) => string;
  };
};

const DEFAULT_RESET_EXPIRES_IN_SECONDS = 3600;
const MAX_RESET_EXPIRES_IN_SECONDS = 7 * 24 * 60 * 60;
const DEFAULT_ATTACH_FRESH_SESSION_AGE_SECONDS = 600;

const isFunction = (value: unknown) => typeof value === "function";

/**
 * Shape checks for the plain-data options, run at construction so a typo fails the deployment
 * instead of weakening a flow at runtime (e.g. an unparseable `keyStretching` reaching clients).
 */
const optionsSchema = z.looseObject({
  keyStretching: keyStretchingSchema.optional(),
  serverIdentifier: z.string().min(1).optional(),
  hooks: z.record(z.string(), z.custom(isFunction)).optional(),
  accountRateLimit: z.custom(isFunction).optional(),
  disableSignUp: z.boolean().optional(),
  removeClassicCredential: z.boolean().optional(),
  attach: z
    .strictObject({
      requireCurrentPassword: z.boolean().optional(),
      freshSessionAge: z.int().positive().optional(),
    })
    .optional(),
  passwordReset: z
    .strictObject({
      expiresIn: z.int().positive().max(MAX_RESET_EXPIRES_IN_SECONDS).optional(),
      url: z.custom(isFunction),
    })
    .optional(),
});

let serenityLoad: Promise<typeof Serenity> | undefined;

/**
 * Loads serenity on first use and waits for its WASM. Dynamic because serenity compiles its
 * inlined WASM while its module evaluates, and importing this package must have no side effects.
 * The promise is cached, so the module is compiled once per process.
 */
function loadSerenity(): Promise<typeof Serenity> {
  serenityLoad ??= import("@serenity-kit/opaque").then(async (serenity) => {
    await serenity.ready;
    return serenity;
  });
  return serenityLoad;
}

/**
 * Resolved plugin options plus the serenity server calls, bound to the configured setup and
 * server identifier. Every endpoint awaits {@link requireServerPublicKey} before anything else.
 */
export type OpaqueRuntime = {
  /** Profile captured by registration challenges and stored on the account at complete. */
  keyStretching: OpaqueKeyStretching;
  hooks: OpaqueHooks;
  /** Explicit `disableSignUp` option; `undefined` defers to `emailAndPassword.disableSignUp`. */
  disableSignUp: boolean | undefined;
  passwordReset: { expiresIn: number; url: (token: string) => string } | undefined;
  attach: { requireCurrentPassword: boolean; freshSessionAge: number };
  removeClassicCredential: boolean;
  /**
   * Consults `accountRateLimit` for the account with `email` (no-op without the option); throws
   * `TOO_MANY_ATTEMPTS` when the app refuses. Call it before any work that depends on whether the
   * email exists.
   */
  checkAccountRateLimit: (
    ctx: GenericEndpointContext,
    email: string,
    flow: OpaqueRateLimitedFlow,
  ) => Promise<void>;
  /** Fields every challenge response carries so the client passes the same identifiers. */
  challengeIdentity: { serverIdentifier?: string };
  /**
   * Loads serenity and resolves the server public key. Every flow calls this first, so an
   * invalid setup fails closed with `INVALID_SERVER_SETUP` before anything is read or written.
   */
  requireServerPublicKey: () => Promise<string>;
  /** Registration response for `userIdentifier`; `INVALID_OPAQUE_MESSAGE` for malformed input. */
  createRegistrationResponse: (
    userIdentifier: string,
    registrationRequest: string,
  ) => Promise<string>;
  /**
   * Starts a server login. `registrationRecord: null` produces serenity's fake response, which is
   * indistinguishable from a real one without the password. A malformed request fails with
   * `INVALID_OPAQUE_MESSAGE` on both paths.
   */
  startLogin: (
    userIdentifier: string,
    registrationRecord: string | null,
    startLoginRequest: string,
  ) => Promise<{ serverLoginState: string; loginResponse: string }>;
  /** Whether the client's finalization proves knowledge of the password; never throws. */
  verifyLogin: (serverLoginState: string, finishLoginRequest: string) => Promise<boolean>;
  /**
   * Rejects a registration record serenity cannot load, before it is stored: a malformed record
   * would otherwise make the account unusable. Throws `INVALID_OPAQUE_MESSAGE`. This is a
   * structural check only; it cannot tell whether the client used the right password.
   */
  validateRegistrationRecord: (userIdentifier: string, registrationRecord: string) => Promise<void>;
};

/**
 * Validates the options that can be checked synchronously and builds the shared runtime. The
 * setup itself is validated lazily because serenity's WASM loads on first use, and the plugin
 * must not do work at import or construction time. Never generates a setup.
 */
export function createRuntime(options: OpaqueOptions): OpaqueRuntime {
  if (typeof options?.serverSetup !== "string" || options.serverSetup.length === 0) {
    throw new Error(
      "opaque(): `serverSetup` is required. Generate one with `better-auth-opaque create-setup` and keep a backup.",
    );
  }
  const parsed = optionsSchema.safeParse(options);
  if (!parsed.success) {
    throw new Error(`opaque(): invalid options.\n${z.prettifyError(parsed.error)}`);
  }

  const serverSetup = options.serverSetup;
  const serverIdentifier = options.serverIdentifier;
  const identifiers = serverIdentifier === undefined ? undefined : { server: serverIdentifier };
  let publicKeyCheck: Promise<string | null> | undefined;

  return {
    keyStretching: options.keyStretching ?? DEFAULT_KEY_STRETCHING,
    hooks: options.hooks ?? {},
    disableSignUp: options.disableSignUp,
    passwordReset: options.passwordReset && {
      expiresIn: options.passwordReset.expiresIn ?? DEFAULT_RESET_EXPIRES_IN_SECONDS,
      url: options.passwordReset.url,
    },
    attach: {
      requireCurrentPassword: options.attach?.requireCurrentPassword ?? true,
      freshSessionAge: options.attach?.freshSessionAge ?? DEFAULT_ATTACH_FRESH_SESSION_AGE_SECONDS,
    },
    removeClassicCredential: options.removeClassicCredential ?? true,
    challengeIdentity: serverIdentifier === undefined ? {} : { serverIdentifier },

    async checkAccountRateLimit(ctx, email, flow) {
      const accountRateLimit = options.accountRateLimit;
      if (!accountRateLimit) {
        return;
      }
      const key = await hmacSha256(ctx.context.secret, `opaque/account/${email.toLowerCase()}`);
      if (!(await accountRateLimit({ key, flow }, ctx))) {
        throw APIError.from("TOO_MANY_REQUESTS", OPAQUE_ERROR_CODES.TOO_MANY_ATTEMPTS);
      }
    },

    async requireServerPublicKey() {
      publicKeyCheck ??= loadSerenity().then(({ server }) => {
        try {
          return server.getPublicKey(serverSetup);
        } catch {
          return null;
        }
      });
      const publicKey = await publicKeyCheck;
      if (publicKey === null) {
        throw APIError.from("INTERNAL_SERVER_ERROR", OPAQUE_ERROR_CODES.INVALID_SERVER_SETUP);
      }
      return publicKey;
    },

    async createRegistrationResponse(userIdentifier, registrationRequest) {
      const { server } = await loadSerenity();
      try {
        return server.createRegistrationResponse({
          serverSetup,
          userIdentifier,
          registrationRequest,
        }).registrationResponse;
      } catch {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_OPAQUE_MESSAGE);
      }
    },

    async startLogin(userIdentifier, registrationRecord, startLoginRequest) {
      const { server } = await loadSerenity();
      try {
        return server.startLogin({
          serverSetup,
          userIdentifier,
          registrationRecord,
          startLoginRequest,
          identifiers,
        });
      } catch {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_OPAQUE_MESSAGE);
      }
    },

    async verifyLogin(serverLoginState, finishLoginRequest) {
      const { server } = await loadSerenity();
      try {
        server.finishLogin({ serverLoginState, finishLoginRequest, identifiers });
        return true;
      } catch {
        return false;
      }
    },

    async validateRegistrationRecord(userIdentifier, registrationRecord) {
      const { client, server } = await loadSerenity();
      // A throwaway login against the record makes serenity deserialize it; the password is
      // random because the result is discarded.
      const { startLoginRequest } = client.startLogin({ password: randomToken() });
      try {
        server.startLogin({
          serverSetup,
          userIdentifier,
          registrationRecord,
          startLoginRequest,
          identifiers,
        });
      } catch {
        throw APIError.from("BAD_REQUEST", OPAQUE_ERROR_CODES.INVALID_OPAQUE_MESSAGE);
      }
    },
  };
}
