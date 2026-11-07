import type * as Serenity from "@serenity-kit/opaque";
import { APIError } from "better-auth/api";
import {
  DEFAULT_KEY_STRETCHING,
  OPAQUE_ERROR_CODES,
  type OpaqueHooks,
  type OpaqueKeyStretching,
} from "../contract.ts";

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
  /** Enables `auth.api.createPasswordResetToken`; the app delivers the URL itself. */
  passwordReset?: {
    /** Token lifetime in seconds. Defaults to 3600. */
    expiresIn?: number;
    /** Builds the link sent to the user from the raw token (only its SHA-256 is stored). */
    url: (token: string) => string;
  };
};

const DEFAULT_RESET_EXPIRES_IN_SECONDS = 3600;

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
  passwordReset: { expiresIn: number; url: (token: string) => string } | undefined;
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

  const serverSetup = options.serverSetup;
  const serverIdentifier = options.serverIdentifier;
  const identifiers = serverIdentifier === undefined ? undefined : { server: serverIdentifier };
  let publicKeyCheck: Promise<string | null> | undefined;

  return {
    keyStretching: options.keyStretching ?? DEFAULT_KEY_STRETCHING,
    hooks: options.hooks ?? {},
    passwordReset: options.passwordReset && {
      expiresIn: options.passwordReset.expiresIn ?? DEFAULT_RESET_EXPIRES_IN_SECONDS,
      url: options.passwordReset.url,
    },
    challengeIdentity: serverIdentifier === undefined ? {} : { serverIdentifier },

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
  };
}
