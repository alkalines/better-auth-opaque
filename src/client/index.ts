/**
 * Better Auth client plugin for OPAQUE password authentication. Every action runs the serenity
 * OPAQUE client locally and performs the challenge and complete round trips itself.
 *
 * Secret handling: the password is only passed to serenity and never appears in a request; the
 * export key is derived locally, never sent, and returned to the caller only after the matching
 * complete call succeeded (RFC 9807 §10.4). The session key is never used as an export key.
 */
import type * as Serenity from "@serenity-kit/opaque";
import type { BetterAuthClientPlugin, BetterFetchOption, User } from "better-auth/client";
import type * as z from "zod";
import {
  OPAQUE_ERROR_CODES,
  OPAQUE_PATHS,
  OPAQUE_PLUGIN_ID,
  type CredentialUpdateResponse,
  type OpaqueKeyStretching,
  type ResetVerifyResponse,
  type SignInCompleteResponse,
  type SignUpCompleteResponse,
  type changePasswordChallengeResponseSchema,
  type resetChallengeResponseSchema,
  type signInChallengeResponseSchema,
  type signUpChallengeResponseSchema,
} from "../contract.ts";

/** Options of {@link opaqueClient}. */
export type OpaqueClientOptions = {
  /**
   * Pins the key-stretching profile for new registrations (sign-up, change, reset). When set and
   * the server advertises a different profile, the action fails with `KEY_STRETCHING_MISMATCH`
   * before anything is sent to the complete endpoint. Sign-in always uses the profile the server
   * stored for the account.
   */
  keyStretching?: OpaqueKeyStretching;
};

/**
 * Better Fetch options applied to every request of an action. `onSuccess` and `onError` only run
 * for the final complete request, so they fire once per action. Actions always resolve to
 * `{ data, error }`; `throw` is not supported.
 */
export type OpaqueFetchOptions = Omit<BetterFetchOption, "body" | "method" | "throw">;

/**
 * App payload committed with a new credential: a JSON value, or a callback that receives the new
 * export key (base64url) locally and returns the value, e.g. data encrypted under a key derived
 * from it. The export key itself never leaves the client.
 */
export type OpaquePayloadInput = ((exportKey: string) => unknown) | unknown;

/** Error of an action: an HTTP error body, or a local failure shaped like one. */
export type OpaqueClientError = {
  code?: string | undefined;
  message?: string | undefined;
  status: number;
  statusText: string;
};

/** Better Auth's result shape. */
export type OpaqueClientResult<T> =
  | { data: T; error: null }
  | { data: null; error: OpaqueClientError };

/** Input of `authClient.signUp.opaque`. Extra keys are Better Auth user `additionalFields`. */
export type OpaqueSignUpInput = {
  email: string;
  password: string;
  name: string;
  image?: string;
  callbackURL?: string;
  rememberMe?: boolean;
  payload?: OpaquePayloadInput;
  fetchOptions?: OpaqueFetchOptions;
  [additionalField: string]: unknown;
};

/** Input of `authClient.signIn.opaque`. */
export type OpaqueSignInInput = {
  email: string;
  password: string;
  rememberMe?: boolean;
  fetchOptions?: OpaqueFetchOptions;
};

/** Input of `authClient.opaque.changePassword`; requires a signed-in session. */
export type OpaqueChangePasswordInput = {
  currentPassword: string;
  newPassword: string;
  payload?: OpaquePayloadInput;
  fetchOptions?: OpaqueFetchOptions;
};

/** Input of `authClient.opaque.resetPassword`. */
export type OpaqueResetPasswordInput = {
  token: string;
  newPassword: string;
  payload?: OpaquePayloadInput;
  fetchOptions?: OpaqueFetchOptions;
};

/** Input of `authClient.opaque.verifyResetToken`. */
export type OpaqueVerifyResetTokenInput = {
  token: string;
  fetchOptions?: OpaqueFetchOptions;
};

/** The export key (base64url) of the credential the action just registered or proved. */
type WithExportKey<T> = T & { exportKey: string };

export type OpaqueSignUpData = WithExportKey<SignUpCompleteResponse<User>>;
export type OpaqueSignInData = WithExportKey<SignInCompleteResponse<User>>;
export type OpaqueCredentialUpdateData = WithExportKey<CredentialUpdateResponse>;

type SignUpChallengeResponse = z.infer<typeof signUpChallengeResponseSchema>;
type SignInChallengeResponse = z.infer<typeof signInChallengeResponseSchema>;
type ChangePasswordChallengeResponse = z.infer<typeof changePasswordChallengeResponseSchema>;
type ResetChallengeResponse = z.infer<typeof resetChallengeResponseSchema>;

/**
 * Error for a failure detected locally, before any complete call. Status and status text mirror
 * what Better Auth sends for the same code, so a local sign-in failure (wrong password or fake
 * record) looks like a server-side one.
 */
let serenityLoad: Promise<typeof Serenity> | undefined;

/**
 * Loads serenity on first use and waits for its WASM. Dynamic because serenity compiles its
 * inlined WASM while its module evaluates, and importing this entry must have no side effects.
 */
function loadSerenity(): Promise<typeof Serenity> {
  serenityLoad ??= import("@serenity-kit/opaque").then(async (serenity) => {
    await serenity.ready;
    return serenity;
  });
  return serenityLoad;
}

function localError(
  code: "INVALID_CREDENTIALS" | "INVALID_PASSWORD" | "KEY_STRETCHING_MISMATCH",
  status: number,
  statusText: string,
): { data: null; error: OpaqueClientError } {
  return {
    data: null,
    error: { code, message: OPAQUE_ERROR_CODES[code].message, status, statusText },
  };
}

function sameKeyStretching(a: OpaqueKeyStretching, b: OpaqueKeyStretching): boolean {
  if (typeof a === "string" || typeof b === "string") {
    return a === b;
  }
  const left = a["argon2id-custom"];
  const right = b["argon2id-custom"];
  return (
    left.iterations === right.iterations &&
    left.memory === right.memory &&
    left.parallelism === right.parallelism
  );
}

function keyStretchingMismatch(): { data: null; error: OpaqueClientError } {
  return localError("KEY_STRETCHING_MISMATCH", 400, "BAD_REQUEST");
}

/**
 * Finishes a registration locally: checks the pinned profile, runs serenity's
 * `finishRegistration` with the server-advertised profile and identifiers, then resolves the
 * payload (calling it with the export key when it is a callback). Returns `null` when the
 * advertised profile differs from the pinned one; nothing has been sent at that point.
 */
async function finishRegistration(input: {
  password: string;
  clientRegistrationState: string;
  challenge: SignUpChallengeResponse | ResetChallengeResponse | ChangePasswordChallengeResponse;
  payload: OpaquePayloadInput;
  pinnedKeyStretching: OpaqueKeyStretching | undefined;
}): Promise<{ registrationRecord: string; exportKey: string; payload: unknown } | null> {
  const { challenge, pinnedKeyStretching } = input;
  if (
    pinnedKeyStretching !== undefined &&
    !sameKeyStretching(pinnedKeyStretching, challenge.keyStretching)
  ) {
    return null;
  }
  const { client } = await loadSerenity();
  const { registrationRecord, exportKey } = client.finishRegistration({
    password: input.password,
    registrationResponse: challenge.registrationResponse,
    clientRegistrationState: input.clientRegistrationState,
    keyStretching: challenge.keyStretching,
    identifiers: serverIdentifiers(challenge.serverIdentifier),
  });
  const payload =
    typeof input.payload === "function" ? await input.payload(exportKey) : input.payload;
  return { registrationRecord, exportKey, payload };
}

/** Better Auth client plugin for the `opaque` server plugin. */
export function opaqueClient(options?: OpaqueClientOptions) {
  const pinnedKeyStretching = options?.keyStretching;

  return {
    id: OPAQUE_PLUGIN_ID,
    // The server endpoints are `scope: "server"`, so there are no inferred path actions; the
    // server plugin contributes its error codes.
    $InferServerPlugin: {} as {
      id: typeof OPAQUE_PLUGIN_ID;
      $ERROR_CODES: typeof OPAQUE_ERROR_CODES;
    },
    $ERROR_CODES: OPAQUE_ERROR_CODES,

    getActions: ($fetch, $store) => {
      /**
       * POSTs one protocol step. Challenge steps drop `onSuccess`/`onError` so those callbacks
       * describe the outcome of the whole action. `throw: false` overrides a client-wide
       * `throw: true` so actions can always inspect `{ data, error }`.
       */
      async function post<T>(
        path: string,
        body: Record<string, unknown>,
        fetchOptions: OpaqueFetchOptions | undefined,
        step: "challenge" | "complete",
      ): Promise<OpaqueClientResult<T>> {
        let requestOptions = fetchOptions ?? {};
        if (step === "challenge") {
          const { onSuccess: _onSuccess, onError: _onError, ...rest } = requestOptions;
          requestOptions = rest;
        }
        const result = await $fetch<T>(path, {
          ...requestOptions,
          method: "POST",
          body,
          throw: false,
        });
        if (result.error) {
          return { data: null, error: result.error as OpaqueClientError };
        }
        return { data: result.data as T, error: null };
      }

      return {
        signUp: {
          /**
           * Registers a new user with an OPAQUE credential. Creates a session like
           * email/password sign-up (unless verification is required or auto sign-in is off).
           */
          opaque: async (
            input: OpaqueSignUpInput,
          ): Promise<OpaqueClientResult<OpaqueSignUpData>> => {
            const { email, password, payload, fetchOptions, ...userFields } = input;
            const { client } = await loadSerenity();

            const registration = client.startRegistration({ password });
            const challenge = await post<SignUpChallengeResponse>(
              OPAQUE_PATHS.signUpChallenge,
              { email, registrationRequest: registration.registrationRequest },
              fetchOptions,
              "challenge",
            );
            if (challenge.error) {
              return challenge;
            }

            const finished = await finishRegistration({
              password,
              clientRegistrationState: registration.clientRegistrationState,
              challenge: challenge.data,
              payload,
              pinnedKeyStretching,
            });
            if (!finished) {
              return keyStretchingMismatch();
            }

            const complete = await post<SignUpCompleteResponse<User>>(
              OPAQUE_PATHS.signUpComplete,
              {
                ...userFields,
                stateId: challenge.data.stateId,
                registrationRecord: finished.registrationRecord,
                payload: finished.payload,
              },
              fetchOptions,
              "complete",
            );
            if (complete.error) {
              return complete;
            }
            $store.notify("$sessionSignal");
            return { data: { ...complete.data, exportKey: finished.exportKey }, error: null };
          },
        },

        signIn: {
          /**
           * Signs in with email and password. A wrong password and an unknown email produce the
           * same `INVALID_CREDENTIALS` error; when the local OPAQUE step already fails, no
           * complete request is made.
           */
          opaque: async (
            input: OpaqueSignInInput,
          ): Promise<OpaqueClientResult<OpaqueSignInData>> => {
            const { client } = await loadSerenity();

            const login = client.startLogin({ password: input.password });
            const challenge = await post<SignInChallengeResponse>(
              OPAQUE_PATHS.signInChallenge,
              { email: input.email, loginRequest: login.startLoginRequest },
              input.fetchOptions,
              "challenge",
            );
            if (challenge.error) {
              return challenge;
            }

            const finished = client.finishLogin({
              clientLoginState: login.clientLoginState,
              loginResponse: challenge.data.loginResponse,
              password: input.password,
              keyStretching: challenge.data.keyStretching,
              identifiers: serverIdentifiers(challenge.data.serverIdentifier),
            });
            if (!finished) {
              return localError("INVALID_CREDENTIALS", 401, "UNAUTHORIZED");
            }

            const complete = await post<SignInCompleteResponse<User>>(
              OPAQUE_PATHS.signInComplete,
              {
                stateId: challenge.data.stateId,
                loginFinalization: finished.finishLoginRequest,
                rememberMe: input.rememberMe,
              },
              input.fetchOptions,
              "complete",
            );
            if (complete.error) {
              return complete;
            }
            $store.notify("$sessionSignal");
            return { data: { ...complete.data, exportKey: finished.exportKey }, error: null };
          },
        },

        opaque: {
          /**
           * Changes the password of the signed-in user: proves the current password and
           * registers the new one in a single challenge/complete pair. Other sessions are
           * revoked; the current one stays.
           */
          changePassword: async (
            input: OpaqueChangePasswordInput,
          ): Promise<OpaqueClientResult<OpaqueCredentialUpdateData>> => {
            const { client } = await loadSerenity();

            const login = client.startLogin({ password: input.currentPassword });
            const registration = client.startRegistration({ password: input.newPassword });
            const challenge = await post<ChangePasswordChallengeResponse>(
              OPAQUE_PATHS.changePasswordChallenge,
              {
                loginRequest: login.startLoginRequest,
                registrationRequest: registration.registrationRequest,
              },
              input.fetchOptions,
              "challenge",
            );
            if (challenge.error) {
              return challenge;
            }

            const proven = client.finishLogin({
              clientLoginState: login.clientLoginState,
              loginResponse: challenge.data.loginResponse,
              password: input.currentPassword,
              keyStretching: challenge.data.loginKeyStretching,
              identifiers: serverIdentifiers(challenge.data.serverIdentifier),
            });
            if (!proven) {
              return localError("INVALID_PASSWORD", 400, "BAD_REQUEST");
            }

            const finished = await finishRegistration({
              password: input.newPassword,
              clientRegistrationState: registration.clientRegistrationState,
              challenge: challenge.data,
              payload: input.payload,
              pinnedKeyStretching,
            });
            if (!finished) {
              return keyStretchingMismatch();
            }

            const complete = await post<CredentialUpdateResponse>(
              OPAQUE_PATHS.changePasswordComplete,
              {
                stateId: challenge.data.stateId,
                loginFinalization: proven.finishLoginRequest,
                registrationRecord: finished.registrationRecord,
                payload: finished.payload,
              },
              input.fetchOptions,
              "complete",
            );
            if (complete.error) {
              return complete;
            }
            $store.notify("$sessionSignal");
            return { data: { ...complete.data, exportKey: finished.exportKey }, error: null };
          },

          /**
           * Sets a new password with a reset token. The token is consumed by the challenge, so
           * a failed attempt needs a new token. Every session of the user is revoked.
           */
          resetPassword: async (
            input: OpaqueResetPasswordInput,
          ): Promise<OpaqueClientResult<OpaqueCredentialUpdateData>> => {
            const { client } = await loadSerenity();

            const registration = client.startRegistration({ password: input.newPassword });
            const challenge = await post<ResetChallengeResponse>(
              OPAQUE_PATHS.resetChallenge,
              { token: input.token, registrationRequest: registration.registrationRequest },
              input.fetchOptions,
              "challenge",
            );
            if (challenge.error) {
              return challenge;
            }

            const finished = await finishRegistration({
              password: input.newPassword,
              clientRegistrationState: registration.clientRegistrationState,
              challenge: challenge.data,
              payload: input.payload,
              pinnedKeyStretching,
            });
            if (!finished) {
              return keyStretchingMismatch();
            }

            const complete = await post<CredentialUpdateResponse>(
              OPAQUE_PATHS.resetComplete,
              {
                stateId: challenge.data.stateId,
                registrationRecord: finished.registrationRecord,
                payload: finished.payload,
              },
              input.fetchOptions,
              "complete",
            );
            if (complete.error) {
              return complete;
            }
            $store.notify("$sessionSignal");
            return { data: { ...complete.data, exportKey: finished.exportKey }, error: null };
          },

          /**
           * Checks a reset token without consuming it and returns the app payload of the
           * current credential (`loadPayload`), e.g. to show what a reset will replace.
           */
          verifyResetToken: (
            input: OpaqueVerifyResetTokenInput,
          ): Promise<OpaqueClientResult<ResetVerifyResponse>> =>
            post<ResetVerifyResponse>(
              OPAQUE_PATHS.resetVerify,
              { token: input.token },
              input.fetchOptions,
              "complete",
            ),
        },
      };
    },
  } satisfies BetterAuthClientPlugin;
}

function serverIdentifiers(serverIdentifier: string | undefined): { server: string } | undefined {
  return serverIdentifier === undefined ? undefined : { server: serverIdentifier };
}
