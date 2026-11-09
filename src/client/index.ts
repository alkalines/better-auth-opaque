/**
 * Better Auth client plugin for OPAQUE password authentication. Every action runs the serenity
 * OPAQUE client locally and performs the challenge and complete round trips itself.
 *
 * Secret handling: the OPAQUE password is only passed to serenity and never appears in a request.
 * Attaching may send the existing classic password, never the new OPAQUE password. The export key
 * stays local and is returned only after complete succeeds (RFC 9807 §10.4); it is never a session key.
 */
import type * as Serenity from "@serenity-kit/opaque";
import type { BetterAuthClientPlugin, BetterFetchOption, User } from "better-auth/client";
import * as z from "zod";
import {
  OPAQUE_ERROR_CODES,
  OPAQUE_PATHS,
  OPAQUE_PLUGIN_ID,
  type CredentialUpdateResponse,
  type ChangePasswordResponse,
  type OpaqueKeyStretching,
  type ResetVerifyResponse,
  type PasswordProofResponse,
  type SignInPayloadResponse,
  type SignInCompleteResponse,
  type SignUpCompleteResponse,
  attachChallengeResponseSchema,
  changePasswordChallengeResponseSchema,
  keyStretchingSchema,
  resetChallengeResponseSchema,
  signInChallengeResponseSchema,
  passwordProofChallengeResponseSchema,
  signUpChallengeResponseSchema,
} from "../contract.ts";

/** Named serenity profiles with at least `memory-constrained` strength and bounded memory (about 2 GiB). */
export const DEFAULT_ALLOWED_KEY_STRETCHING: readonly OpaqueKeyStretching[] = Object.freeze([
  "rfc-recommended",
  "rfc-draft-recommended",
  "memory-constrained",
]);

/** Client-controlled allowlists checked before deriving any key from a server challenge. */
export type OpaqueKeyStretchingPolicy = {
  /** Profiles accepted for sign-up, attach, change and reset. Defaults to {@link DEFAULT_ALLOWED_KEY_STRETCHING}. */
  registration?: readonly OpaqueKeyStretching[];
  /**
   * Profiles accepted for sign-in, password proof and the current password during a change.
   * Defaults to {@link DEFAULT_ALLOWED_KEY_STRETCHING} plus every registration profile.
   * An explicit list replaces that default, allowing older stored profiles to be retired.
   */
  login?: readonly OpaqueKeyStretching[];
};

/** Options of {@link opaqueClient}; invalid options throw at plugin construction. */
export type OpaqueClientOptions = {
  keyStretching?: OpaqueKeyStretchingPolicy;
};

const clientOptionsSchema = z.strictObject({
  keyStretching: z
    .strictObject({
      registration: z.array(keyStretchingSchema).min(1).optional(),
      login: z.array(keyStretchingSchema).min(1).optional(),
    })
    .optional(),
});

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

/**
 * Input of `opaque.attachCredential`; requires a session for a classic email/password user.
 * Only `currentPassword` (the classic password) is sent to the server. The new OPAQUE password
 * must differ; when `currentPassword` is omitted the client cannot check for password reuse.
 */
export type OpaqueAttachCredentialInput = {
  newPassword: string;
  currentPassword?: string;
  payload?: OpaquePayloadInput;
  fetchOptions?: OpaqueFetchOptions;
};

/** Input of `authClient.opaque.verifyResetToken`. */
export type OpaqueVerifyResetTokenInput = {
  token: string;
  fetchOptions?: OpaqueFetchOptions;
};

/** Input of `opaque.loadSignInPayload`; call only after a successful second-factor verification. */
export type OpaqueLoadSignInPayloadInput = {
  payloadToken: string;
  fetchOptions?: OpaqueFetchOptions;
};

/** Input of `opaque.createPasswordProof`; the password stays local. Requires a session. */
export type OpaqueCreatePasswordProofInput = {
  password: string;
  fetchOptions?: OpaqueFetchOptions;
};

/**
 * The export key (base64url) of the credential the completed OPAQUE step registered or proved.
 * Sign-in may still require 2FA: the key is locally derivable with the password, but the server
 * withholds the credential payload until the second factor succeeds.
 */
type WithExportKey<T> = T & { exportKey: string };

export type OpaqueSignUpData = WithExportKey<SignUpCompleteResponse<User>>;
/** A completed OPAQUE proof, with either a session/payload or a pending second-factor challenge. */
export type OpaqueSignInData = WithExportKey<SignInCompleteResponse<User>>;
export type OpaqueCredentialUpdateData = WithExportKey<CredentialUpdateResponse>;
/** Password change result, including the replacement session token and new credential export key. */
export type OpaqueChangePasswordData = WithExportKey<ChangePasswordResponse>;
/** First OPAQUE credential result, including the replacement session token and export key. */
export type OpaqueAttachCredentialData = WithExportKey<ChangePasswordResponse>;

type SignUpChallengeResponse = z.infer<typeof signUpChallengeResponseSchema>;
type SignInChallengeResponse = z.infer<typeof signInChallengeResponseSchema>;
type ChangePasswordChallengeResponse = z.infer<typeof changePasswordChallengeResponseSchema>;
type ResetChallengeResponse = z.infer<typeof resetChallengeResponseSchema>;
type PasswordProofChallengeResponse = z.infer<typeof passwordProofChallengeResponseSchema>;
type AttachChallengeResponse = z.infer<typeof attachChallengeResponseSchema>;

/** Shared lazy WASM load; importing the client entry itself performs no cryptographic work. */
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

/**
 * Local protocol failures retain Better Auth's status conventions. Malformed challenges and
 * serenity processing exceptions use `INVALID_SERVER_RESPONSE` with 502 `BAD_GATEWAY`.
 */
function localError(
  code:
    | "INVALID_CREDENTIALS"
    | "INVALID_PASSWORD"
    | "KEY_STRETCHING_MISMATCH"
    | "INVALID_SERVER_RESPONSE"
    | "PASSWORD_REUSED",
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
 * Finishes an allowed registration and resolves its app payload. Only serenity exceptions are
 * converted to protocol errors; payload callback exceptions remain application failures.
 */
async function finishRegistration(input: {
  password: string;
  clientRegistrationState: string;
  challenge: SignUpChallengeResponse | ResetChallengeResponse | ChangePasswordChallengeResponse;
  payload: OpaquePayloadInput;
  allowedKeyStretching: readonly OpaqueKeyStretching[];
}): Promise<
  OpaqueClientResult<{ registrationRecord: string; exportKey: string; payload: unknown }>
> {
  const { challenge } = input;
  if (
    !input.allowedKeyStretching.some((profile) =>
      sameKeyStretching(profile, challenge.keyStretching),
    )
  ) {
    return keyStretchingMismatch();
  }
  const { client } = await loadSerenity();
  let finished: Serenity.client.FinishRegistrationResult;
  try {
    finished = client.finishRegistration({
      password: input.password,
      registrationResponse: challenge.registrationResponse,
      clientRegistrationState: input.clientRegistrationState,
      keyStretching: challenge.keyStretching,
      identifiers: serverIdentifiers(challenge.serverIdentifier),
    });
  } catch {
    return localError("INVALID_SERVER_RESPONSE", 502, "BAD_GATEWAY");
  }
  const payload =
    typeof input.payload === "function" ? await input.payload(finished.exportKey) : input.payload;
  return { data: { ...finished, payload }, error: null };
}

/** Isolates untrusted login-response processing; an undefined result still means wrong password. */
function finishLogin(
  client: typeof Serenity.client,
  input: Serenity.client.FinishLoginParams,
): OpaqueClientResult<Serenity.client.FinishLoginResult | undefined> {
  try {
    return { data: client.finishLogin(input), error: null };
  } catch {
    return localError("INVALID_SERVER_RESPONSE", 502, "BAD_GATEWAY");
  }
}

/**
 * Better Auth client plugin for the `opaque` server plugin. Server-advertised profiles must
 * match the local policy exactly before key derivation; invalid configuration throws an Error.
 */
export function opaqueClient(options?: OpaqueClientOptions) {
  const parsedOptions = clientOptionsSchema.safeParse(options === undefined ? {} : options);
  if (!parsedOptions.success) {
    throw new Error(`Invalid opaqueClient options: ${parsedOptions.error.message}`);
  }
  const registrationProfiles =
    parsedOptions.data.keyStretching?.registration ?? DEFAULT_ALLOWED_KEY_STRETCHING;
  const loginProfiles = parsedOptions.data.keyStretching?.login ?? [
    ...DEFAULT_ALLOWED_KEY_STRETCHING,
    ...registrationProfiles,
  ];

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
        responseSchema?: z.ZodType<T>,
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
        if (responseSchema) {
          const parsed = responseSchema.safeParse(result.data);
          if (!parsed.success) return localError("INVALID_SERVER_RESPONSE", 502, "BAD_GATEWAY");
          return { data: parsed.data, error: null };
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
              signUpChallengeResponseSchema,
            );
            if (challenge.error) {
              return challenge;
            }

            const finished = await finishRegistration({
              password,
              clientRegistrationState: registration.clientRegistrationState,
              challenge: challenge.data,
              payload,
              allowedKeyStretching: registrationProfiles,
            });
            if (finished.error) {
              return finished;
            }

            const complete = await post<SignUpCompleteResponse<User>>(
              OPAQUE_PATHS.signUpComplete,
              {
                ...userFields,
                stateId: challenge.data.stateId,
                registrationRecord: finished.data.registrationRecord,
                payload: finished.data.payload,
              },
              fetchOptions,
              "complete",
            );
            if (complete.error) {
              return complete;
            }
            $store.notify("$sessionSignal");
            return { data: { ...complete.data, exportKey: finished.data.exportKey }, error: null };
          },
        },

        signIn: {
          /**
           * Signs in with email and password. A wrong password and an unknown email produce the
           * same `INVALID_CREDENTIALS` error; when the local OPAQUE step already fails, no
           * complete request is made. A 2FA redirect also returns the locally derived export key,
           * but never a session or payload; verify the second factor, then call loadSignInPayload.
           * The server's stored profile must be accepted by the local login policy.
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
              signInChallengeResponseSchema,
            );
            if (challenge.error) {
              return challenge;
            }

            if (
              !loginProfiles.some((profile) =>
                sameKeyStretching(profile, challenge.data.keyStretching),
              )
            ) {
              return keyStretchingMismatch();
            }
            const processed = finishLogin(client, {
              clientLoginState: login.clientLoginState,
              loginResponse: challenge.data.loginResponse,
              password: input.password,
              keyStretching: challenge.data.keyStretching,
              identifiers: serverIdentifiers(challenge.data.serverIdentifier),
            });
            if (processed.error) return processed;
            const finished = processed.data;
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
            if (!complete.data.twoFactorRedirect) $store.notify("$sessionSignal");
            return { data: { ...complete.data, exportKey: finished.exportKey }, error: null };
          },
        },

        opaque: {
          /**
           * Attaches a first OPAQUE credential to a signed-in classic email/password user.
           * `newPassword` stays local. `currentPassword` is sent only to the challenge endpoint
           * and must differ from the new password, since the server knows the classic password.
           * When omitted (if the server allows fresh sessions), reuse cannot be checked locally.
           * The registration policy is enforced before derivation or payload construction.
           * All sessions are replaced with a new caller session; the export key is returned only
           * after complete succeeds. A failed challenge/complete requires restarting the action.
           */
          attachCredential: async (
            input: OpaqueAttachCredentialInput,
          ): Promise<OpaqueClientResult<OpaqueAttachCredentialData>> => {
            if (
              input.currentPassword !== undefined &&
              input.currentPassword === input.newPassword
            ) {
              return localError("PASSWORD_REUSED", 400, "BAD_REQUEST");
            }
            const { client } = await loadSerenity();
            const registration = client.startRegistration({ password: input.newPassword });
            const challenge = await post<AttachChallengeResponse>(
              OPAQUE_PATHS.attachChallenge,
              {
                registrationRequest: registration.registrationRequest,
                currentPassword: input.currentPassword,
              },
              input.fetchOptions,
              "challenge",
              attachChallengeResponseSchema,
            );
            if (challenge.error) return challenge;

            const finished = await finishRegistration({
              password: input.newPassword,
              clientRegistrationState: registration.clientRegistrationState,
              challenge: challenge.data,
              payload: input.payload,
              allowedKeyStretching: registrationProfiles,
            });
            if (finished.error) return finished;

            const complete = await post<ChangePasswordResponse>(
              OPAQUE_PATHS.attachComplete,
              {
                stateId: challenge.data.stateId,
                registrationRecord: finished.data.registrationRecord,
                payload: finished.data.payload,
              },
              input.fetchOptions,
              "complete",
            );
            if (complete.error) return complete;
            $store.notify("$sessionSignal");
            return { data: { ...complete.data, exportKey: finished.data.exportKey }, error: null };
          },

          /**
           * Loads the credential payload after successful Better Auth second-factor verification.
           * The token is single use, including failed authenticated attempts; retry sign-in if lost.
           */
          loadSignInPayload: (
            input: OpaqueLoadSignInPayloadInput,
          ): Promise<OpaqueClientResult<SignInPayloadResponse>> =>
            post<SignInPayloadResponse>(
              OPAQUE_PATHS.signInPayload,
              { payloadToken: input.payloadToken },
              input.fetchOptions,
              "complete",
            ),

          /**
           * Proves the password locally for one 2FA management request. Pass `proof` as that
           * method's `password`; it expires in five minutes and is consumed even on rejection.
           * The server's stored profile must be accepted by the local login policy.
           */
          createPasswordProof: async (
            input: OpaqueCreatePasswordProofInput,
          ): Promise<OpaqueClientResult<PasswordProofResponse>> => {
            const { client } = await loadSerenity();
            const login = client.startLogin({ password: input.password });
            const challenge = await post<PasswordProofChallengeResponse>(
              OPAQUE_PATHS.passwordProofChallenge,
              { loginRequest: login.startLoginRequest },
              input.fetchOptions,
              "challenge",
              passwordProofChallengeResponseSchema,
            );
            if (challenge.error) return challenge;
            if (
              !loginProfiles.some((profile) =>
                sameKeyStretching(profile, challenge.data.keyStretching),
              )
            ) {
              return keyStretchingMismatch();
            }
            const processed = finishLogin(client, {
              clientLoginState: login.clientLoginState,
              loginResponse: challenge.data.loginResponse,
              password: input.password,
              keyStretching: challenge.data.keyStretching,
              identifiers: serverIdentifiers(challenge.data.serverIdentifier),
            });
            if (processed.error) return processed;
            const finished = processed.data;
            if (!finished) return localError("INVALID_PASSWORD", 400, "BAD_REQUEST");
            return post<PasswordProofResponse>(
              OPAQUE_PATHS.passwordProofComplete,
              { stateId: challenge.data.stateId, loginFinalization: finished.finishLoginRequest },
              input.fetchOptions,
              "complete",
            );
          },

          /**
           * Changes the password of the signed-in user: proves the current password and
           * registers the new one in a single challenge/complete pair. Both profiles must be
           * accepted before either derivation runs. All sessions are revoked and replaced with
           * a new caller session, whose token is returned and set as a cookie.
           */
          changePassword: async (
            input: OpaqueChangePasswordInput,
          ): Promise<OpaqueClientResult<OpaqueChangePasswordData>> => {
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
              changePasswordChallengeResponseSchema,
            );
            if (challenge.error) {
              return challenge;
            }

            if (
              !loginProfiles.some((profile) =>
                sameKeyStretching(profile, challenge.data.loginKeyStretching),
              ) ||
              !registrationProfiles.some((profile) =>
                sameKeyStretching(profile, challenge.data.keyStretching),
              )
            ) {
              return keyStretchingMismatch();
            }
            const processed = finishLogin(client, {
              clientLoginState: login.clientLoginState,
              loginResponse: challenge.data.loginResponse,
              password: input.currentPassword,
              keyStretching: challenge.data.loginKeyStretching,
              identifiers: serverIdentifiers(challenge.data.serverIdentifier),
            });
            if (processed.error) return processed;
            const proven = processed.data;
            if (!proven) {
              return localError("INVALID_PASSWORD", 400, "BAD_REQUEST");
            }

            const finished = await finishRegistration({
              password: input.newPassword,
              clientRegistrationState: registration.clientRegistrationState,
              challenge: challenge.data,
              payload: input.payload,
              allowedKeyStretching: registrationProfiles,
            });
            if (finished.error) {
              return finished;
            }

            const complete = await post<ChangePasswordResponse>(
              OPAQUE_PATHS.changePasswordComplete,
              {
                stateId: challenge.data.stateId,
                loginFinalization: proven.finishLoginRequest,
                registrationRecord: finished.data.registrationRecord,
                payload: finished.data.payload,
              },
              input.fetchOptions,
              "complete",
            );
            if (complete.error) {
              return complete;
            }
            $store.notify("$sessionSignal");
            return { data: { ...complete.data, exportKey: finished.data.exportKey }, error: null };
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
              resetChallengeResponseSchema,
            );
            if (challenge.error) {
              return challenge;
            }

            const finished = await finishRegistration({
              password: input.newPassword,
              clientRegistrationState: registration.clientRegistrationState,
              challenge: challenge.data,
              payload: input.payload,
              allowedKeyStretching: registrationProfiles,
            });
            if (finished.error) {
              return finished;
            }

            const complete = await post<CredentialUpdateResponse>(
              OPAQUE_PATHS.resetComplete,
              {
                stateId: challenge.data.stateId,
                registrationRecord: finished.data.registrationRecord,
                payload: finished.data.payload,
              },
              input.fetchOptions,
              "complete",
            );
            if (complete.error) {
              return complete;
            }
            $store.notify("$sessionSignal");
            return { data: { ...complete.data, exportKey: finished.data.exportKey }, error: null };
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
