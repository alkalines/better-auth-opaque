import type { BetterAuthPlugin } from "better-auth";
import { createAuthEndpoint } from "better-auth/api";
import {
  OPAQUE_ACCOUNT_FIELDS,
  OPAQUE_ERROR_CODES,
  OPAQUE_PATHS,
  OPAQUE_PLUGIN_ID,
} from "../contract.ts";
import { changePasswordEndpoints } from "./change-password.ts";
import { resetPasswordEndpoints } from "./reset-password.ts";
import { createRuntime, type OpaqueOptions } from "./runtime.ts";
import { signInEndpoints } from "./sign-in.ts";
import { signUpEndpoints } from "./sign-up.ts";

export type { OpaqueOptions } from "./runtime.ts";

const signInAndResetPaths: string[] = [
  OPAQUE_PATHS.signInChallenge,
  OPAQUE_PATHS.signInComplete,
  OPAQUE_PATHS.resetVerify,
  OPAQUE_PATHS.resetChallenge,
  OPAQUE_PATHS.resetComplete,
];
const registrationPaths: string[] = [
  OPAQUE_PATHS.signUpChallenge,
  OPAQUE_PATHS.signUpComplete,
  OPAQUE_PATHS.changePasswordChallenge,
  OPAQUE_PATHS.changePasswordComplete,
];

/**
 * Better Auth server plugin for OPAQUE (RFC 9807) password authentication. The password never
 * reaches the server: the client runs serenity's OPAQUE client and the server stores only the
 * registration record on an `account` row with `providerId: "opaque"`.
 *
 * Throws at construction when `serverSetup` is missing. The setup is validated on first use;
 * call `auth.api.validateOpaqueSetup()` at boot to fail fast. Add the schema fields
 * (`registrationRecord`, `opaqueCredentialVersion`, `opaqueKeyStretching` on `account`) with
 * Better Auth's migration tooling.
 *
 * HTTP endpoints are `scope: "server"`, so the Better Auth client does not infer path actions for
 * them; use the `opaqueClient` plugin, whose actions run both protocol round trips.
 */
export function opaque(options: OpaqueOptions) {
  const runtime = createRuntime(options);

  /**
   * Server-only (never routed over HTTP): resolves serenity and validates `serverSetup`, returning
   * the server's static public key. Throws `INVALID_SERVER_SETUP` for an invalid setup.
   */
  const validateOpaqueSetup = createAuthEndpoint.serverOnly(
    { method: "POST", metadata: { SERVER_ONLY: true } },
    async () => {
      const publicKey = await runtime.requireServerPublicKey();
      return { publicKey };
    },
  );

  return {
    id: OPAQUE_PLUGIN_ID,
    endpoints: {
      ...signUpEndpoints(runtime),
      ...signInEndpoints(runtime),
      ...changePasswordEndpoints(runtime),
      ...resetPasswordEndpoints(runtime),
      validateOpaqueSetup,
    },
    schema: {
      account: {
        fields: {
          [OPAQUE_ACCOUNT_FIELDS.registrationRecord]: {
            type: "string",
            required: false,
            returned: false,
            input: false,
          },
          [OPAQUE_ACCOUNT_FIELDS.credentialVersion]: {
            type: "string",
            required: false,
            input: false,
          },
          [OPAQUE_ACCOUNT_FIELDS.keyStretching]: {
            type: "string",
            required: false,
            input: false,
          },
        },
      },
    },
    // Every path is limited per IP and path. Sign-in and reset are the online guessing surfaces,
    // so they get the smallest budget.
    rateLimit: [
      {
        window: 60,
        max: 5,
        pathMatcher: (path: string) => signInAndResetPaths.includes(path),
      },
      {
        window: 60,
        max: 10,
        pathMatcher: (path: string) => registrationPaths.includes(path),
      },
    ],
    // `options` are deliberately not exposed on the plugin: they contain the server setup.
    $ERROR_CODES: OPAQUE_ERROR_CODES,
  } satisfies BetterAuthPlugin;
}
