# @alkalines/better-auth-opaque

[OPAQUE](https://www.rfc-editor.org/rfc/rfc9807) password authentication for [Better Auth](https://better-auth.com) 1.7, built on [`@serenity-kit/opaque`](https://github.com/serenity-kit/opaque).

With OPAQUE the password never reaches your server, and the server stores a registration record instead of a password hash. Each successful login also yields an **export key** on the client: a stable secret per credential that apps can use to encrypt client-side data. This package adds sign-up, sign-in, password change and password reset endpoints to Better Auth, a client plugin that runs the protocol in the browser, and hooks for keeping app data that is encrypted under the export key consistent with the credential.

> Status: 0.1.0, unreleased.

## Install

```sh
bun add @alkalines/better-auth-opaque better-auth @better-auth/core zod
# or: npm install @alkalines/better-auth-opaque better-auth @better-auth/core zod
```

Peer dependencies: `better-auth` and `@better-auth/core` `>=1.7.16 <1.8.0` (use the same version for both; `better-auth` already depends on it), `zod` `^4`. `@serenity-kit/opaque` is pinned at exactly `1.1.0`.

## Generate the server setup

The server setup holds the OPAQUE server key pair and OPRF seed. Generate it once per deployment:

```sh
npx better-auth-opaque create-setup
```

Store the printed value as a secret (for example `OPAQUE_SERVER_SETUP`) and **back it up**. If it is lost or changed, every registration record becomes unusable and all users must reset their passwords. Never commit it. The plugin never generates a setup by itself and fails closed when it is missing or invalid. See [docs/security.md](docs/security.md#server-setup-backup).

## Server

```ts
import { betterAuth } from "better-auth";
import { opaque } from "@alkalines/better-auth-opaque";

export const auth = betterAuth({
  // database, secret, baseURL, ...
  plugins: [
    opaque({
      serverSetup: process.env.OPAQUE_SERVER_SETUP!,
      passwordReset: {
        url: (token) => `https://app.example.com/reset?token=${token}`,
      },
    }),
  ],
});

// Optional boot check: throws when the setup is invalid.
await auth.api.validateOpaqueSetup();
```

Run your Better Auth schema generation/migration afterwards: the plugin adds `registrationRecord`, `opaqueCredentialVersion` and `opaqueKeyStretching` to the `account` model.

Options (see the TSDoc on [`OpaqueOptions`](src/server/runtime.ts)):

| Option             | Default             | Notes                                                                                                                            |
| ------------------ | ------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `serverSetup`      | required            | Output of `create-setup`.                                                                                                        |
| `keyStretching`    | `"rfc-recommended"` | Serenity key-stretching profile for new registrations. Stored per account, so changing it later keeps existing accounts working. |
| `serverIdentifier` | unset               | Bound into every record. Changing it later breaks **all** existing records.                                                      |
| `hooks`            | none                | App payload hooks, below.                                                                                                        |
| `passwordReset`    | none                | `{ url(token), expiresIn = 3600 }` for `createPasswordResetToken`.                                                               |

### Password reset

`createPasswordResetToken` is server-only (not reachable over HTTP). Send the URL yourself:

```ts
const { url, expiresAt } = await auth.api.createPasswordResetToken({ body: { email } });
await sendEmail(email, url);
```

It throws `USER_NOT_FOUND` when the email has no OPAQUE account; do not forward that difference to the requester if you want reset requests to be enumeration-safe.

### Limitations

- **Two-factor:** Better Auth's `twoFactor` plugin does not gate OPAQUE sign-in, so users with two-factor enabled are refused with `TWO_FACTOR_NOT_SUPPORTED` instead of being signed in without their second factor.
- **Password policy:** the server never sees the password, so `emailAndPassword.minPasswordLength`/`maxPasswordLength` cannot be enforced server-side. Check length in your client before calling the plugin.
- **`account.update` database hooks** do not run when a password change or reset switches the credential (the switch is a compare-and-set on the credential version). `user.create`, `account.create` and `session.create` hooks run as usual.

### Payload hooks

Apps that encrypt data under the export key store the encrypted material ("payload") per credential version. A new password means a new export key, so the payload has to be replaced together with the registration record. The hooks make that safe without multi-write transactions:

```ts
opaque({
  serverSetup,
  hooks: {
    validatePayload: ({ payload, flow, userId }) => {
      /* throw to reject */
    },
    commitPayload: async ({ userId, credentialVersion, payload }) => {
      await db.payloads.upsert({ userId, credentialVersion, payload });
    },
    activatePayload: async ({ userId, previousCredentialVersion }) => {
      // Delete only the replaced version; never "everything but the current one".
      if (previousCredentialVersion) {
        await db.payloads.delete({ userId, credentialVersion: previousCredentialVersion });
      }
    },
    loadPayload: async ({ userId, credentialVersion }) =>
      (await db.payloads.find({ userId, credentialVersion }))?.payload ?? null,
  },
});
```

Order for every registration (sign-up, password change, reset): `validatePayload` → `commitPayload` → account record switched to the new version (an atomic compare-and-set on the previous version) → `activatePayload`. `loadPayload` receives the version the account currently points to. A failure at any step leaves the user able to sign in with either the old or the new password and receive the matching payload.

`activatePayload` must delete only `previousCredentialVersion`. Deleting every other version is unsafe: a slow activation of an earlier switch, or a commit for a registration still in flight, would lose the payload of the credential that is (or is about to become) current. Payloads committed by registrations that later failed are left behind; if storage matters, periodically delete versions the account does not point to that are older than an hour (commit and switch happen within one request). The hook contracts are documented on [`OpaqueHooks`](src/contract.ts).

## Client

```ts
import { createAuthClient } from "better-auth/react";
import { opaqueClient } from "@alkalines/better-auth-opaque/client";

export const authClient = createAuthClient({ plugins: [opaqueClient()] });

await authClient.signUp.opaque({
  email,
  password,
  name,
  payload: async (exportKey) => wrapAppKey(exportKey),
});

const { data, error } = await authClient.signIn.opaque({ email, password });
// data.exportKey (base64url), data.payload (loadPayload output)

await authClient.opaque.changePassword({ currentPassword, newPassword, payload: rewrap });
await authClient.opaque.verifyResetToken({ token }); // { payload }
await authClient.opaque.resetPassword({ token, newPassword, payload: freshPayload });
```

All actions return Better Auth's `{ data, error }` and accept `fetchOptions`. `exportKey` is returned only after the server's finish step succeeded; payload builders receive the new export key locally and only their result is sent. Error codes are exported as `OPAQUE_ERROR_CODES` and exposed through the client's `$ERROR_CODES`.

`opaqueClient({ keyStretching })` optionally pins the profile the client accepts for new registrations; a server advertising a different profile is rejected with `KEY_STRETCHING_MISMATCH`.

## Convex

With [`@convex-dev/better-auth`](https://labs.convex.dev/better-auth) 0.13, use its [local install](https://labs.convex.dev/better-auth/features/local-install): the plugin adds fields to the `account` table, and only a locally installed Better Auth component carries a schema you generate. The tested layout is [`test/convex`](test/convex):

- `convex/betterAuth/convex.config.ts`, `adapter.ts` (`createApi(schema, createAuthOptions)`), `auth.ts` (static instance for schema generation) and `schema.ts`, generated with `npx auth generate --config convex/betterAuth/auth.ts --output convex/betterAuth/schema.ts`; it contains `registrationRecord`, `opaqueCredentialVersion` and `opaqueKeyStretching`. In this repository the schema is gitignored and regenerated by the workspace's `postinstall` ([`scripts/generate-schema.ts`](test/convex/scripts/generate-schema.ts)).
- `convex/auth.ts` adds `opaque({ serverSetup: process.env.OPAQUE_SERVER_SETUP, ... })` next to the `convex()` plugin; `convex/http.ts` calls `authComponent.registerRoutes`.
- Set `OPAQUE_SERVER_SETUP` with `npx convex env set`. The auth HTTP action runs in Convex's default runtime; no `"use node"` is needed.
- Payload hooks run inside the HTTP action, so they call `ctx.runMutation`/`ctx.runQuery` on your own tables.
- Call `createPasswordResetToken` from an internal action (`createAuth(ctx).api.createPasswordResetToken(...)`), never from a public function.

The adapter has no multi-write transactions; the plugin's write ordering and compare-and-set switch do not depend on them (see [docs/security.md](docs/security.md#write-ordering-instead-of-transactions)).

## Supported runtimes

Only rows backed by a test in this repository are listed.

| Runtime / environment                                    | Part            | Adapter                                      | Evidence                                                                                                                                                                                            |
| -------------------------------------------------------- | --------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node.js 24                                               | server + client | Better Auth memory adapter                   | `bun run test`, Vitest project `node` ([`test/unit`](test/unit))                                                                                                                                    |
| Vitest `edge-runtime` environment (`@edge-runtime/vm` 5) | server + client | memory adapter                               | `bun run test`, Vitest project `edge`. Only the globals are edge-runtime's; modules are still loaded by Node, so this does not prove support for Vercel Edge, Cloudflare Workers or other isolates. |
| Convex default runtime (local backend, `convex` 1.49)    | server          | `@convex-dev/better-auth` 0.13 local install | `bun run test:convex` ([`test/convex`](test/convex))                                                                                                                                                |
| Chromium (Playwright 1.65)                               | client          | —                                            | `bun run test:e2e` ([`examples/tanstack-start/e2e`](examples/tanstack-start/e2e))                                                                                                                   |
| Node.js 24 via TanStack Start dev server (Vite 8)        | server          | Prisma 7 + SQLite (libsql)                   | `bun run test:e2e`                                                                                                                                                                                  |

Not tested and therefore not claimed: Bun or Deno as the server runtime, Convex cloud deployments, Cloudflare Workers, Vercel Edge, Firefox, Safari, and Better Auth database adapters other than the ones above.

## Example

[`examples/tanstack-start`](examples/tanstack-start) is a minimal TanStack Start + Prisma (SQLite) app with sign-up, sign-in, password change and reset, including an app payload wrapped under the export key.

## Security

See [docs/security.md](docs/security.md) for the threat model, residual enumeration leakage and setup backup.

## License

MIT
