# @alkalines/better-auth-opaque

[OPAQUE](https://www.rfc-editor.org/rfc/rfc9807) password authentication for [Better Auth](https://better-auth.com) 1.7, built on [`@serenity-kit/opaque`](https://github.com/serenity-kit/opaque).

With OPAQUE the password never reaches your server, and the server stores a registration record instead of a password hash. Each successful login also yields an **export key** on the client: a stable secret per credential that apps can use to encrypt client-side data. This package adds sign-up, sign-in, password change and password reset endpoints to Better Auth, a client plugin that runs the protocol in the browser, and hooks for keeping app data that is encrypted under the export key consistent with the credential.

> Status: 0.2.0. Before 1.0, minor versions may contain breaking changes; see the [changelog](CHANGELOG.md).

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

| Option                    | Default                                                  | Notes                                                                                                                                                                    |
| ------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `serverSetup`             | required                                                 | Output of `create-setup`.                                                                                                                                                |
| `keyStretching`           | `"rfc-recommended"`                                      | Serenity key-stretching profile for new registrations. Stored per account, so changing it later keeps existing accounts working. Clients must allow it (below).          |
| `serverIdentifier`        | unset                                                    | Bound into every record. Changing it later breaks **all** existing records.                                                                                              |
| `hooks`                   | none                                                     | App payload hooks and `onCredentialChanged`, below.                                                                                                                      |
| `passwordReset`           | none                                                     | `{ url(token), expiresIn = 3600 }` (seconds, at most 7 days) for `createPasswordResetToken`.                                                                             |
| `disableSignUp`           | `emailAndPassword.disableSignUp`                         | Rejects OPAQUE sign-up with `SIGN_UP_DISABLED`.                                                                                                                          |
| `accountRateLimit`        | none                                                     | `({ key, flow }, ctx) => boolean`: per-account throttle, below.                                                                                                          |
| `attach`                  | `{ requireCurrentPassword: true, freshSessionAge: 600 }` | Migration from classic passwords, below.                                                                                                                                 |
| `removeClassicCredential` | `true`                                                   | Delete the classic `credential` account once an OPAQUE credential was attached or enrolled through reset.                                                                |
| `absentUserId`            | derived from the id configuration                        | User id that never exists, used to keep unknown-email sign-in queries identical. Set it when the database assigns ids that are not UUID-compatible (`"0"` for integers). |

Invalid options throw at construction.

### Password reset

`createPasswordResetToken` is server-only (not reachable over HTTP). Send the URL yourself:

```ts
const { url, expiresAt } = await auth.api.createPasswordResetToken({ body: { email } });
await sendEmail(email, url);
```

It throws `USER_NOT_FOUND` when the email has no OPAQUE account; do not forward that difference to the requester if you want reset requests to be enumeration-safe.

A link is bound to the credential it was issued for: once any reset or password change completes, every other outstanding link stops working. Issuing a new link does not invalidate earlier ones unless you pass `revokePrevious: true`; `auth.api.revokePasswordResetTokens({ body: { email } })` (server-only) invalidates all of a user's links, and resets already started from them, without issuing one. Accounts registered under a 0.1.x key-stretching profile outside the current bounds cannot sign in; issue them a reset link.

### Per-account rate limit

Better Auth's rate limiter counts per client IP, which does not stop guessing from many IPs and depends on the IP your deployment can resolve. `accountRateLimit` is called before every sign-in, password-proof, change-password and attach challenge:

```ts
opaque({
  serverSetup,
  // `key` is an HMAC of the lowercased email (also for unknown emails); return false to answer 429 TOO_MANY_ATTEMPTS.
  accountRateLimit: async ({ key, flow }) => limiter.consume(`${flow}:${key}`),
});
```

### Limitations

- **Password policy:** the server never sees the password, so `emailAndPassword.minPasswordLength`/`maxPasswordLength` cannot be enforced server-side. Check length in your client before calling the plugin.
- **`account.update` database hooks** do not run when a password change or reset switches the credential (the switch is a compare-and-set on the credential version). `user.create`, `account.create` and `session.create` hooks run as usual.

### Two-factor authentication

OPAQUE sign-in goes through Better Auth's own [two-factor](https://www.better-auth.com/docs/plugins/2fa) gate: the plugin hands `/sign-in/opaque/complete` to the installed `twoFactor` plugin's sign-in hook, so trusted devices, TOTP, OTP and backup codes behave as for email/password sign-in.

```ts
import { twoFactor } from "better-auth/plugins";

betterAuth({
  plugins: [
    opaque({ serverSetup }),
    // OPAQUE users have no credential password; the opaque plugin requires a password proof instead.
    twoFactor({ allowPasswordless: true }),
  ],
});
```

```ts
import { twoFactorClient } from "better-auth/client/plugins";

const authClient = createAuthClient({ plugins: [opaqueClient(), twoFactorClient()] });

// Managing 2FA: prove the password with OPAQUE, then pass the one-time proof as `password`.
const { data: proof } = await authClient.opaque.createPasswordProof({ password });
const { data: setup } = await authClient.twoFactor.enable({ password: proof!.proof });
await authClient.twoFactor.verifyTotp({ code });

// Signing in: the payload is withheld until the second factor is verified.
const { data } = await authClient.signIn.opaque({ email, password });
if (data?.twoFactorRedirect) {
  await authClient.twoFactor.verifyTotp({ code, trustDevice: true });
  const { data: loaded } = await authClient.opaque.loadSignInPayload({
    payloadToken: data.payloadToken,
  });
  // loaded.payload, data.exportKey
}
```

- `twoFactor({ allowPasswordless: true })` is required: OPAQUE users have no credential password, so without it they cannot enable 2FA (the plugin logs a warning at startup). The opaque plugin then requires a valid password proof (`opaque.createPasswordProof`: single use, 5 minutes, bound to the user and the current credential) for `/two-factor/enable`, `/disable`, `/get-totp-uri` and `/generate-backup-codes`. Users who also have an email/password credential keep Better Auth's password check.
- A 2FA sign-in returns `{ twoFactorRedirect, twoFactorMethods, payloadToken, exportKey }` and no session or payload. Keep `exportKey` and `payloadToken` in memory and handle the redirect in your sign-in UI; `twoFactorClient({ twoFactorPage })` reloads the page and loses them. `loadSignInPayload` needs the session created by the second-factor verification, is single use and expires with the two-factor cookie (`twoFactorCookieMaxAge`, 10 minutes by default).
- The export key is returned before the second factor because anyone holding the password can derive it locally from the challenge; what 2FA protects is the session and the payload.
- A pending second factor is bound to the password that proved the first factor, for OPAQUE sign-in and for Better Auth's own email, username and phone-number sign-in: if any password change, reset or attach (including Better Auth's own `/change-password` and `/reset-password`) happens first, sending an OTP or verifying the second factor fails with `CREDENTIAL_CHANGED` and no session is created.
- The integration calls the installed two-factor plugin's sign-in hook, an internal of Better Auth; it is tested with better-auth 1.7.18. If the hook cannot be found, 2FA users fail closed with `TWO_FACTOR_NOT_SUPPORTED` instead of signing in without their second factor.

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
    // Audit log, notify other devices; runs after the attempt to revoke every session.
    onCredentialChanged: async ({
      userId,
      flow,
      previousCredentialVersion,
      credentialVersion,
      sessionsRevoked, // false: revocation failed, old sessions may still be live
    }) => {},
  },
});
```

Order for every registration (sign-up, password change, reset, attach): `validatePayload` → `commitPayload` → account record switched to the new version (an atomic compare-and-set on the previous version, or the new account row for sign-up and attach) → `activatePayload`. `loadPayload` receives the version the account currently points to (`null` only when verifying an enrolment reset link of a user without an OPAQUE credential). A failure at any step leaves the user able to sign in with either the old or the new password and receive the matching payload.

`activatePayload` must delete only `previousCredentialVersion`. Deleting every other version is unsafe: a slow activation of an earlier switch, or a commit for a registration still in flight, would lose the payload of the credential that is (or is about to become) current. Payloads committed by registrations that later failed are left behind; if storage matters, periodically delete versions the account does not point to that are older than an hour (commit and switch happen within one request). The hook contracts are documented on [`OpaqueHooks`](src/contract.ts).

### Migrating classic passwords

Users who sign in with a Better Auth email/password (`credential` account) can move to OPAQUE in two ways:

- **Attach** while signed in: `authClient.opaque.attachCredential({ currentPassword, newPassword, payload })` proves the classic password to the server (which already stores its hash), registers the new password with OPAQUE, revokes every session and returns a new one (`data.token`, `data.exportKey`). Pick a **new** password: the server knows the classic one, so the client refuses `newPassword === currentPassword` with `PASSWORD_REUSED`. With `attach: { requireCurrentPassword: false }`, a session younger than `freshSessionAge` seconds may attach without `currentPassword`; a stolen fresh session can then set the password, so use it only right after sign-in.
- **Enrolment reset**: `auth.api.createPasswordResetToken({ body: { email, allowEnrolment: true } })` also issues links for users without an OPAQUE credential; `resetPassword` with such a link creates their first OPAQUE credential and revokes all sessions. `verifyResetToken` returns `loadPayload` output for `credentialVersion: null`.

Both delete the classic `credential` account afterwards unless `removeClassicCredential: false`. If that step fails after the OPAQUE credential was created, finish it with the server-only `auth.api.removeClassicCredential({ body: { userId } })`. A user who already has an OPAQUE credential gets `OPAQUE_ACCOUNT_EXISTS` from attach; use `changePassword`.

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

// Revokes every session of the user and returns a new one for this browser: data.token.
await authClient.opaque.changePassword({ currentPassword, newPassword, payload: rewrap });
await authClient.opaque.verifyResetToken({ token }); // { payload }
await authClient.opaque.resetPassword({ token, newPassword, payload: freshPayload });
```

All actions return Better Auth's `{ data, error }` and accept `fetchOptions`. `exportKey` is returned only after the server's finish step succeeded; payload builders receive the new export key locally and only their result is sent. Error codes are exported as `OPAQUE_ERROR_CODES` and exposed through the client's `$ERROR_CODES`.

### Key-stretching policy

The client only derives keys with profiles it allows, so a compromised or misconfigured server cannot make it register under weak Argon2id parameters or run unbounded work at login:

```ts
opaqueClient({
  keyStretching: {
    // Profiles new credentials may use (sign-up, change, reset, attach).
    registration: ["rfc-recommended"],
    // Profiles logins may use; defaults to DEFAULT_ALLOWED_KEY_STRETCHING plus `registration`.
    login: ["rfc-recommended", "memory-constrained"],
  },
});
```

Both lists default to `DEFAULT_ALLOWED_KEY_STRETCHING` (serenity's named profiles, all at least `memory-constrained`). A challenge advertising any other profile fails with `KEY_STRETCHING_MISMATCH` before anything is derived or sent; a malformed challenge fails with `INVALID_SERVER_RESPONSE`. If your server uses a custom profile, or accounts still carry an older one, list it explicitly. Custom profiles must stay within `ARGON2ID_CUSTOM_LIMITS` (exported by the server entry) on both sides. `rfc-recommended` takes seconds and up to 2 GiB per derivation; test it on your slowest target devices.

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
