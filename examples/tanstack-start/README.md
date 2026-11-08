# TanStack Start example

A minimal TanStack Start app using `@alkalines/better-auth-opaque` with Better Auth, Prisma 7 and SQLite. It demonstrates the payload hooks with a client-side key hierarchy: a random AES-GCM data key is wrapped under a key derived (HKDF-SHA-256) from the OPAQUE export key, and the server only stores the wrapped key per credential version.

This is a demo, not a template for production: the unwrapped data key is kept in `sessionStorage` so the change-password page can rewrap it, and the reset-link route is a localhost-only stand-in for sending an email.

## Run it

From the repository root:

```sh
bun install
bun run create-setup
```

`create-setup` prints a server setup. Back it up like a private key: losing it locks out every account created with it. Then create the environment file:

```sh
cp examples/tanstack-start/.env.example examples/tanstack-start/.env
```

Fill in `examples/tanstack-start/.env`:

- `OPAQUE_SERVER_SETUP`: the value printed by `create-setup`.
- `BETTER_AUTH_SECRET`: any random string of at least 32 characters, for example `openssl rand -base64 32`.

Leave `BETTER_AUTH_URL` and `DATABASE_URL` as they are, then start the app:

```sh
bun run --cwd examples/tanstack-start dev
```

The `dev` script builds the root package (the example consumes it through `workspace:*`, whose exports point at `dist/`), generates the Prisma client, applies the committed migrations to `dev.db` and starts Vite on <http://localhost:3000>. `.env`, `dev.db` and the generated client are gitignored.

## Pages

| Route              | Purpose                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------- |
| `/`                | Session status, sign out and two-factor management link                                  |
| `/sign-up`         | Registers with a wrapped data key as the payload                                         |
| `/sign-in`         | Signs in, verifies TOTP if required, unwraps the payload and shows a fingerprint         |
| `/change-password` | Rewraps the same data key under the new export key                                       |
| `/two-factor`      | Requires a session; enables TOTP with backup codes or disables two-factor authentication |
| `/forgot`          | Gets a reset link from `POST /api/dev/reset-token` (loopback and non-production only)    |
| `/reset?token=...` | Verifies the token, then resets with a freshly generated data key                        |

The data key is unrecoverable after a reset because only the old password could unwrap it, so the reset page starts a new one. The fingerprint shown after sign-in matches the one from sign-up or the last change, and differs after a reset.

## Two-factor authentication

The server registers `twoFactor({ allowPasswordless: true, issuer: "better-auth-opaque example" })` alongside `opaque()`, and the client registers `twoFactorClient()` alongside `opaqueClient()`. OPAQUE accounts have no Better Auth credential password: `allowPasswordless` lets Better Auth manage their second factors, while the OPAQUE plugin requires a single-use password proof for management operations. The password itself is never sent to Better Auth.

After signing up, open `/two-factor`, enter the current password and enable two-factor. Add the displayed secret to an authenticator, save the backup codes, then verify a code to finish enabling. Disable it with the current password on the same page.

Sign-in keeps the export key and payload token only in component memory while the TOTP form is pending; there is deliberately no `twoFactorPage` navigation. Only after verification establishes a session does the page consume the payload token, unwrap the payload and display its fingerprint. Reloading the page abandons this pending state: start sign-in again. Checking “Trust this device” allows subsequent sign-ins on that device without another TOTP prompt.

The Chromium E2E flow computes time-based codes from the displayed secret using `@better-auth/utils`. Better Auth 1.7.18 accepts codes in its current 30-second step and adjacent steps and does not reject same-window code reuse; the test generates a current code immediately before each verification rather than depending on a fixed code or waiting for a clock boundary. It also checks wrong-code failure, wrong-password/unknown-email equivalence, trusted-device sign-in, disabling, matching payload fingerprints and request-body password secrecy.

## Layout

- `src/server/auth.ts`: Better Auth config, Prisma client and the payload hooks.
- `src/lib/auth-client.ts`: `createAuthClient` with `opaqueClient()` and `twoFactorClient()`.
- `src/lib/demo-crypto.ts`: Web Crypto helpers for the key hierarchy.
- `prisma/schema.prisma`: Better Auth models including the two-factor fields, the plugin's account fields (`registrationRecord`, `opaqueCredentialVersion`, `opaqueKeyStretching`) and the `DemoPayload` table keyed by `(userId, credentialVersion)`.
- `src/routeTree.gen.ts`: generated by the TanStack router plugin; do not edit it by hand.

## Scripts

- `dev`: build the root package, `db:setup`, start Vite.
- `db:setup`: `prisma generate && prisma migrate deploy`.
- `typecheck`: `prisma generate && tsc --noEmit`.

To change the schema, edit `prisma/schema.prisma` and run `bunx prisma migrate dev --name <name>` in this directory.
