# Changelog

All notable changes to `@alkalines/better-auth-opaque` are recorded here. The project follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Security fixes

- **security** **breaking** Reset-link revocation no longer uses a per-user epoch that every issuance created and extended. `revokePasswordResetTokens` and `createPasswordResetToken({ revokePrevious: true })` now write a fresh random marker (`opaque:reset-revocation:<userId>`, lives 7 days + 1 hour, longer than any link and its reset state); issuance only reads it, and a link is valid while no marker other than the one it carries is live. Concurrent issuances can no longer delete or outlive each other's epoch (one of two links issued together used to fail), and no expiry is extended out of order. The reset-token value is now `{ userId, credentialVersion, revocation }`.
- **security** A revocation also cancels resets already started: the reset state carries the link's revocation marker and `/reset/opaque/complete` answers `INVALID_RESET_TOKEN` when it is no longer current.
- **security** Enrolment links are rejected as soon as the user has any OPAQUE account row, including one whose fields do not decode; previously such a link passed `verify` and burned at `challenge`, failing only at `complete`.
- **security** Accounts stored with a 0.1.x key-stretching profile outside the 0.2.0 bounds can be reset again (`createPasswordResetToken`, reset verify/challenge/complete replace the record and profile). They still cannot sign in, change the password or prove the password. Previously they could neither sign in nor be reset.
- **security** Attach re-checks the classic password fingerprint after creating the OPAQUE account, so a classic password changed while `validatePayload`/`commitPayload` ran fails with `CREDENTIAL_CHANGED` and leaves no OPAQUE account. If the post-insert re-check itself fails, the new account is deleted before the error is returned, so it cannot block retries while the classic password and old sessions keep working.
- **security** The replacement session issued by change-password and attach complete is created and then checked against the credential the flow installed; if a reset or another change replaced it in between, the session is deleted and the call fails with `CREDENTIAL_CHANGED`.
- **security** Session-bound calls to `/two-factor/verify-totp`, `/verify-otp`, `/verify-backup-code` and `/send-otp` (enabling 2FA, sending a code to a signed-in user) are no longer refused with `CREDENTIAL_CHANGED`, nor their challenge retired, because of a stale `two_factor` cookie; Better Auth ignores that cookie when a session exists.

### Features

- `onCredentialChanged` receives `sessionsRevoked`, `false` when revoking the user's sessions failed. Its documentation now covers Better Auth's cookie cache, which `deleteUserSessions` does not invalidate.
- New option `absentUserId`: the never-existing user id the sign-in challenge queries accounts for when the email is unknown, for databases that assign ids that are neither serial nor UUID-compatible.
- `hooks` accepts members explicitly set to `undefined`.

### Migration

- Reset links issued by 0.2.0 stop working; issue new ones. Leftover `opaque:reset-epoch:<userId>` verification rows are unused and expire on their own.

## 0.2.0 (2026-11-08)

Fixes from the 0.1.3 security review and the migration features it asked for. Several changes are breaking (marked **breaking**); see the migration notes at the end.

### Security fixes

- **security** **breaking** The client enforces a key-stretching policy. `opaqueClient({ keyStretching: { registration?, login? } })` takes allowlists of profiles; both default to `DEFAULT_ALLOWED_KEY_STRETCHING` (`"rfc-recommended"`, `"rfc-draft-recommended"`, `"memory-constrained"`), and `login` also includes every `registration` profile unless it is set explicitly. A registration (sign-up, change, reset, attach) under a profile outside `registration` and a login (sign-in, password proof, the current password in a change) under a profile outside `login` fail locally with `KEY_STRETCHING_MISMATCH` before any derivation, payload builder call or `complete` request. Previously the default client registered under any server-advertised profile (a compromised backend could choose trivially weak Argon2id parameters and recover the export key offline) and logins derived with an unbounded server-chosen profile. The old exact-pin form `opaqueClient({ keyStretching: profile })` is removed and throws at construction.
- **security** The client parses every challenge response with the contract schemas and catches serenity failures; both resolve to the new client-only error `INVALID_SERVER_RESPONSE` (502) instead of passing malformed data to serenity or rejecting the action. Challenge response schemas now bound `stateId`, `registrationResponse` and `loginResponse`.
- **security** **breaking** Password change revokes every session of the user with `deleteUserSessions` and issues a new session to the caller (cookie set; `token` returned: `/opaque/change-password/complete` now answers `{ status: true, token }`). Previously only the sessions returned by one `listSessions` page (adapter default limit 100, expired rows included) were revoked, so later sessions survived the change.
- **security** A second-factor sign-in started with a password that has since been replaced can no longer be completed: `/two-factor/send-otp`, TOTP, OTP and backup-code verification answer `CREDENTIAL_CHANGED` (409), retire the challenge, send no OTP, spend no backup code and leave no session; a session or trusted device created by a verify that races the switch is deleted. Every challenge, from OPAQUE sign-in and from Better Auth's own email, username and phone-number sign-in, is bound when issued to a snapshot of the user's OPAQUE credential version and classic password hash (new stored key `opaque:two-factor-pending:<sha256>`), so OPAQUE changes, resets, attach, enrolment, and Better Auth's own `/change-password` and `/reset-password` all invalidate pending challenges. The challenge is recorded from the two-factor gate's own verification write; no `Set-Cookie` parsing and no clock comparison. Challenges without a binding are refused, so 2FA sign-ins in flight during the upgrade must be restarted once.
- **security** **breaking** Reset links are bound to the credential version and a per-user epoch. A reset or password change invalidates every other outstanding link (`verify` no longer reveals the new payload to an older link, and the link cannot reset again). New `createPasswordResetToken({ revokePrevious: true })` and server-only `auth.api.revokePasswordResetTokens({ body: { email } })` invalidate earlier links. New stored key `opaque:reset-epoch:<userId>`; the reset-token value is now `{ userId, credentialVersion, epoch }`.
- **security** Sign-in, sign-up and reset endpoints run Better Auth's `formCsrfMiddleware`, like `/sign-in/email`: cookie-less cross-site requests are refused with 403.
- **security** The sign-in challenge runs one user lookup and the same indexed `account.userId` query for every email (with an unused id in the database's id format for unknown emails), so unknown emails no longer skip a query on adapters without native joins (e.g. Convex). Measured on a local Convex backend: p50 60.0 ms for registered vs 61.3 ms for unknown emails.
- **security** **breaking** Custom Argon2id profiles are bounded by the schema (`ARGON2ID_CUSTOM_LIMITS`: iterations ≤ 64, memory 8 KiB per lane up to 2 GiB − 1 KiB, parallelism ≤ 64). Out-of-bounds profiles are rejected in server options, client options and challenge responses (`INVALID_SERVER_RESPONSE`); an account stored with such a profile can no longer sign in and must be reset.
- **security** OPAQUE sign-up honours `emailAndPassword.disableSignUp` (new error `SIGN_UP_DISABLED`, 400), at the challenge and again at complete; the new `opaque({ disableSignUp })` option overrides it.
- **security** Registration records are checked with a throwaway serenity login before they are stored (sign-up, change, reset, attach); a record serenity cannot load is rejected with `INVALID_OPAQUE_MESSAGE` instead of making the account unusable.
- **security** Server options are validated at construction (`keyStretching` against the profile schema, `passwordReset.expiresIn` a positive integer of at most 7 days, `passwordReset.url` a function, `attach`, `serverIdentifier`, hook types); invalid options throw.

### Features

- **security** Attach: `POST /opaque/attach/{challenge,complete}` and `authClient.opaque.attachCredential({ newPassword, currentPassword?, payload? })` add a first OPAQUE credential for a signed-in user with a classic Better Auth password. The challenge verifies the classic password (or, with `opaque({ attach: { requireCurrentPassword: false, freshSessionAge } })`, accepts a fresh session); complete creates the account (first credential wins under concurrency), deletes the classic `credential` account unless `removeClassicCredential: false`, revokes every session and returns a new one (`{ status: true, token }`). The client refuses a new password equal to the classic one (`PASSWORD_REUSED`). New hook flow `"attach"`, new error `OPAQUE_ACCOUNT_EXISTS`.
- **security** Enrolment reset: `createPasswordResetToken({ email, allowEnrolment: true })` also issues links for users without an OPAQUE credential; completing one creates their first OPAQUE credential, removes the classic credential (per `removeClassicCredential`) and revokes all sessions. `loadPayload` receives `credentialVersion: null` when such a link is verified.
- Server-only `auth.api.removeClassicCredential({ body: { userId } })` deletes a user's classic `credential` account once an OPAQUE credential exists, to finish an interrupted migration.
- **security** Per-account throttling: `opaque({ accountRateLimit })` is called before sign-in, password-proof, change-password and attach challenges with an HMAC of the lowercased email (computed the same way for unknown emails) and the flow; returning `false` refuses the attempt with the new error `TOO_MANY_ATTEMPTS` (429).
- `onCredentialChanged` hook, called once per password change, reset or attach after the switch and the session revocation, also when `activatePayload` failed.

### Migration

- Client: replace `opaqueClient({ keyStretching: profile })` with `opaqueClient({ keyStretching: { registration: [profile] } })`. If accounts were registered under a custom profile, list it in `registration` or `login`, or those users get `KEY_STRETCHING_MISMATCH` at sign-in.
- `changePassword` replaces the caller's session: read the new `token` if you use bearer tokens.
- Reset links issued by 0.1.x stop working; issue new ones.
- Hook types: `OpaqueFlow` and `OpaqueRegistrationFlow` include `"attach"`; `loadPayload` receives `credentialVersion: string | null`.

## 0.1.3 (2026-11-07)

No package changes; the contents match 0.1.2. The npm release is now staged through npm trusted publishing (OIDC) instead of an npm token, and still needs a maintainer's 2FA approval.

## 0.1.2 (2026-11-07)

First release on npm. The package contents match 0.1.0. The release workflow now stages the npm release with `npm stage publish`, and a maintainer approves it with 2FA before it goes live.

## 0.1.1 (2026-11-07, GitHub Packages only)

Published to GitHub Packages only; the npm publish failed because CI cannot pass 2FA. The package contents match 0.1.0. The release workflow now creates its pack directory before running `npm pack`.

## 0.1.0 (2026-11-07, not published)

Initial release. Tagged `v0.1.0`, but the release workflow failed before publishing, so it is not on npm or GitHub Packages.

- **security** Server plugin `opaque()` for Better Auth 1.7 (peers `better-auth` and `@better-auth/core` `>=1.7.16 <1.8.0`, `zod` `^4`) implementing OPAQUE (RFC 9807) with `@serenity-kit/opaque` 1.1.0 (exact): `POST` endpoints `/sign-up/opaque/{challenge,complete}`, `/sign-in/opaque/{challenge,complete}`, `/opaque/change-password/{challenge,complete}` and `/reset/opaque/{verify,challenge,complete}`.
- **security** Stored fields on the `account` model: `registrationRecord` (never returned), `opaqueCredentialVersion`, `opaqueKeyStretching`. OPAQUE accounts use `providerId: "opaque"` with a random 256-bit credential id as `accountId` and as the OPAQUE user identifier. No client identifier is bound; the optional `serverIdentifier` is bound into every record.
- **security** Challenge state lives in Better Auth `verification` rows: single use (`consumeVerificationValue`), 5-minute lifetime, never sent to the client. Reset tokens are 256-bit, stored as SHA-256, single use, one hour by default; `verify` does not consume them.
- **security** Enumeration: unknown emails and users without an OPAQUE account get a fake login response for `HMAC-SHA-256(secret, "opaque/fake/" + email)`; all sign-in failures share `INVALID_CREDENTIALS` (401), also when detected on the client. Sign-up for an existing email matches Better Auth email/password sign-up in the same configuration. Residual leakage is documented in `docs/security.md`.
- **security** Error codes: `INVALID_SERVER_SETUP`, `INVALID_CREDENTIALS`, `INVALID_PASSWORD`, `INVALID_STATE`, `INVALID_OPAQUE_MESSAGE`, `INVALID_RESET_TOKEN`, `USER_NOT_FOUND`, `OPAQUE_ACCOUNT_NOT_FOUND`, `CREDENTIAL_CHANGED`, `PAYLOAD_NOT_SUPPORTED`, `INVALID_PAYLOAD`, `TWO_FACTOR_NOT_SUPPORTED`, and the client-only `KEY_STRETCHING_MISMATCH`.
- **security** Missing `serverSetup` throws at construction; an invalid one fails every flow closed with `INVALID_SERVER_SETUP`. Server-only `auth.api.validateOpaqueSetup()` and `auth.api.createPasswordResetToken()` are not reachable over HTTP.
- **security** Key-stretching profile (default `"rfc-recommended"`) is stored per account and returned by the sign-in challenge.
- **security** Password change and reset switch the credential with a compare-and-set on the previous version (concurrent switches: one wins, the other gets `CREDENTIAL_CHANGED`) and then revoke other sessions (change) or all sessions (reset). A sign-in proven against a credential that changed before its session was created fails and leaves no session.
- **security** Two-factor authentication: OPAQUE sign-in runs Better Auth's own `twoFactor` sign-in gate (TOTP, OTP, backup codes, trusted devices). New endpoints `POST /sign-in/opaque/payload` (redeems a single-use `payloadToken` after the second factor; payloads are never returned before it) and `POST /opaque/password-proof/{challenge,complete}` (one-time OPAQUE password proof accepted in the `password` field of `/two-factor/enable`, `/disable`, `/get-totp-uri`, `/generate-backup-codes`). Requires `twoFactor({ allowPasswordless: true })`. `TWO_FACTOR_NOT_SUPPORTED` is returned only when the installed two-factor plugin's sign-in hook cannot be found.
- **security** Rate limits on every endpoint: 5 requests per 60 s on sign-in, sign-in payload, password-proof and reset paths, 10 per 60 s on sign-up and password change.
- App payload hooks `validatePayload`, `commitPayload`, `activatePayload` (with `previousCredentialVersion`) and `loadPayload` (with the account's current `credentialVersion`), ordered so that a failure at any step leaves a working password with its matching payload.
- Client plugin `opaqueClient()` from `@alkalines/better-auth-opaque/client`: `signUp.opaque`, `signIn.opaque`, `opaque.changePassword`, `opaque.resetPassword`, `opaque.verifyResetToken`, `opaque.loadSignInPayload`, `opaque.createPasswordProof`. The export key is returned only after the server's finish step succeeded; payload builders receive it locally.
- `@serenity-kit/opaque` is loaded lazily on first use, so importing the package does not compile WebAssembly.
- CLI `better-auth-opaque create-setup`.
