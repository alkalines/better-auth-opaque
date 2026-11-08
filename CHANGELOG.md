# Changelog

All notable changes to `@alkalines/better-auth-opaque` are recorded here. The project follows [Semantic Versioning](https://semver.org/).

## 0.1.1 (2026-11-07)

First published release. The package contents match 0.1.0. The release workflow now creates its pack directory before running `npm pack`.

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
