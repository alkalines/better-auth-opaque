# Security notes

Design decisions and residual risks of `@alkalines/better-auth-opaque`. Usage lives in the [README](../README.md); behavior lives in the code under [`src/`](../src).

## Threat model

OPAQUE (RFC 9807) is an augmented PAKE: the server stores a registration record from which the password cannot be recovered without an offline dictionary attack, and the password never crosses the network.

In scope:

- **Network attackers and the TLS terminator / reverse proxy** see protocol messages only. The password is never in a request; the export key is never in a request or response.
- **Database disclosure** (backup leak, SQL injection elsewhere) yields registration records. Without the server setup (the OPRF seed and server key pair) records cannot even be attacked offline; with the setup, each guess costs one OPRF evaluation plus the account's key-stretching (Argon2id) cost.
- **Online guessing** is limited by Better Auth's rate limiter on every challenge and complete endpoint (stricter on sign-in and reset).
- **Account enumeration** through sign-in and reset is reduced as described under residual leakage.
- **Replay** of any challenge state: state rows are single use (`consumeVerificationValue`) and expire after 5 minutes.

Out of scope:

- A compromised server process. It sees the server setup and every login's server state and can serve malicious client code in web deployments; OPAQUE cannot protect a password typed into JavaScript the attacker controls.
- Compromised client devices.
- Denial of service beyond Better Auth's rate limiting.

## Export key handling (RFC 9807 §10.4)

The export key is derived on the client and is the only value apps may use to encrypt client-side data (via the payload hooks). The client plugin:

- returns `exportKey` to the caller only after the matching `complete` call succeeded;
- hands it to a `payload(exportKey)` builder before `complete` only for registrations (sign-up, change, reset), and only the resulting payload, never the key, is sent;
- never uses or exposes the OPAQUE session key in its place.

## State binding and replay

- Sign-up state binds the email and a freshly minted credential id. Sign-in state binds the server login state, user and credential version. Change-password state binds the user, the account and its credential version at challenge time; a credential change between challenge and complete aborts with `CREDENTIAL_CHANGED`.
- Reset: the token is stored as SHA-256, `verify` does not consume it, `challenge` consumes it and issues a reset state that `complete` consumes.

## Identifiers

- The OPAQUE user identifier is a random 256-bit credential id (`account.accountId`), not the email, so changing a user's email does not invalidate the record and records do not reveal emails.
- No client identifier is bound. The optional `serverIdentifier` is bound into every record; **changing or adding it later breaks every existing record** (all users would have to reset their passwords).

## Write ordering instead of transactions

Better Auth adapters, including the Convex adapter, do not all support multi-write transactions. Every registration therefore writes in an order where each intermediate state is valid: the app payload for a new credential version is committed before the account record points at it, and only the replaced version's payload is removed after the switch (`activatePayload` receives `previousCredentialVersion`). A failure at any step leaves the account on either the old or the new credential, each with its matching payload. Sign-up deletes the user it created if a later step fails, and wraps its writes in a transaction when the adapter has one.

## Concurrent credential changes and sessions

- **Compare-and-set switch.** Password change and reset switch the account with a single update conditioned on the credential version the request proved or was issued against. Two concurrent replacements from the same version cannot both win; the loser gets `CREDENTIAL_CHANGED`. Because the condition is part of the update, Better Auth's `account.update` database hooks do not run for this write.
- **Sign-in racing a change or reset.** A sign-in proof is bound to the credential version at challenge time. After creating the session, sign-in re-reads the account; if the credential changed meanwhile, the session is deleted and the attempt fails like a wrong password. Together with "switch, then revoke" on the change/reset side, a proof made with the old password cannot leave a live session behind.
- **Revocation.** Password change revokes the user's other sessions; reset revokes all of them. Revocation runs whenever the switch happened, also when `activatePayload` fails afterwards. With Better Auth's `session.cookieCache` enabled, a revoked session can stay usable from its cookie until the cache entry expires.
- **Two-factor authentication.** Better Auth's two-factor plugin only matches its own sign-in routes, so the opaque plugin runs that plugin's sign-in hook for `/sign-in/opaque/complete` instead of reimplementing it (trust device, cookie, attempts stay Better Auth's). The 2FA signal appears only after a valid password proof, so wrong passwords and unknown emails stay indistinguishable. App payloads are withheld until the second factor is verified: the sign-in returns a single-use `payloadToken` (stored as SHA-256, bound to the user and credential version, expiring with the two-factor cookie) that `/sign-in/opaque/payload` redeems only for a session of that user created after the token. The export key is not 2FA-protected: anyone holding the password derives it locally from the challenge. If the installed two-factor plugin's sign-in hook cannot be found (Better Auth internals changed), sign-in fails closed with `TWO_FACTOR_NOT_SUPPORTED` before a session exists.
- **2FA management.** OPAQUE users have no credential password, so `twoFactor({ allowPasswordless: true })` is required, and the opaque plugin substitutes a password proof: an OPAQUE login against the session user's credential yields a one-time proof (SHA-256 stored, 5 minutes, bound to user and credential version) that the two-factor management endpoints consume in their `password` field. A stolen session alone therefore cannot enable or disable 2FA or read the TOTP URI or backup codes.
- **Pending 2FA across a reset.** As with Better Auth email/password sign-in, a second-factor challenge started with the old password is not cancelled by a password reset: someone holding the old password and the second factor can still complete it and get a session. `loadSignInPayload` refuses such a session with `CREDENTIAL_CHANGED`.

## Residual leakage

What an attacker who does not know the password can still learn:

- **Sign-up with an existing email** mirrors Better Auth email/password sign-up in the same configuration ([`email-password-parity.ts`](../src/server/email-password-parity.ts)):
  - Default configuration: the sign-up challenge answers `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` (HTTP 422), exactly the information email/password sign-up discloses. The plugin answers at the challenge so the client does not spend a key-stretching round first.
  - `emailAndPassword.requireEmailVerification: true` or `autoSignIn: false`: the response is a synthetic user without a session token, identical in shape to a new sign-up, and `onExistingUserSignUp` is called. Timing still differs: for an existing email the complete call skips user creation and the hooks, so it returns faster. Better Auth equalizes this on its own route by hashing the password; there is no equivalent work here because the server never sees the password.
- **Key-stretching profile.** The sign-in challenge returns the profile the account was registered with; unknown emails get the server's current default. After you change `keyStretching`, accounts registered under the old profile are distinguishable from unknown emails until their next password change.
- **Timing of the sign-in challenge.** Both paths compute the HMAC, look the email up the same way, run serenity's `startLogin` (with a real or `null` record) and write a state row. Residual differences in database access patterns are not measured.
- **Email verification.** `EMAIL_NOT_VERIFIED` (403) is only returned after a valid password proof, so it reveals nothing to someone without the password.
- **Password reset.** `auth.api.createPasswordResetToken` returns `USER_NOT_FOUND` for emails without an OPAQUE account. It is not reachable over HTTP; apps must not forward the difference to the requester (answer "if the account exists, we sent an email" in both cases). `/reset/opaque/verify` returns the current `loadPayload` output to anyone holding a valid token, so payloads must be ciphertext under export-key-derived keys, never plaintext secrets.
- **Password policy.** `emailAndPassword.minPasswordLength`/`maxPasswordLength` cannot be enforced by the server because it never sees the password; enforce them in the client before calling the plugin.
- **Rate limits** are Better Auth's (per client IP and path): 5 requests per 60 s on sign-in, sign-in payload, password-proof and reset paths, 10 per 60 s on sign-up and password change. They do not limit guesses per account across many IPs. Note that Better Auth enables rate limiting in production only by default.

## Server setup backup

The server setup (`bun run create-setup`) contains the OPRF seed and the server's long-term private key. Losing it invalidates every registration record: no user can sign in until they reset their password. Leaking it enables offline dictionary attacks against any leaked registration records.

- Generate it once per deployment, store it in your secret manager, and keep an offline backup.
- Never commit it; never generate it at runtime (the plugin refuses to start flows without a valid setup).
- Use `auth.api.validateOpaqueSetup()` at boot to fail fast on a missing or malformed value.
