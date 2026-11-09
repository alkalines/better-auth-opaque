# Security notes

Design decisions and residual risks of `@alkalines/better-auth-opaque`. Usage lives in the [README](../README.md); behavior lives in the code under [`src/`](../src).

## Threat model

OPAQUE (RFC 9807) is an augmented PAKE: the server stores a registration record from which the password cannot be recovered without an offline dictionary attack, and the password never crosses the network.

In scope:

- **Network attackers and the TLS terminator / reverse proxy** see protocol messages only. The password is never in a request; the export key is never in a request or response.
- **Database disclosure** (backup leak, SQL injection elsewhere) yields registration records. Without the server setup (the OPRF seed and server key pair) records cannot even be attacked offline; with the setup, each guess costs one OPRF evaluation plus the account's key-stretching (Argon2id) cost.
- **Online guessing** is limited by Better Auth's rate limiter on every challenge and complete endpoint (stricter on sign-in and reset), and optionally per account through the `accountRateLimit` hook (see residual leakage for why per-IP limits alone are weak).
- **Cross-site requests.** The cookie-less first-login endpoints (sign-in, sign-up, reset) run Better Auth's `formCsrfMiddleware` like `/sign-in/email`, so a cross-site `Origin` or Fetch Metadata request is refused even without cookies. Session-bound endpoints are covered by Better Auth's global origin check because they always carry cookies.
- **Account enumeration** through sign-in and reset is reduced as described under residual leakage.
- **Replay** of any challenge state: state rows are single use (`consumeVerificationValue`) and expire after 5 minutes.
- **A compromised authentication backend, when the client code is distributed separately** (a native or packaged app, or a web client served from another origin). The backend holds the setup and controls every response; the client limits what it can do with them:
  - **Registrations** (sign-up, change, reset, attach) only use a key-stretching profile from the client's `registration` allowlist (default: serenity's named profiles, all at least `memory-constrained`). A backend advertising a weaker or missing profile gets `KEY_STRETCHING_MISMATCH` before the password is stretched, the payload builder runs, or anything is sent. Without this, a backend could have new records protected by trivial Argon2id parameters and recover the export key cheaply offline.
  - **Logins** (sign-in, password proof, the current-password half of a change) only derive with a profile from the client's `login` allowlist, so a backend cannot make the client run unbounded Argon2id work (tab freeze or out-of-memory).
  - Challenge responses are parsed with the contract schemas, and serenity failures are caught; both become `INVALID_SERVER_RESPONSE` instead of an exception. The schema also bounds custom Argon2id profiles (`ARGON2ID_CUSTOM_LIMITS`: at most 64 iterations, 2 GiB − 1 KiB memory, 64 lanes, and at least 8 KiB per lane), so even an allowlisted profile cannot ask for more than serenity can run.
  - Still possible: offline guessing at the cost of the weakest allowed profile, and refusing service.

Out of scope:

- A compromised server process that also serves the client code (typical web deployments): it can serve malicious JavaScript, and OPAQUE cannot protect a password typed into JavaScript the attacker controls.
- Compromised client devices.
- Denial of service beyond Better Auth's rate limiting.

## Export key handling (RFC 9807 §10.4)

The export key is derived on the client and is the only value apps may use to encrypt client-side data (via the payload hooks). The client plugin:

- returns `exportKey` to the caller only after the matching `complete` call succeeded;
- hands it to a `payload(exportKey)` builder before `complete` only for registrations (sign-up, change, reset, attach), and only the resulting payload, never the key, is sent;
- never uses or exposes the OPAQUE session key in its place.

## State binding and replay

- Sign-up state binds the email and a freshly minted credential id. Sign-in state binds the server login state, user and credential version. Change-password state binds the user, the account and its credential version at challenge time; a credential change between challenge and complete aborts with `CREDENTIAL_CHANGED`.
- Reset: the token is stored as SHA-256, `verify` does not consume it, `challenge` consumes it and issues a reset state that `complete` consumes. The token row binds the user, the credential version at issuance and a per-user reset epoch (`opaque:reset-epoch:<userId>`). Any reset or password change therefore invalidates every other outstanding link (verify and challenge answer `INVALID_RESET_TOKEN`), and `createPasswordResetToken({ revokePrevious: true })` or `revokePasswordResetTokens` rotate the epoch to invalidate links without a credential change. Tokens issued by 0.1.x carry no binding and are rejected.

## Identifiers

- The OPAQUE user identifier is a random 256-bit credential id (`account.accountId`), not the email, so changing a user's email does not invalidate the record and records do not reveal emails.
- No client identifier is bound. The optional `serverIdentifier` is bound into every record; **changing or adding it later breaks every existing record** (all users would have to reset their passwords).

## Write ordering instead of transactions

Better Auth adapters, including the Convex adapter, do not all support multi-write transactions. Every registration therefore writes in an order where each intermediate state is valid: the app payload for a new credential version is committed before the account record points at it, and only the replaced version's payload is removed after the switch (`activatePayload` receives `previousCredentialVersion`). A failure at any step leaves the account on either the old or the new credential, each with its matching payload. Sign-up deletes the user it created if a later step fails, and wraps its writes in a transaction when the adapter has one.

## Concurrent credential changes and sessions

- **Compare-and-set switch.** Password change and reset switch the account with a single update conditioned on the credential version the request proved or was issued against. Two concurrent replacements from the same version cannot both win; the loser gets `CREDENTIAL_CHANGED`. Because the condition is part of the update, Better Auth's `account.update` database hooks do not run for this write.
- **Sign-in racing a change or reset.** A sign-in proof is bound to the credential version at challenge time. After creating the session, sign-in re-reads the account; if the credential changed meanwhile, the session is deleted and the attempt fails like a wrong password. Together with "switch, then revoke" on the change/reset side, a proof made with the old password cannot leave a live session behind.
- **Revocation.** Password change and attach revoke **every** session of the user (`deleteUserSessions`, which is not limited to one page of sessions and covers secondary storage) and then issue a new session to the caller, like Better Auth's `changePassword({ revokeOtherSessions: true })`; reset revokes all sessions and issues none. Revocation runs whenever the switch happened, also when `activatePayload` fails afterwards; in that case the caller gets the error and no replacement session and signs in with the new password. With Better Auth's `session.cookieCache` enabled, a revoked session can stay usable from its cookie until the cache entry expires.
- **Two-factor authentication.** Better Auth's two-factor plugin only matches its own sign-in routes, so the opaque plugin runs that plugin's sign-in hook for `/sign-in/opaque/complete` instead of reimplementing it (trust device, cookie, attempts stay Better Auth's). The 2FA signal appears only after a valid password proof, so wrong passwords and unknown emails stay indistinguishable. App payloads are withheld until the second factor is verified: the sign-in returns a single-use `payloadToken` (stored as SHA-256, bound to the user and credential version, expiring with the two-factor cookie) that `/sign-in/opaque/payload` redeems only for a session of that user created after the token. The export key is not 2FA-protected: anyone holding the password derives it locally from the challenge. If the installed two-factor plugin's sign-in hook cannot be found (Better Auth internals changed), sign-in fails closed with `TWO_FACTOR_NOT_SUPPORTED` before a session exists.
- **2FA management.** OPAQUE users have no credential password, so `twoFactor({ allowPasswordless: true })` is required, and the opaque plugin substitutes a password proof: an OPAQUE login against the session user's credential yields a one-time proof (SHA-256 stored, 5 minutes, bound to user and credential version) that the two-factor management endpoints consume in their `password` field. A stolen session alone therefore cannot enable or disable 2FA or read the TOTP URI or backup codes.
- **Pending 2FA across a credential change.** Every pending second-factor challenge is bound to the credentials that proved the first factor. The plugin records, on the request's own copy of the auth context, the challenge the two-factor gate writes (the verification row whose value is the signed-in user's id) and stores `opaque:two-factor-pending:<SHA-256 of the challenge id>` with a snapshot: the OPAQUE credential version (the proven one for OPAQUE sign-ins) and a SHA-256 of the classic password hash (for native email, username or phone sign-ins, the hash the password was actually verified against). This covers OPAQUE sign-ins and Better Auth's own `/sign-in/email`, `/sign-in/username` and `/sign-in/phone-number`. When the snapshot no longer matches — an OPAQUE change, reset or attach, an enrolment reset, a removed classic credential, or Better Auth's own `/change-password` and `/reset-password` — `/two-factor/send-otp`, `/verify-totp`, `/verify-otp` and `/verify-backup-code` fail with `CREDENTIAL_CHANGED`: no OTP is sent, no backup code is spent, the challenge is deleted so it cannot be retried, and no session is created. A challenge without a binding is refused the same way, so challenges pending while upgrading to 0.2.0 fail once. If a switch races the verify, the session and any trusted-device record the verify created are deleted afterwards. The comparison is exact and does not depend on clocks. Nothing is parsed from `Set-Cookie` headers; if the gate stops writing its challenge through `internalAdapter.createVerificationValue` or resolving its cookie through `createAuthCookie`, 2FA sign-in fails closed.

## Migration from classic passwords

- **Attach** (`/opaque/attach/*`) needs a session read from the store, a classic `credential` account with a password hash, and no OPAQUE credential. By default the challenge verifies the classic password with Better Auth's password hasher; that password is already known to the server, so sending it adds no exposure. The client refuses a new password equal to it (`PASSWORD_REUSED`): an OPAQUE credential under a password the server knows would let the server derive the export key. With `attach.requireCurrentPassword: false`, a session younger than `freshSessionAge` suffices instead, which a stolen fresh session also satisfies.
- The attach state binds the user, a fresh credential id and a fingerprint of the classic account; complete re-checks that no OPAQUE credential exists and that the classic password did not change, commits the payload, creates the OPAQUE account, and re-reads the user's accounts: if a concurrent attach or enrolment also created one, this one is deleted and the request fails with `OPAQUE_ACCOUNT_EXISTS`, so the first credential wins. It then activates the payload, deletes the classic account (`removeClassicCredential`), revokes every session and issues a new one to the caller. A failure after the OPAQUE account exists still runs the remaining steps and returns the first error; if the classic account survives, `auth.api.removeClassicCredential` finishes the migration.
- **Enrolment reset** (`createPasswordResetToken({ allowEnrolment: true })`) issues links for users without an OPAQUE credential. Such a link is valid only while the user still has none; completing it runs the same sequence as attach (without a session) and revokes all sessions. Possession of the link is the only authorization, as for any reset.

## Residual leakage

What an attacker who does not know the password can still learn:

- **Sign-up with an existing email** mirrors Better Auth email/password sign-up in the same configuration ([`email-password-parity.ts`](../src/server/email-password-parity.ts)):
  - Default configuration: the sign-up challenge answers `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` (HTTP 422), exactly the information email/password sign-up discloses. The plugin answers at the challenge so the client does not spend a key-stretching round first.
  - `emailAndPassword.requireEmailVerification: true` or `autoSignIn: false`: the response is a synthetic user without a session token, identical in shape to a new sign-up, and `onExistingUserSignUp` is called. Timing still differs: for an existing email the complete call skips user creation and the hooks, so it returns faster. Better Auth equalizes this on its own route by hashing the password; there is no equivalent work here because the server never sees the password.
- **Key-stretching profile.** The sign-in challenge returns the profile the account was registered with; unknown emails get the server's current default. After you change `keyStretching`, accounts registered under the old profile are distinguishable from unknown emails until their next password change. A client whose `login` allowlist lacks that old profile reports `KEY_STRETCHING_MISMATCH` instead of `INVALID_CREDENTIALS` for such accounts; this adds nothing to what the challenge already reveals.
- **Timing of the sign-in challenge.** Every path computes the HMAC, looks the user up by email, runs the same indexed account query (`account.userId`, with an unused id of the database's id format when the email is unknown, so adapters without native joins such as Convex do not skip it), runs serenity's `startLogin` (with a real or `null` record) and writes a state row. Measured on a local Convex backend (30 first probes each): p50 60.0 ms for registered emails, 61.3 ms for unknown ones; repeating the same email is faster for both (Convex caches query results, p50 39.4 vs 37.5 ms over 100 probes). These are local measurements, not a guarantee for other adapters or deployments.
- **Email verification.** `EMAIL_NOT_VERIFIED` (403) is only returned after a valid password proof, so it reveals nothing to someone without the password.
- **Password reset.** `auth.api.createPasswordResetToken` returns `USER_NOT_FOUND` for emails without an OPAQUE account. It is not reachable over HTTP; apps must not forward the difference to the requester (answer "if the account exists, we sent an email" in both cases). `/reset/opaque/verify` returns the current `loadPayload` output to anyone holding a valid token, so payloads must be ciphertext under export-key-derived keys, never plaintext secrets.
- **Password policy.** `emailAndPassword.minPasswordLength`/`maxPasswordLength` cannot be enforced by the server because it never sees the password; enforce them in the client before calling the plugin.
- **Rate limits** are Better Auth's (per client IP and path): 5 requests per 60 s on sign-in, sign-in payload, password-proof, reset and attach-challenge paths, 10 per 60 s on sign-up, password change and attach complete. They do not limit guesses per account across many IPs, and they are only as good as the client IP Better Auth resolves (behind proxies, or on Convex, check `advanced.ipAddress` and the header your edge sets; with no usable IP every request shares one bucket) and its storage (the default in-memory storage is per instance). Better Auth enables rate limiting in production only by default. Use `accountRateLimit` with a shared store for per-account limits: it receives an HMAC of the email that is computed the same way for unknown emails.

## Server setup backup

The server setup (`bun run create-setup`) contains the OPRF seed and the server's long-term private key. Losing it invalidates every registration record: no user can sign in until they reset their password. Leaking it enables offline dictionary attacks against any leaked registration records.

- Generate it once per deployment, store it in your secret manager, and keep an offline backup.
- Never commit it; never generate it at runtime (the plugin refuses to start flows without a valid setup).
- Use `auth.api.validateOpaqueSetup()` at boot to fail fast on a missing or malformed value.
