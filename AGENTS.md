# better-auth-opaque: agent instructions

## Package boundaries

- `@alkalines/better-auth-opaque` is a Better Auth (1.7.x) plugin for OPAQUE password authentication (RFC 9807) built on `@serenity-kit/opaque`, pinned exactly at 1.1.x. One package: server plugin (`.`), client plugin (`./client`), and the `better-auth-opaque` binary (`create-setup`). MIT; credit TheUntraceable/better-auth-opaque in the license notice and source comments if any of its code is adapted.
- The package is generic and reusable by any alkalines project. Radium (github.com/alkalines/Radium) is the first consumer and pins exact versions; nothing here may reference Radium's keys, schema, or flows. App-specific data travels through generic hooks.
- **The password never reaches the server; the export key never leaves the client.** Return the export key only after the server's finish step succeeded (RFC 9807 §10.4). **Never substitute the session key for the export key.**
- Published code uses Web APIs only: no `node:*` imports, no `Buffer`, no `fs`, no top-level await, no import-time side effects other than declaring exports. ESM only, `sideEffects: false`. The client entry must not import server code.
- Published code must run in Node, Bun, browsers, and serverless runtimes. The Convex default runtime is required; edge runtimes count only as verified.
- Missing or invalid server setup **fails closed**. Never generate a setup implicitly at runtime.
- Login, sign-up, and reset state is single use (Better Auth `verification` rows consumed with `consumeVerificationValue`), short-lived, and **never sent to the client when it contains server secrets**.
- Responses for unknown emails must be indistinguishable from wrong passwords: shape, status, and error code; timing as far as reasonable.
- Server-only APIs (`createPasswordResetToken`) use Better Auth's `SERVER_ONLY` endpoint metadata and are **never HTTP-reachable**.
- Do not claim a runtime, adapter, or browser is supported until a test in this repository runs there.

## Commands and setup

- Bun is the package manager and script runner: `bun install`, `bun run <script>`. Bun is not a runtime requirement for consumers.
- The scripts below are **added in the implementation session**; until they exist in `package.json`, do not run or cite them as checks, and do not invent flags for them.
  - `lint`: oxlint.
  - `format` / `format:check`: oxfmt write / check. Do not format unrelated files or hard-wrap Markdown prose.
  - `typecheck`: TypeScript over the package, examples, and tests.
  - `test`: Vitest with Node and edge-runtime projects.
  - `test:convex`: tests against a real local Convex backend in `test/convex`.
  - `test:e2e`: Playwright Chromium against `examples/tanstack-start`.
  - `build`: tsdown.
  - `check:package`: publint and Are The Types Wrong against the built package.
- Workspaces: the root is the published package; `examples/*` and `test/convex` are private workspaces and never published.
- `OPAQUE_SERVER_SETUP` for examples and fixtures comes from `bun run create-setup`. **Never commit a real setup.** `.env*` files are gitignored except `.env.example`.

## Code ownership

- `src/contract.ts` owns endpoint request/response schemas, error codes, and hook types, shared by server and client. `src/server/` owns endpoints, state, and storage; `src/client/` owns the client plugin; `src/cli.ts` owns the binary.
- Use Better Auth primitives instead of copies: `createAuthEndpoint`, `sessionMiddleware`, `internalAdapter` (`createUser`/`createAccount`/`createSession`, verification values), `setSessionCookie`, plugin `schema`, `rateLimit`, `$ERROR_CODES`. Read the installed `better-auth` sources for signatures; do not guess.
- Dependencies: `@serenity-kit/opaque` is an exact pin; `better-auth` and `zod` are peer dependencies with tested ranges. No other runtime dependencies without recording why in the PR.

## Code clarity and documentation

- Prefer straightforward code over both dense clusters and fragmented call chains. Use descriptive names, ordinary control flow, and whitespace between meaningful phases; avoid nested ternaries, clever expression chains, and packing unrelated work into one statement. Optimize for understanding, not minimum line count.
- Before adding a helper, search the owning module and `src/contract.ts` for the same behavior, including differently named equivalents. Reuse or extend a compatible helper without weakening its contract; do not copy it into another file. Promote genuinely shared behavior to its nearest common owner, not a catch-all utilities module.
- Extract a function when it owns a meaningful policy, isolates a complex operation, or removes real duplication. Keep simple one-use steps inline; do not create pass-through wrappers, chains of tiny helpers, or temporary variables that merely rename a value. A longer cohesive function can be clearer than several one-line functions; split by responsibility, not an arbitrary line limit.
- Use **TSDoc beside declarations** for exported APIs, shared contracts, and non-obvious internal contracts. Explain purpose and relevant trust/secret-handling assumptions, inputs/outputs, side effects, failures, and single-use/retry constraints; do not repeat types or add boilerplate tags. Improve missing documentation in the code you touch rather than creating a Markdown mirror.
- Use short **`//` comments immediately above the relevant block** when names/control flow cannot explain why it exists: secret-handling or enumeration safeguards, ordering or atomicity requirements, state consumption, migration fallbacks, protocol quirks, bounds/units, or workarounds. Explain the invariant, reason, or consequence—not a translation of the following line. Add an issue/reference for a workaround when one exists.
- For multi-phase logic, a brief comment can orient the reader at a non-obvious transition; do not label every statement or use comments to excuse tangled code. Prefer clearer names or a simpler structure first. Keep comments accurate when behavior changes; remove stale comments and commented-out code you encounter in the touched logic.
- `README.md` is the user guide: install, server/client setup, hooks, setup generation and backup, Convex local install, and a supported-runtimes table with evidence. `docs/` holds design decisions and security notes only—not exhaustive function/API descriptions. `CHANGELOG.md` records every released change. Keep setup instructions and environment examples aligned with executable config; link to code rather than duplicating its behavior. Do not hard-wrap prose for visual spacing.

## Security review triggers

- Any change to endpoint shapes, stored fields, state lifetime, identifiers, key stretching, enumeration behavior, or error codes needs a test of the security property and a CHANGELOG entry flagged **security**.

## Compatibility and releases

- Semver. Breaking changes: endpoint paths or bodies, stored fields, hook signatures, error codes, stretching defaults, supported peer ranges. Stored-data changes need a documented migration.
- `version` in `package.json` changes only in a release PR. CI publishes on `v*.*.*` tags to npm and GitHub Packages; **never run `npm publish` locally** after the first bootstrap release.

## Verification

- Test observable behavior and security boundaries—single use, enumeration resistance, export key equality between registration and login, fail-closed setup—not implementation details, mock call counts, or library behavior. Extend focused coverage for actual regressions; do not add suites simply to increase test count. Preserve useful coverage when consolidating redundant tests.
- Unit tests use Better Auth with the memory adapter; they are fast regression checks, **not integration verification**. Convex claims need `test:convex` against a real local backend; browser claims need `test:e2e`. If prerequisites or permission are missing, report that verification as blocked; do not substitute more mocks or claim end-to-end success.
- Report which of unit, runtime, Convex, and browser checks ran, and which were skipped and why.

## Generated files and workflow

- Never hand-edit generated files (`dist/`, Convex `_generated/` in `test/convex`, route trees in examples). Review generated diffs; a build does not prove runtime support.
- Do not present an intended or untested path as a working quickstart. Distinguish intended work from implemented and verified behavior.
- Work on task branches and integrate through PRs targeting `main`; do not commit directly to `main`. Do not commit, push, open or merge PRs, tag, or publish without explicit authorization.
