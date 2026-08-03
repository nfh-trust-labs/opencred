# Developer Guide

This section is for contributors and anyone building OpenCred from source. If you just want to use OpenCred, see the [Desktop](../desktop/README.md) or [Docker](../docker/README.md) operator guides instead.

## Pages in this section

* [Package layout](package-layout.md) — what each workspace package does
* [Building](building.md) — pnpm, Turborepo, native addons, the build pipeline
* [Testing](testing.md) — vitest, integration tests, coverage targets

## Repository at a glance

OpenCred is a TypeScript monorepo using **pnpm workspaces** and (where useful) **Turborepo** for caching. The runtime is Node.js 20+.

```
opencred/
  apps/
    desktop/             # Electron app (primary product)
    server/              # Hono HTTP server (Docker image entrypoint)
  packages/
    crypto/              # Proof generation, signing, hashing, JCS
    vc-core/             # CredentialBuilder, JSON-LD contexts, document loader
    did/                 # DID resolution: did:key, did:jwk, did:web, composite
    verification/        # Verification orchestrator (multi-format)
    schema-engine/       # JSON Schema validation, built-in schemas
    templates/           # SVG templates and renderer
    dedi-client/         # DeDi HTTP client (revocation, schemas, contexts, keys)
    ca-adapter/          # Certificate Authority adapter (extension point)
    signing/             # Hardware token + OS cert store backends
    shared/              # Shared types, errors, config schema, SSRF helper
  docs/                  # This documentation
  CLAUDE.md              # Contributor protocol and the seven security invariants
  docs/PRD.md            # Product requirements (the source of truth)
```

See [Package layout](package-layout.md) for what each package exports and depends on.

## Prerequisites

| Tool | Version | Why |
|---|---|---|
| Node.js | **20+** (`.nvmrc` pins the exact version) | Runtime for everything |
| pnpm | **9+** (`packageManager` pinned in root `package.json`) | Workspaces and lockfile management |
| Python | 3.x (with distutils) | `node-gyp` builds for native addons |
| C/C++ toolchain | platform-specific (Xcode CLT on macOS, Build Tools on Windows, `build-essential` on Linux) | Native addon compilation |

You also need:

* (Linux/macOS) `pkg-config` and OpenSSL headers if building hardware token support
* (Windows) `softhsm2` if you want to run PKCS#11 tests locally

## First-time setup

```bash
git clone https://github.com/nfh-trust-labs/opencred.git
cd opencred

# Install dependencies (frozen lockfile in CI; non-frozen locally is fine)
pnpm install

# Build all packages
pnpm build

# Run all tests
pnpm test

# Type-check across the monorepo
pnpm typecheck
```

For day-to-day development:

```bash
# Run the Desktop app in dev mode (vite + electron with hot reload)
cd apps/desktop && pnpm dev

# Run the Docker server in dev mode (tsx watch)
cd apps/server && pnpm dev

# Run a single package's tests in watch mode
cd packages/crypto && pnpm vitest
```

## Branching and PRs

* **Permanent integration branch**: `new-opencred-dev`. All feature branches start here, and all PRs target it.
* **Branch naming**: `feat/<issue#>-<short-description>` for features, `fix/...` for bug fixes, `docs/...` for documentation, `spike/...` for spikes.
* **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) — `feat(package): description`, `fix(package): description`, etc.
* **`main` is protected.** Never push to `main` directly. Never target a PR at `main`.
* **PR merge strategy**: squash merge. The squashed message follows conventional commits.
* **Delete branches after merge** — feature branches are ephemeral.

The full contributor protocol is in [`CLAUDE.md`](../../CLAUDE.md), including how to claim issues, the multi-agent protocol when working in parallel, and the spike protocol for time-boxed investigations.

## Definition of Done

Per `CLAUDE.md`, an issue is only complete when **all** of the following are true:

1. Code implements what the issue describes — no more, no less
2. Tests exist and pass
3. No lint or type errors
4. PR is reviewed and approved (or self-reviewed)
5. PR is merged to `new-opencred-dev`
6. A completion comment is posted on the issue
7. No regressions — existing tests still pass

## Contribution checklist

Before opening a PR:

- [ ] Tests added or updated
- [ ] `pnpm typecheck` passes across all packages
- [ ] `pnpm test` passes
- [ ] No new dependencies on remote network calls (especially JSON-LD contexts — see [Invariant 6](../security/invariants.md#6-json-ld-contexts-are-bundled))
- [ ] No new code paths that accept private key material — see [Invariant 1](../security/invariants.md#1-never-touch-issuer-private-keys)
- [ ] No `Math.random()` in security-sensitive paths — see [Invariant 4](../security/invariants.md#4-csprng-only)
- [ ] Logging changes don't introduce key material — see [Invariant 2](../security/invariants.md#2-never-log-key-material)
- [ ] Error messages don't leak paths or buffers — see [Invariant 5](../security/invariants.md#5-no-secrets-in-error-responses)
- [ ] PR body references the issue (`Closes #<issue>`) — note the issue still needs a manual close + completion comment after merge, since PRs land on `opencred-dev`, not the default branch

## Related documentation

* [`CONTRIBUTING.md`](../../CONTRIBUTING.md) — contribution workflow
* [`CLAUDE.md`](../../CLAUDE.md) — full contributor protocol
* [`docs/PRD.md`](../PRD.md) — product requirements
* [Security invariants](../security/invariants.md)
