# Building

OpenCred is built with **pnpm workspaces** and per-package TypeScript compilation. Some packages also compile native C/C++ addons via `node-gyp`. This page covers how everything is wired together.

## Prerequisites

| Tool | Version | Notes |
|---|---|---|
| Node.js | **20+** | `.nvmrc` pins the exact version. Use `nvm use` if you have nvm. |
| pnpm | **9+** | Pinned by `packageManager` in the root `package.json` (`pnpm@10.30.1` at time of writing). |
| Python | 3.x | Used by `node-gyp` for native compilation |
| C/C++ toolchain | platform-specific | macOS: Xcode Command Line Tools (`xcode-select --install`). Windows: Visual Studio Build Tools with the C++ workload. Linux: `build-essential` and `python3` packages. |

The native toolchain is **only** required if you build the Desktop client locally — the Docker image build doesn't need a host toolchain because it builds inside Alpine.

## Installing dependencies

```bash
# Install the lockfile-locked versions (CI uses this)
pnpm install --frozen-lockfile

# Or, if you've changed package.json files locally
pnpm install
```

If you're adding a new workspace package and the lockfile is out of date, you may need:

```bash
CI=true pnpm install --no-frozen-lockfile
```

`CI=true` forces non-interactive mode (no prompts), `--no-frozen-lockfile` allows pnpm to update the lockfile to reflect your changes. Commit the updated `pnpm-lock.yaml` in the same PR.

## Building the workspace

```bash
# Build everything (recursive across all workspace packages)
pnpm build
```

This runs `pnpm -r run build`, which invokes each package's `build` script in dependency order. For most packages this is just `tsc`. A few have additional steps:

| Package | Extra build step |
|---|---|
| `packages/vc-core` | `node scripts/embed-contexts.cjs && tsc` — bakes JSON-LD contexts into the dist output |
| `packages/templates` | `node scripts/embed-svgs.cjs && tsc` — bakes SVG templates into the dist output |
| `packages/signing` | `tsc && npm run build:native` — compiles native addons via `node-gyp rebuild` |
| `apps/desktop` | `vite build && node scripts/bundle-main.mjs` — Vite for the renderer, esbuild for the main process |
| `apps/desktop` (full) | `pnpm build:dist` — adds `electron-rebuild`, native dep prep, and `electron-builder` |
| `apps/server` | `tsc` — straightforward |

## Type-checking

```bash
# Type-check across all workspaces (no emit)
pnpm typecheck
```

Each package has its own `tsconfig.json` extending the root `tsconfig.base.json`. The base config sets:

* `strict: true`
* `noUnusedLocals: true`
* `noUnusedParameters: true`
* ESM module resolution

Unused variables and parameters are **errors**, not warnings — they will fail the build. This is intentional: OpenCred is a security-sensitive codebase and dead code is a vector for confusion.

## Linting and formatting

```bash
# Lint TypeScript files
pnpm lint

# Auto-fix lint errors where possible
pnpm lint:fix

# Format code with Prettier
pnpm format

# Check formatting without modifying files
pnpm format:check
```

Configuration files: `.eslintrc.json`, `.prettierrc`, `.prettierignore`.

## Cleaning

```bash
# Remove all dist directories and node_modules
pnpm clean
```

This runs `pnpm -r run clean && rm -rf node_modules` from the root. Use it when you want a fresh build, or when switching between Node.js versions.

## Building the Desktop client

```bash
cd apps/desktop

# Dev mode — Vite + Electron with hot reload
pnpm dev

# Production build (renderer + main bundle, no installer)
pnpm build

# Full distributable build (rebuilds native modules, runs electron-builder)
pnpm build:dist
```

`pnpm build:dist` produces installers in `apps/desktop/out/` for the host platform:

| Platform | Output |
|---|---|
| macOS | `.dmg` and `.zip` (universal: x64 + arm64) |
| Windows | `.exe` (NSIS installer) |
| Linux | `.AppImage` and `.deb` |

The exact targets are configured in `apps/desktop/package.json` under the `build` key (electron-builder). macOS builds are signed and notarized via the `afterSign` hook (`scripts/notarize.cjs`); credentials must be set in the environment for signing to succeed.

### Native addon rebuild

Hardware token and OS certificate store signing rely on N-API addons (`pkcs11js` plus the OpenCred-built `macos-keychain` and `windows-cng` addons under `packages/signing/native/`). They must be built against the **Electron** ABI, not Node's ABI, before packaging:

```bash
cd apps/desktop
pnpm rebuild:native
```

This is automatic during `pnpm build:dist`. Run it manually if you change the Electron version or you see errors like `Module did not self-register`.

## Building the Docker image

The Docker image is built from `apps/server/Dockerfile`:

```bash
docker build -f apps/server/Dockerfile -t opencred:latest .
```

The Dockerfile is multi-stage:

1. **Builder stage** — `node:20-alpine` with `pnpm`. Copies the workspace, installs dependencies (`--frozen-lockfile`), runs `pnpm --filter @opencred/server... build`, then `pnpm prune --prod`.
2. **Runtime stage** — fresh `node:20-alpine`. Copies only the production output and `node_modules`. Runs as the non-root `node` user.

Base image digests are pinned (`node:20-alpine@sha256:b5b9467f...`) for reproducible builds. To update, run:

```bash
docker pull node:20-alpine
docker inspect --format='{{index .RepoDigests 0}}' node:20-alpine
```

and replace the digest in the Dockerfile.

The image exposes port 3100 and includes a `HEALTHCHECK` that polls `/health` every 30 seconds.

See the [Docker deployment guide](../docker/deployment.md) for runtime configuration.

## Turborepo (optional)

OpenCred uses pnpm workspaces directly. Some scripts may benefit from Turborepo's caching for incremental rebuilds, but the default `pnpm -r run build` is the canonical entry point. There is no Turborepo configuration file at the repo root today; if you want caching across runs, install `turbo` and add `turbo.json` per the [Turborepo docs](https://turbo.build/repo/docs).

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `node-gyp` errors during install | Missing C/C++ toolchain or Python | Install Xcode CLT / VS Build Tools / build-essential |
| `Module did not self-register` when running Desktop | Native addon built against wrong ABI | `pnpm rebuild:native` from `apps/desktop` |
| `pnpm install` says "lockfile out of sync" | Lockfile is older than `package.json` files | `CI=true pnpm install --no-frozen-lockfile`, then commit `pnpm-lock.yaml` |
| TypeScript errors about unused variables | Strict mode with `noUnusedLocals` | Remove the variable, prefix with `_`, or use it |
| `electron-builder` fails to notarize on macOS | Missing `APPLE_ID` / `APPLE_APP_SPECIFIC_PASSWORD` env vars | Set them, or skip notarization for local builds (see `scripts/notarize.cjs`) |
| Docker build fails on `pnpm install` | Lockfile mismatch with the workspace | Make sure `pnpm-lock.yaml` is committed and current |
