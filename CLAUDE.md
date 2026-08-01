# OpenCred — Claude Code Instructions

## Mode & Stability

- **Mode: production** — correctness over speed. Testing, CI, observability,
  security, and release discipline are non-negotiable defaults.
- **Stability: stable** — the backward-compatibility gate below applies to
  every release.

## Repository

This is the canonical open-source repository for OpenCred
(github.com/nfh-trust-labs/opencred-releases, MIT license). The repo name is
historical — it began as the public release mirror, and the name was kept so
auto-update feeds in already-installed desktop apps keep working. Source,
issues, and releases all live here.

## Branch Model

- **`main`** — default branch, stable. Tracks the latest release; releases
  are tagged from it. Never push or commit to `main` directly.
- **`opencred-dev`** — development/integration branch. All feature branches
  are created from `opencred-dev` and all PRs target `opencred-dev`.

Flow:
1. Feature branch from `opencred-dev`: `feat/<issue>-<desc>` or `fix/<issue>-<desc>`.
2. PR into `opencred-dev`, **squash-merged** with a conventional-commit title.
3. Releasing = a **promotion PR** `opencred-dev` → `main`, merged with a
   **merge commit** (NEVER squashed — release-please reads the individual
   commits on `main` to compute the version and changelog).
4. release-please (running on `main`) opens the release PR; merging it tags
   `vX.Y.Z` and triggers the desktop + docker release pipelines.
5. After a release, `main` is **back-merged into `opencred-dev`** so the
   version-bump/changelog commits reach dev (otherwise the next promotion
   conflicts).

## Backward Compatibility — HARD RULE (launch-blocking)

Every version must be backward compatible. Treat any change to a public
contract as breaking: `/v1/*` request/response shapes, env vars and their
defaults, VC/JWT/PDF output formats, on-disk DID/key formats, DeDi record
shapes, desktop settings, Docker env/volumes. Prefer additive evolution.
Credentials issued by version N must verify under N+1. Migrations are
automatic and tested. Known gap: no N→N+1 upgrade test suite exists yet —
flag any change that relies on untested compatibility.

## Build & Dev Notes

- `pnpm install` needs `CI=true` for non-interactive runs.
- `pnpm build` must exit 0 before trusting local dist — schema-engine can
  abort silently on network failure.
- Tests: vitest, colocated in `src/__tests__/`. tsconfig is strict with
  noUnused* (unused vars fail the build).
- "Lint" CI = eslint + `prettier --check`. Root eslint loads ONLY
  @typescript-eslint (no react-hooks plugin — never write react-hooks/*
  disable directives).

## Security Invariants — MANDATORY

These rules are non-negotiable. Every agent, every PR, every line of code
must respect them.

### Key Management Model

- **Issuer private keys**: OpenCred NEVER receives, handles, or stores issuer
  private keys. All signing is local — the issuer's key stays on their
  machine (Desktop Client) or within their controlled environment (Docker
  Image). No code path should accept, transmit, or hold an issuer's private
  key.

### Rules

1. **Never touch issuer private keys.** No endpoint, no function, no code
   path should accept an issuer's private key as input. All signing happens
   locally on the issuer's machine or within the Docker container.
2. **Never log key material.** No private keys, no signing buffers in `pino`
   logs, `console.log`, error messages, or stack traces. Log the key *ID* or
   *fingerprint*, never the key itself.
3. **Session data is ephemeral.** Credential payloads, built VCs, and
   packaged output are purged within TTL (default 4 hours).
4. **CSPRNG only.** All key generation must use `crypto.randomBytes` or
   equivalent CSPRNG. Never use `Math.random()` for anything
   security-related.
5. **No secrets in error responses.** Error responses must never leak key
   material, internal paths, or signing buffers. Use the `OpenCredError`
   hierarchy — it sanitizes by design.
6. **JSON-LD contexts are bundled.** Never fetch remote contexts at runtime
   in production — use the bundled document loader. Remote fetch is a
   supply-chain attack vector.
7. **did:web resolution requires SSRF protection.** When fetching DID
   documents for `did:web` verification, always validate that resolved IPs
   are public (use `resolveDnsForSsrf` from `@opencred/shared`) AND pin the
   connection to the validated addresses (use `fetchWithPinnedIp` from
   `@opencred/shared`) — a plain `fetch(url)` after the DNS check
   re-resolves the hostname and is vulnerable to DNS-rebinding TOCTOU.
   Never "pin" by putting the IP in the URL with a `Host` header (breaks
   TLS certificate validation). HTTPS only, no redirects, 10-second
   timeout.

## Source of Truth

1. **PRD** (`docs/PRD.md`) — what the product is and why.
2. **GitHub Issues** (this repo) — discrete, implementable work units.

If something conflicts, the PRD wins for product questions; the code +
`docs/` win for shipped-behavior questions.

## Working on Issues

1. Read the issue fully before starting: `gh issue view <number>`.
2. Claim it: `gh issue edit <number> --add-assignee @me`. If it already has
   an assignee, pick another.
3. Feature branch from `opencred-dev` (naming above).
4. Stay scoped to the issue; new work discovered → new issue, not scope creep.
5. Write tests for all new functionality.
6. Open a PR referencing the issue (`Closes #<number>`). Note: auto-close
   only fires when the PR lands on the default branch — since PRs target
   `opencred-dev`, close the issue manually after merge and post a
   completion comment (what was implemented, deviations, follow-ups).

### Commits

- [Conventional Commits](https://www.conventionalcommits.org/):
  `feat(package): …`, `fix(package): …`, `test(package): …`, `docs: …`,
  `chore: …`, `refactor(package): …`.
- **DCO sign-off required** on every commit: `git commit -s`.
- Squash-merge feature PRs; delete branches after merge.
- Do NOT hand-edit `CHANGELOG.md` — release-please owns it.

### Multi-Agent / Parallel Work

1. Each agent works in an isolated git worktree — never share a branch.
2. Claim issues before starting; check assignees first.
3. Respect dependency order noted in issue bodies.
4. One PR per issue.
5. Model selection: feature development agents use `model: "opus"`.

## Documentation — MANDATORY on every PR and release

Documentation is part of the change, never an afterthought. Every PR that
changes behavior — an endpoint, a response shape, a config variable, a
contract, a default — MUST **thoroughly** update the documentation that
describes it.

- **Sweep, don't guess.** Grep the whole repo for every doc that references
  what you changed, and update each hit. There is almost always more than
  one doc: e.g. a `/v1/credentials/*` change touches BOTH
  `docs/api-reference.md` AND `docs/docker/api-reference.md`, the deployment
  guides, the bootcamp tutorial + `docs/bootcamp/postman-collection.json`,
  and any affected `docs/concepts/*`.
- **Check on every change:** `docs/api-reference.md`,
  `docs/docker/api-reference.md`, `docs/deployment-guide.md`,
  `docs/docker/deployment.md`, the relevant `docs/concepts/*`,
  `docs/bootcamp/*`, affected package READMEs, and the changelog (via
  conventional commits, not by hand).
- **"Docs updated" in a PR means you ran the sweep** — list the docs you
  touched in the PR description.

## Definition of Done

1. Code implements what the issue describes — no more, no less.
2. Tests exist and pass.
3. No lint/type errors.
4. PR reviewed and merged to `opencred-dev`.
5. Issue closed manually with a completion comment.
6. No regressions — existing tests still pass.
7. Documentation thoroughly updated (repo-wide grep sweep).

## Spike Protocol

Spikes are time-boxed investigations, not implementation work:
- Branch: `spike/<number>-<desc>`. Output: a findings doc at
  `docs/spikes/spike-<number>-<topic>.md`, not production code.
- PR contains the findings doc; prototype code clearly marked non-production.
- Closing comment summarizes the recommendation and links the doc.
