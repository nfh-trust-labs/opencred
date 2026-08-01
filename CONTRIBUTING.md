# Contributing to OpenCred

Thanks for your interest in contributing! OpenCred is MIT-licensed and
welcomes issues, docs improvements, and code contributions.

## Ground rules

- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Security vulnerabilities go through **private disclosure**, never public
  issues — see [SECURITY.md](SECURITY.md).
- Every contribution must respect the project's
  [security invariants](docs/security/invariants.md). The non-negotiable one:
  **no code path may ever receive, transmit, store, or log an issuer's
  private key.** All signing is local to the issuer's machine or container.

## Branch model

| Branch | Purpose | Target your PR here? |
|---|---|---|
| `main` | Stable. Tracks the latest release; releases are tagged from it. | **No** (a CI check will redirect you) |
| `opencred-dev` | Development. All feature/fix work integrates here. | **Yes** |

Flow: feature branch → PR into `opencred-dev` (squash-merged) → periodically
`opencred-dev` is promoted to `main` via a merge-commit PR, which triggers
release automation (release-please) and a tagged release.

Branch naming: `feat/<issue>-<short-description>`, `fix/<issue>-<short-description>`,
or `docs/<short-description>`.

## Commits

- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat(vc-core): …`, `fix(desktop): …`, `docs: …`, `chore: …`,
  `refactor(server): …`, `test(schema-engine): …`.
  PRs are squash-merged, and the squash commit message becomes a changelog
  entry — write it for the changelog reader.
- **Sign off every commit** (Developer Certificate of Origin): commit with
  `git commit -s`, which adds a `Signed-off-by: Your Name <you@example.com>`
  line. By signing off you certify the [DCO](https://developercertificate.org/)
  — that you have the right to submit the work under the MIT license.

## Development setup

```sh
git clone https://github.com/nfh-trust-labs/opencred-releases.git
cd opencred-releases
CI=true pnpm install
pnpm build          # must exit 0 — schema-engine aborts on network failure
pnpm test
```

Requires Node.js 20+ and pnpm 9+. See
[docs/development/README.md](docs/development/README.md) for the full
developer guide (package layout, running the desktop app, e2e tests).

## Pull requests

1. Open or find an issue describing the change; discuss approach first for
   anything non-trivial.
2. Branch from `opencred-dev`, keep the PR scoped to one concern.
3. Add tests for new functionality (vitest, colocated in `src/__tests__/`).
4. Update **all** documentation that references what you changed — API
   references, deployment guides, concepts docs, package READMEs. A change is
   complete only when a repo-wide grep finds no stale references.
5. Ensure `pnpm lint`, `pnpm typecheck`, and `pnpm test` pass.
6. Fill in the PR template, including the test plan.

## Backward compatibility — hard rule

Every release must be backward compatible. Treat any change to a public
contract as breaking: `/v1/*` request/response shapes, env vars and their
defaults, VC/JWT/PDF output formats, on-disk DID/key formats, desktop
settings, Docker env/volumes. Prefer additive evolution; credentials issued
by version N must verify under N+1. Flag anything that might break these in
your PR description.

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE), as certified by your DCO sign-off.
