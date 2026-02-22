# OpenCred — Claude Code Instructions

## Security Invariants — MANDATORY

These rules are non-negotiable. Every agent, every PR, every line of code must respect them.

### Key Management Model

OpenCred handles **two categories** of private keys differently:

- **Issuer private keys**: OpenCred NEVER receives, handles, or stores issuer private keys. In Local Signing the key stays on the issuer's machine. In Interface Signing the key never leaves the issuer's control (browser SubtleCrypto / HSM / cloud KMS). No code path should accept, transmit, or hold an issuer's private key.
- **OpenCred's own signing keys**: Used for Delegated Signing. These are OpenCred-managed, long-lived keys (potentially HSM-backed). They ARE persisted and properly managed. Key rotation, access control, and audit logging apply.

### Rules

1. **Never touch issuer private keys.** No API endpoint, no function, no code path should accept an issuer's private key as input. Interface Signing sends signing payloads/digests TO the issuer — never the reverse.
2. **Never log key material.** No private keys, no signing buffers in `pino` logs, `console.log`, error messages, or stack traces. Log the key *ID* or *fingerprint*, never the key itself.
3. **Session data is ephemeral.** Credential payloads, built VCs, and packaged output are purged within TTL (default 4 hours). Delegation certificates are the sole exception — they persist as long as the delegation is active.
4. **CSPRNG only.** All key generation must use `crypto.randomBytes` or equivalent CSPRNG. Never use `Math.random()` for anything security-related.
5. **No secrets in error responses.** API error responses must never leak key material, internal paths, or signing buffers. Use the `OpenCredError` hierarchy — it sanitizes by design.
6. **Delegation certificates are trust boundaries.** Always validate `scope`, `validFrom`, `validUntil`, and the authorised key ID before accepting a delegation cert. Never skip validation even in dev/test.
7. **JSON-LD contexts are bundled.** Never fetch remote contexts at runtime in production — use the bundled document loader. Remote fetch is a supply-chain attack vector.

## Project Tracking

All implementation issues are on GitHub Issues at https://github.com/nfh-trust-labs/opencred/issues (43 issues, 12 labels).

| Label | Scope | Issues |
|---|---|---|
| `infra` | Monorepo scaffolding, CI | #4 |
| `spike` | Risk spikes / technical PoCs | #5–#8 |
| `phase-0` | Core Foundation packages | #9–#15 |
| `phase-1` | Type A + Interface Signing + Verification | #16–#22 |
| `phase-2` | Delegated Signing + Type D | #23–#27 |
| `phase-3` | Type B (SSL) + Type C (CA API) | #28–#30 |
| `phase-4` | Bulk Issuance | #31–#32 |
| `phase-5` | Web UI Polish + QR/PDF | #33–#35 |
| `phase-6a` | Desktop — Software Keys + Offline | #36–#38 |
| `phase-6b` | Desktop — PKCS#11 Hardware Tokens | #39 |
| `phase-6c` | Desktop — OS Cert Store + Distribution | #40–#41 |
| `phase-7` | Containerization & Deployment | #42–#46 |

Full implementation plan: `implementation-plan.md`
PRD (source of truth): `OpenCred_PRD.md`

## Project Management Protocol

### Source of Truth Hierarchy

1. **PRD** (`OpenCred_PRD.md`) — the ultimate source of truth for requirements
2. **Implementation Plan** (`implementation-plan.md`) — derived from the PRD; defines phases, architecture, and technical approach
3. **GitHub Issues** — derived from the implementation plan; each issue is a discrete, implementable work unit

Changes flow downward: PRD → implementation plan → issues. If something conflicts, the higher-level document wins.

### Working on Issues

Follow this protocol for every issue you work on:

1. **Check open issues**: `gh issue list --state open --label <phase-label>`
2. **Read the issue fully** before starting: `gh issue view <number>`
3. **Claim the issue**: `gh issue edit <number> --add-assignee @me`
4. **Create a feature branch** from `anusree-dev`:
   - Branch naming: `feat/<number>-<short-description>` (e.g., `feat/9-crypto-core`)
   - For bug fixes: `fix/<number>-<short-description>`
5. **Implement the issue** — stay scoped to what the issue describes; do not scope-creep
6. **Write tests** for all new functionality
7. **Open a PR** referencing the issue:
   - PR title: concise summary of what was implemented
   - PR body must include `Closes #<number>` to auto-close the issue on merge
   - PR body should include a summary of changes and a test plan
8. **After the PR is merged**, the issue auto-closes. Then **update the closed issue** with a completion comment:
   - What was implemented (briefly)
   - Any deviations from the original issue description
   - Any follow-up work identified (create new issues for these)

   Example closing comment:
   ```
   ## Completed

   Implemented X, Y, Z as described.

   **Deviations:** None / [describe any deviation and why].
   **Follow-ups:** Created #45 for [describe].
   ```

### Multi-Agent / Parallel Work

When working as a team of agents on multiple issues simultaneously:

1. **Each agent works in an isolated git worktree** — never work on the same branch as another agent
2. **Claim before starting** — always `gh issue edit <number> --add-assignee` to prevent duplicate work
3. **Check assignees before claiming** — if an issue already has an assignee, pick a different one
4. **Respect dependency order** — issues within a phase may depend on each other. Check the issue body for dependency notes. Work on unblocked issues first (lower issue numbers generally come first)
5. **One PR per issue** — do not bundle multiple issues into a single PR
6. **Communicate via SendMessage** when coordinating within a team session
7. **Model selection**: All feature development agents must use `model: "opus"`. Do not use Sonnet or Haiku for implementation work.

### When the PRD Changes

If requirements change in the PRD:

1. **Update `OpenCred_PRD.md`** with the new requirements
2. **Update `implementation-plan.md`** to reflect the changes — add/remove/modify phases or tasks as needed
3. **Update GitHub Issues** to match:
   - Modify existing issue descriptions if scope changed
   - Create new issues if new work was added
   - Close issues (with a comment explaining why) if work was removed
   - Update labels/milestones if phasing changed
4. **Add a comment on affected issues** noting what changed and linking to the PRD change

### Issue Hygiene

- **Labels**: Every issue must have a phase label (`phase-0`, `phase-1`, etc.) and optionally a type label (`infra`, `spike`, etc.)
- **Blocked issues**: If an issue is blocked, add a comment explaining what it's blocked on and reference the blocking issue number
- **Scope creep**: If you discover additional work while implementing an issue, create a new issue for it — do not expand the current issue's scope
- **Stale issues**: If an issue is no longer relevant, close it with a comment explaining why rather than deleting it

### Commit & Branch Conventions

- **Commit messages**: Use [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat(package): description` — new functionality
  - `fix(package): description` — bug fix
  - `test(package): description` — adding/updating tests
  - `docs: description` — documentation only
  - `chore: description` — tooling, CI, dependencies
  - `refactor(package): description` — code change that neither fixes a bug nor adds a feature
- **Branch `main`**: Protected. NEVER push, merge, or commit to `main` directly. Do not target PRs to `main`.
- **Branch `anusree-dev`**: This is the working integration branch — treat it as "main" for all practical purposes. All feature branches are created from `anusree-dev` and all PRs target `anusree-dev`.
- **All changes go through PRs** — no direct pushes to `anusree-dev`, even for small fixes
- **PR merge strategy**: Squash merge to keep `anusree-dev` history clean. The squashed commit message should follow conventional commits format.
- **Delete branches after merge** — feature branches are ephemeral

### Definition of Done

An issue is only considered complete when ALL of the following are true:

1. **Code implements what the issue describes** — no more, no less
2. **Tests exist and pass** — unit tests for logic, integration tests for cross-package interactions
3. **No lint/type errors** — code passes all static analysis checks
4. **PR is reviewed and approved** (or self-reviewed if working solo)
5. **PR is merged to `anusree-dev`**
6. **Closing comment is posted** on the issue (see Working on Issues, step 8)
7. **No regressions** — existing tests still pass

If any of these are not met, the issue stays open.

### Spike Protocol

Spikes (#5–#8) are time-boxed investigations, not implementation work. They follow a different protocol:

1. **Goal**: Answer a specific technical question or validate a feasibility assumption
2. **Output**: A spike produces a **written findings document**, not production code
   - Create a file: `docs/spikes/spike-<number>-<topic>.md`
   - Document: what was tested, what was learned, recommendation, and any prototype code (in the doc or a throwaway branch)
3. **Branch naming**: `spike/<number>-<short-description>`
4. **PR**: Open a PR with just the findings doc. Prototype code can be included but should be clearly marked as non-production.
5. **Closing the issue**: The completion comment should summarize the recommendation and link to the findings doc
6. **Outcome flows back up**: If a spike changes the technical approach, update the implementation plan and any affected downstream issues
