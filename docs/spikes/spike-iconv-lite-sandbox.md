# Spike: `iconv-lite@0.6.3` sandbox EPERM in agent worktrees

**Issue:** [#332](https://github.com/nfh-trust-labs/opencred/issues/332)
**Branch:** `spike/iconv-lite-sandbox`
**Date:** 2026-04-07
**Author:** Team G

---

## TL;DR

`iconv-lite@0.6.3`'s npm tarball ships JetBrains IDE config files (`.idea/codeStyles/Project.xml`, `.idea/iconv-lite.iml`, etc.) that the Claude Code sandbox refuses to write inside agent worktrees. The upstream maintainer fixed this in `0.7.0+` by switching to a `package.json#files` allow-list (PR `pillarjs/iconv-lite#372`). The recommended fix is a 4-line `pnpm.overrides` block in the root `package.json` that pins the dependency to `^0.7.2`. Lockfile regeneration is required and is intentionally **not** part of this spike — it should land as a follow-up PR.

---

## Reproduction

```bash
# 1. Create a fresh worktree (any branch off new-opencred-dev)
git worktree add ~/.claude/worktrees/agent-test new-opencred-dev

# 2. Try to install
cd ~/.claude/worktrees/agent-test
CI=true pnpm install --no-frozen-lockfile

# 3. pnpm fails during package extraction:
#   ENOENT/EPERM: ... node_modules/.pnpm/iconv-lite@0.6.3/
#                     node_modules/iconv-lite/.idea/codeStyles/Project.xml
```

You can also confirm the offending content directly without installing:

```bash
curl -sL https://registry.npmjs.org/iconv-lite/-/iconv-lite-0.6.3.tgz \
  -o /tmp/iconv-lite-0.6.3.tgz
tar -tzf /tmp/iconv-lite-0.6.3.tgz | grep -E '\.idea|codeStyles'
```

Output:

```
package/.idea/iconv-lite.iml
package/.idea/codeStyles/codeStyleConfig.xml
package/.idea/modules.xml
package/.idea/inspectionProfiles/Project_Default.xml
package/.idea/codeStyles/Project.xml
package/.idea/vcs.xml
```

---

## Root cause

### What's actually happening

1. The npm tarball for `iconv-lite@0.6.3` (published 2021-05-23) was packaged using a `.npmignore` allow-list that did **not** exclude the maintainer's local JetBrains IDE config directory. As a result, six `.idea/*` files leaked into the published tarball.
2. When pnpm extracts the package into `<worktree>/node_modules/.pnpm/iconv-lite@0.6.3/node_modules/iconv-lite/`, it faithfully recreates every file in the tarball — including `.idea/codeStyles/Project.xml`.
3. Inside an agent worktree under `~/opencred/.claude/worktrees/agent-XXX/`, the Claude Code sandbox blocks writes to any path containing `.idea/`. (IDE config directories are treated as potentially sensitive — they can contain VCS credentials, run configurations with secrets, etc.) The write fails with `EPERM` and pnpm aborts the install.
4. Because pnpm fails partway through extracting the iconv-lite package, the entire worktree's `node_modules` is left in an unusable state — no tests can run.

### Why this only bites agent worktrees

- The user's main worktree (`/Users/anusreejayakrishnan/opencred`) was bootstrapped before the sandbox restrictions tightened, so its `node_modules` already contains the leaked `.idea/` files. Subsequent `pnpm install` runs in that worktree are no-ops for that package and never trigger a write.
- New agent worktrees start with an empty `node_modules` and must perform a fresh extract. They're the only ones that hit the write path.

### Verified facts

| Question | Answer | Evidence |
|---|---|---|
| Does the 0.6.3 tarball contain `.idea/codeStyles/`? | Yes. | `tar -tzf` of the registry tarball lists `package/.idea/codeStyles/Project.xml` and `codeStyleConfig.xml` |
| Postinstall script involved? | No. | `iconv-lite@0.6.3/package.json` has only `coverage` and `test` scripts, no `postinstall`/`install`/`prepare`. The `.idea/` files are extracted verbatim from the tarball. |
| Other packages with the same problem? | Yes — `base45-web@1.0.2` ships `.idea/` (no `codeStyles/` subdir, so it hasn't triggered EPERM yet). | `find node_modules/.pnpm -maxdepth 4 -name .idea` |
| Newer iconv-lite versions clean? | Yes, `0.7.0`, `0.7.1`, `0.7.2` are all clean. | `tar -tzf` of each tarball returns no `.idea` paths. `0.7.2/package.json` adds `"files": ["lib/", "encodings/", "types/"]` |
| Upstream issue/fix? | Yes — `pillarjs/iconv-lite#372` (merged): "use files field in package.json instead of .npmignore". | https://github.com/pillarjs/iconv-lite/pull/372 |
| Pinned by us directly? | No — transitive only. | `pnpm-lock.yaml` shows three importers: `dmg-builder@25.1.8` (`^0.6.2`), `encoding@0.1.13` (optional), `whatwg-encoding@3.1.1` (optional) |
| pnpm version | `10.30.1` (declared in `package.json` `packageManager`) | — |

---

## Impact

**Three agents independently hit this in the final-sprint window:**
- Team A
- Team B
- Team R2

**Workaround used:** point vitest at the main worktree's pre-installed `node_modules` instead of the agent worktree's. Concretely, agents `cd <main-worktree>/<package>` and run `../../node_modules/.bin/vitest` from there.

**Why the workaround is fragile:**
1. **It defeats worktree isolation.** If two agents simultaneously run tests against the main worktree, vitest's coverage/snapshot artefacts can collide.
2. **It hides build issues that depend on the fresh-install state.** A package that builds fine against a stale `node_modules` may break against a clean install — and the agent will never see it locally.
3. **Future agents are not warned.** Unless every agent has read this spike, the next one to spawn a worktree will rediscover the trap, debug for 10–30 minutes, and rediscover the workaround — reliably wasting compounding hours.
4. **CI is unaffected**, so the bug is invisible until an agent encounters it. CI runs use a Linux runner without the macOS-specific Claude Code sandbox restrictions.

**Evidence of the impact in this very repo:** out of 11 worktrees under `~/opencred/.claude/worktrees/`, six have `iconv-lite/.idea/codeStyles/` extracted (created before sandbox tightening), the rest have either an empty `node_modules` or no `node_modules` at all — meaning their `pnpm install` never completed.

---

## Fix options

### Option A — `pnpm.overrides` to force `iconv-lite@^0.7.2`

```jsonc
// package.json
"pnpm": {
  "onlyBuiltDependencies": ["electron", "esbuild", "pkcs11js", "protobufjs"],
  "overrides": {
    "iconv-lite@0.6.3": "^0.7.2"
  }
}
```

**Pros**
- Three-line change to a single existing block.
- Solves the problem at the source (the package contents).
- `0.7.0` only adds bug fixes, not breaking changes (Changelog: surrogate-pair encoding fix, false-positive `encodingExists` fix). The encoder/decoder API is identical.
- Removes the leaked `.idea/` payload from every consumer transitive path in one shot.
- pnpm `10.x` supports the version-qualified override syntax (`iconv-lite@0.6.3` matches only the bad version, not the package globally — a defensive choice).

**Cons**
- Lockfile regeneration is required (`pnpm install --no-frozen-lockfile`). That's a non-trivial diff and should land as a separate, deliberate follow-up PR.
- `dmg-builder@25.1.8` declares `iconv-lite: ^0.6.2`. The override forces it outside that range; we are taking on a small forward-compat risk that dmg-builder picks up an incompatible API at some point. The risk is theoretical: dmg-builder uses `iconv.decode(buf, 'utf-8')` (standard, stable API) and the encoder/decoder surface has not changed in 0.7.x.

**Effort:** 5 minutes for the package.json change + 5 minutes for the lockfile regen PR.

---

### Option B — `.pnpmfile.cjs` hook to strip `.idea/` during extract

```js
// .pnpmfile.cjs
const path = require('path');

function readPackage(pkg, context) {
  // pnpm hooks don't expose tarball contents directly.
  // This hook would only work if we processed the package post-extract.
  return pkg;
}

module.exports = { hooks: { readPackage } };
```

**Pros**
- Could be made generic — strip `.idea/`, `.vscode/`, etc. across all packages.

**Cons**
- pnpm's `readPackage` hook only mutates `package.json`, not file contents. There is no clean hook to filter files during extract.
- Would need a `postinstall` script that recursively walks `node_modules/.pnpm/*/node_modules/*/.idea/` and deletes them, which (a) doesn't help because the EPERM is during extraction, before any postinstall runs, and (b) adds an opaque hook to the install pipeline.
- Doesn't fix the root cause — every new package version with leaked IDE config still re-introduces the problem.

**Effort:** 1–2 hours for a proof of concept that almost certainly won't work.

---

### Option C — Upgrade `iconv-lite` to a clean newer version

Same as Option A — they're identical. Including separately for completeness so the option matrix is honest.

**Effort:** identical.

---

### Option D — Add `.idea/` to the Claude Code sandbox allow-list for this project

Add to `.claude/settings.local.json`:

```jsonc
{
  "permissions": {
    "filesystem": {
      "write": {
        "allow": ["**/.idea/**"]
      }
    }
  }
}
```

**Pros**
- Fixes the symptom for **every** package that leaks `.idea/`, not just iconv-lite. Solves base45-web (latent) and any future offender.
- Zero impact on dependencies, lockfile, or runtime behavior.
- Per-project — doesn't affect other repos.

**Cons**
- Loosens the sandbox in a security-relevant way. `.idea/workspace.xml` can contain plaintext run-configuration environment variables, including secrets. `.idea/dataSources.xml` can contain database connection strings. A malicious package could exploit a relaxed allow-list to drop a file that the IDE later picks up.
- Doesn't actually fix the problem — leaked IDE config continues to bloat `node_modules` (`iconv-lite` ships ~3KB of useless XML to every install).
- Two layers (per-user `~/.claude/settings.json` and project `.claude/settings.local.json`) means it's easy for a future tightening of the user-level config to reintroduce the issue.
- Doesn't apply to CI runners — Linux CI ignores the macOS sandbox config. It's a workaround for a single environment.

**Effort:** 5 minutes — but the security tradeoff makes it a poor primary fix. Acceptable as a **secondary** safety net layered on top of Option A.

---

### Option E — `patch-package` to delete `.idea/` from the installed package

```bash
pnpm add -D patch-package
# Manually delete .idea/ from node_modules/.pnpm/iconv-lite@0.6.3/.../iconv-lite/
pnpm exec patch-package iconv-lite
```

**Pros**
- Surgical — only touches iconv-lite.
- No version bump.

**Cons**
- `patch-package` patches generated by `patch-package` only edit existing files; they cannot represent file deletions cleanly (you'd patch `package.json` to add a `files` field, but the install still extracts everything before the patch runs — same EPERM).
- Adds a dev-dep and a maintenance burden for every future iconv-lite version bump.
- Doesn't generalize — each leaky package needs its own patch.

**Effort:** 30 minutes, with no certainty it actually fixes the EPERM (the issue is in extraction, before patches run).

---

## Recommended fix

**Option A** — `pnpm.overrides` pinning `iconv-lite@0.6.3` to `^0.7.2`.

Rationale:
1. It removes the bad bytes from disk entirely. Every other option leaves the leaked files in the tarball and just papers over the consequences.
2. It's a three-line change with minimal review surface.
3. The semver risk from forcing `dmg-builder` outside its declared range is negligible — the iconv-lite encoder/decoder API has not changed in 0.7.x and dmg-builder only uses the stable `decode()` surface.
4. It is the same fix the upstream maintainer recommended (by publishing `0.7.x` as the supported line).

**Layered with Option D as a defensive safety net** — once the fix is in, also add `.idea/**` to the project sandbox allow-list so a future leaky package doesn't reintroduce the same trap. This should be a separate, security-reviewed PR (not part of this spike).

### Out of scope

- **Lockfile regeneration**: `pnpm install --no-frozen-lockfile` will produce a large diff (replacing every `iconv-lite@0.6.3` reference with the new version, plus any transitive changes). Per spike protocol, this is a deliberate follow-up — open a separate PR titled `chore(deps): regenerate lockfile after iconv-lite override` so the diff can be reviewed in isolation.
- **`base45-web@1.0.2`**: also leaks `.idea/`. It hasn't bitten anyone because its `.idea/` doesn't contain `codeStyles/`. Worth tracking as a separate small issue — recommended fix is the same: `pnpm.overrides` once a clean upstream version exists, or remove the dep if we can.

---

## Implementation (this spike)

This spike includes the trivial fix to `package.json`. The lockfile is intentionally **not** regenerated.

Diff:

```diff
--- a/package.json
+++ b/package.json
@@ -21,7 +21,10 @@
   },
   "packageManager": "pnpm@10.30.1",
   "pnpm": {
-    "onlyBuiltDependencies": ["electron", "esbuild", "pkcs11js", "protobufjs"]
+    "onlyBuiltDependencies": ["electron", "esbuild", "pkcs11js", "protobufjs"],
+    "overrides": {
+      "iconv-lite@0.6.3": "^0.7.2"
+    }
   },
   "devDependencies": {
     "@types/node": "^20.0.0",
```

### Follow-up PR checklist

- [ ] Merge this spike PR (adds the override but does not regenerate the lockfile).
- [ ] Open a new PR `chore(deps): regenerate lockfile after iconv-lite override`:
  - Run `pnpm install --no-frozen-lockfile` from the repo root.
  - Verify only `iconv-lite` and its direct/transitive references change.
  - Run `pnpm -r build && pnpm -r test` to confirm dmg-builder still works (desktop build path).
  - Confirm `apps/desktop` packaging (electron-builder) still produces a valid `.dmg` on macOS.
- [ ] Open a follow-up issue `Add .idea/** to project sandbox allow-list (Option D safety net)` and security-review the change before merging.
- [ ] Open a follow-up issue `base45-web@1.0.2 ships .idea/ — track upstream fix or replace dep`.
