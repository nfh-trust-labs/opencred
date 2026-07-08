#!/usr/bin/env node
"use strict";

/**
 * rebuild-native.cjs — Rebuild known native addons for Electron's ABI.
 *
 * WHY THIS EXISTS
 * ---------------
 * The obvious one-liner is:
 *
 *     electron-rebuild -f -m ../../packages/signing/native -o pkcs11js
 *
 * `@electron/rebuild` always walks the entire dependency tree (calling
 * fs.realpath on every symlink it encounters) BEFORE filtering by `-o`.
 * See module-walker.ts in @electron/rebuild — `searchForNodeModules`
 * walks UP from the `-m` directory to the filesystem root, then enumerates
 * every `node_modules/*` along the way. In a pnpm monorepo on Windows /
 * NTFS, that means stat-ing thousands of `.pnpm/<pkg>/node_modules/<pkg>`
 * symlinks. The "Searching dependency tree" stage hangs for 20+ minutes
 * on `windows-latest` GitHub Actions runners (issue #501). Mac and Linux
 * complete the same scan in under five minutes because POSIX symlink
 * resolution is cheap.
 *
 * Native compilation itself is fine on Windows — node-gyp produces both
 * `pkcs11.node` and `windows-cng.node` in under 90 s each. The pathology
 * is purely in the dependency-tree walk.
 *
 * THE FIX
 * -------
 * We already know exactly which modules need an Electron-ABI rebuild:
 *
 *   1. `pkcs11js`                   (in apps/desktop/node_modules)
 *   2. `opencred-native-addons`     (packages/signing/native)
 *
 * So we skip the walk entirely. For each target we invoke `node-gyp
 * rebuild` directly with the Electron-specific flags that `@electron/rebuild`
 * would have constructed internally:
 *
 *   --target=<electronVersion>      Electron version (e.g. 33.4.11)
 *   --runtime=electron              Tells node-gyp to use Electron headers
 *   --dist-url=https://electronjs.org/headers
 *   --arch=<arch>                   Target architecture
 *   --build-from-source             Don't try prebuilt download
 *
 * We resolve each module to its REAL on-disk path before invoking node-gyp,
 * so node-gyp's own working dir is not a pnpm symlink (avoids confusing
 * build output paths).
 *
 * RESULT
 * ------
 * On Mac/Linux this is fractionally faster than the old command (no tree
 * walk). On Windows it should drop from 20+ min to under 3 min.
 *
 * If we ever add a new native module that needs Electron-ABI rebuilding,
 * add it to TARGETS below.
 */

const childProcess = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const repoRoot = path.resolve(__dirname, "..", "..", "..");
const desktopDir = path.resolve(__dirname, "..");

const TARGETS = [
  {
    // Resolve via the symlink under apps/desktop/node_modules. Falling
    // back to the realpath under the pnpm virtual store keeps node-gyp's
    // working dir off the symlink so its build/ output lands inside the
    // real package and is picked up by node-gyp-build at runtime.
    name: "pkcs11js",
    resolve: () => realDirOrNull(path.join(desktopDir, "node_modules", "pkcs11js")),
  },
  {
    name: "opencred-native-addons",
    resolve: () => realDirOrNull(path.join(repoRoot, "packages", "signing", "native")),
  },
];

function realDirOrNull(p) {
  try {
    const real = fs.realpathSync(p);
    if (fs.statSync(real).isDirectory()) return real;
  } catch (_) {
    /* fall through */
  }
  return null;
}

function readElectronVersion() {
  // Resolve electron from apps/desktop. In a pnpm monorepo this lands on
  // the symlink under apps/desktop/node_modules/electron — that's fine,
  // we only need to read its package.json.
  const electronPkgPath = require.resolve("electron/package.json", {
    paths: [desktopDir],
  });
  const pkg = JSON.parse(fs.readFileSync(electronPkgPath, "utf-8"));
  if (!pkg.version) {
    throw new Error(`Could not determine electron version from ${electronPkgPath}`);
  }
  return pkg.version;
}

function resolveNodeGypBin() {
  // Prefer UPSTREAM node-gyp over @electron/node-gyp.
  //
  // @electron/node-gyp v10.2.0-electron.1 (the version bundled with
  // @electron/rebuild 4.x) ships an older child-process orchestration that
  // hits "Completion callback never invoked!" on modern Windows runners
  // (observed against VS 17.14 / windows-2022 / Python 3.11 — the failure
  // is in the fork's runtime, not in Python or VS detection).
  //
  // Upstream node-gyp v11+ works correctly on the same environment: pnpm's
  // bundled node-gyp builds pkcs11js's native module via its `install`
  // lifecycle hook in <90s on Windows. We invoke that same node-gyp with
  // the Electron-specific flags (--target, --runtime=electron, --dist-url)
  // it supports natively — no @electron-specific patching is needed for a
  // standard C++ native addon rebuild.
  //
  // `@electron/node-gyp` is kept as a fallback in case a future Electron
  // version ships a header file that upstream node-gyp doesn't handle.
  const searchPaths = [__dirname, desktopDir, repoRoot];

  // First try: upstream node-gyp. pkcs11js declares it as a dep, so it's
  // resolvable from apps/desktop's node_modules.
  for (const from of searchPaths) {
    try {
      return require.resolve("node-gyp/bin/node-gyp.js", { paths: [from] });
    } catch (_) {
      /* try next */
    }
  }

  // Fallback: @electron/node-gyp via @electron/rebuild's sub-store.
  for (const from of searchPaths) {
    try {
      const rebuildPkg = require.resolve("@electron/rebuild/package.json", {
        paths: [from],
      });
      const rebuildDir = path.dirname(rebuildPkg);
      return require.resolve("@electron/node-gyp/bin/node-gyp.js", {
        paths: [rebuildDir],
      });
    } catch (_) {
      /* try next */
    }
  }

  throw new Error(
    "Could not locate node-gyp. Expected either upstream `node-gyp` (a transitive " +
      "dep of pkcs11js) or @electron/node-gyp (via @electron/rebuild) to be installed."
  );
}

function resolvePython() {
  // Force node-gyp onto the Python pinned by actions/setup-python in CI.
  //
  // GitHub-hosted runner images include MULTIPLE Python versions in
  // hostedtoolcache. PATH ordering can put a too-new one (e.g. 3.14) ahead
  // of the one setup-python selected (3.11). @electron/node-gyp v10.x ships
  // the 2014-era gyp_main.py which silently fails ("Completion callback
  // never invoked") on Python 3.14 because of removed deprecated APIs.
  // Pinning via `--python` and `PYTHON` env makes the discovery deterministic.
  //
  // actions/setup-python@v5 exports `pythonLocation` env var on Windows
  // pointing at the install root. The interpreter is `<root>\python.exe`.
  // On POSIX it would be `<root>/bin/python`, but this codepath only matters
  // on Windows runners — desktop release validates Mac/Linux too but those
  // already pick the right Python from PATH.
  const root = process.env.pythonLocation;
  if (!root) return null;
  const exe = process.platform === "win32" ? "python.exe" : path.join("bin", "python");
  const full = path.join(root, exe);
  try {
    if (fs.statSync(full).isFile()) return full;
  } catch (_) {
    /* fall through */
  }
  return null;
}

function runNodeGyp({ nodeGypBin, cwd, electronVersion, arch }) {
  const pythonPath = resolvePython();
  const args = [
    nodeGypBin,
    "rebuild",
    `--target=${electronVersion}`,
    "--runtime=electron",
    "--dist-url=https://electronjs.org/headers",
    `--arch=${arch}`,
    "--build-from-source",
  ];
  if (pythonPath) {
    args.push(`--python=${pythonPath}`);
  }

  console.log(`[rebuild-native]   $ node ${args.join(" ")}`);
  const result = childProcess.spawnSync(process.execPath, args, {
    cwd,
    stdio: "inherit",
    env: {
      ...process.env,
      // Tell any nested invocations (gyp scripts that read npm_config_*)
      // about the Electron target too. Mirrors what @electron/rebuild does.
      npm_config_target: electronVersion,
      npm_config_runtime: "electron",
      npm_config_disturl: "https://electronjs.org/headers",
      npm_config_arch: arch,
      npm_config_build_from_source: "true",
      // Belt-and-suspenders: node-gyp also reads PYTHON env var when --python
      // isn't supplied. We set both so nested spawns (e.g. gyp invoking its
      // own python child) inherit the correct interpreter.
      ...(pythonPath ? { PYTHON: pythonPath } : {}),
    },
  });

  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`node-gyp rebuild exited with code ${result.status} (cwd=${cwd})`);
  }
}

function parseArchArg(argv) {
  for (const a of argv) {
    const m = /^--arch=(\w+)$/.exec(a);
    if (m) return m[1];
  }
  return null;
}

function main() {
  const electronVersion = readElectronVersion();
  // Target arch priority: explicit --arch=… flag (used by the electron-builder
  // beforePack hook to compile per TARGET arch — #641/#642), then
  // npm_config_arch, then the host arch. Defaulting to process.arch is only
  // safe when the package target matches the host.
  const arch = parseArchArg(process.argv.slice(2)) || process.env.npm_config_arch || process.arch;
  const nodeGypBin = resolveNodeGypBin();

  console.log(
    `[rebuild-native] Electron ${electronVersion} (${process.platform}/${arch})`
  );
  console.log(`[rebuild-native] node-gyp: ${nodeGypBin}`);

  const startedAt = Date.now();
  for (const target of TARGETS) {
    const cwd = target.resolve();
    if (!cwd) {
      // opencred-native-addons resolves to a real path always; pkcs11js
      // may be absent in a renderer-only workspace. Skip with a warning
      // rather than fail hard.
      console.warn(
        `[rebuild-native] WARN: ${target.name} not found on disk; skipping.`
      );
      continue;
    }
    console.log(`[rebuild-native] Rebuilding ${target.name} (${cwd})`);
    runNodeGyp({ nodeGypBin, cwd, electronVersion, arch });
  }

  const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
  console.log(`[rebuild-native] Done in ${elapsed}s on ${os.platform()}.`);
}

try {
  main();
} catch (err) {
  console.error(`[rebuild-native] FAILED: ${err.message}`);
  process.exit(1);
}
