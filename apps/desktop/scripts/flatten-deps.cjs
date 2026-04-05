/**
 * flatten-deps.cjs — Resolve pnpm workspace symlinks before electron-builder.
 *
 * pnpm uses symlinks for workspace dependencies and the pnpm virtual store.
 * electron-builder resolves these symlinks and fails because target paths
 * are outside apps/desktop/.
 *
 * This script does two things:
 * 1. Replaces all symlinks under node_modules/ with real copies.
 * 2. Resolves missing transitive dependencies from the pnpm virtual store.
 *    pnpm doesn't hoist transitive deps into the app's node_modules/ — they
 *    live as siblings in .pnpm/<pkg>/node_modules/. After flattening, those
 *    deps are unreachable. This pass finds and copies them.
 *
 * Runs as part of build:dist, after tsc + vite build, before electron-builder.
 */

const fs = require("fs");
const path = require("path");

const nodeModulesDir = path.resolve(__dirname, "..", "node_modules");
// pnpm workspaces keep the virtual store at the repo root, not per-package
const rootNodeModulesDir = path.resolve(__dirname, "..", "..", "..", "node_modules");
const pnpmStoreDir = path.join(rootNodeModulesDir, ".pnpm");
let flattened = 0;
let hoisted = 0;

// -------------------------------------------------------------------------
// Pass 1: Flatten all symlinks in node_modules/
// -------------------------------------------------------------------------

function flattenSymlinks(dir, depth) {
  if (depth > 10) return; // safety limit
  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch {
    return;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    let stat;
    try {
      stat = fs.lstatSync(fullPath);
    } catch {
      continue;
    }

    if (stat.isSymbolicLink()) {
      let target;
      try {
        target = fs.realpathSync(fullPath);
      } catch {
        continue; // dangling symlink
      }

      const targetStat = fs.statSync(target);
      fs.unlinkSync(fullPath);

      if (targetStat.isDirectory()) {
        fs.cpSync(target, fullPath, { recursive: true });
        flattened++;
        // Recurse into the newly copied directory for nested symlinks
        flattenSymlinks(fullPath, depth + 1);
      } else {
        fs.copyFileSync(target, fullPath);
        flattened++;
      }
    } else if (stat.isDirectory()) {
      flattenSymlinks(fullPath, depth + 1);
    }
  }
}

// -------------------------------------------------------------------------
// Pass 2: Hoist missing transitive deps from .pnpm/ store
// -------------------------------------------------------------------------

/**
 * Find a package inside the .pnpm virtual store. pnpm stores packages at
 * .pnpm/<name>@<version>/node_modules/<name>. For scoped packages the
 * directory key uses "+" instead of "/".
 */
function findInPnpmStore(pkgName) {
  if (!fs.existsSync(pnpmStoreDir)) return null;

  // The package could be a sibling in any .pnpm entry's node_modules/.
  // Scan store entries that match the package name prefix.
  const storeKey = pkgName.replace("/", "+");
  let entries;
  try {
    entries = fs.readdirSync(pnpmStoreDir);
  } catch {
    return null;
  }

  for (const entry of entries) {
    if (!entry.startsWith(storeKey + "@")) continue;
    const candidate = path.join(pnpmStoreDir, entry, "node_modules", pkgName);
    if (fs.existsSync(candidate)) return candidate;
  }

  // Also check as a transitive dep inside other packages' node_modules
  for (const entry of entries) {
    const candidate = path.join(pnpmStoreDir, entry, "node_modules", pkgName);
    if (fs.existsSync(candidate)) return candidate;
  }

  return null;
}

/**
 * Read production dependencies from a package's package.json.
 */
function getProductionDeps(pkgDir) {
  const pkgJsonPath = path.join(pkgDir, "package.json");
  if (!fs.existsSync(pkgJsonPath)) return [];
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
    return Object.keys(pkg.dependencies || {});
  } catch {
    return [];
  }
}

/**
 * Resolve a dependency name to a directory within node_modules, handling
 * both regular and scoped packages.
 */
function resolveInNodeModules(depName) {
  return path.join(nodeModulesDir, depName);
}

/**
 * Iteratively hoist all missing transitive deps. Keeps going until no
 * new deps are found (handles chains like conf -> dot-prop -> type-fest).
 */
function hoistMissingDeps() {
  let foundNew = true;
  const visited = new Set();

  while (foundNew) {
    foundNew = false;

    // Collect all packages currently in node_modules (top-level)
    let entries;
    try {
      entries = fs.readdirSync(nodeModulesDir);
    } catch {
      return;
    }

    const packages = [];
    for (const entry of entries) {
      if (entry === ".pnpm" || entry === ".package-lock.json") continue;
      if (entry.startsWith("@")) {
        // Scoped package — read subdirectory
        const scopeDir = path.join(nodeModulesDir, entry);
        try {
          for (const sub of fs.readdirSync(scopeDir)) {
            packages.push(entry + "/" + sub);
          }
        } catch {
          // skip
        }
      } else {
        packages.push(entry);
      }
    }

    for (const pkg of packages) {
      if (visited.has(pkg)) continue;
      visited.add(pkg);

      const pkgDir = resolveInNodeModules(pkg);
      const deps = getProductionDeps(pkgDir);

      for (const dep of deps) {
        const depDir = resolveInNodeModules(dep);
        if (fs.existsSync(depDir)) continue; // already present

        // Missing — find in .pnpm store and copy
        const storeLocation = findInPnpmStore(dep);
        if (!storeLocation) {
          console.warn(`[flatten-deps] WARN: ${dep} (needed by ${pkg}) not found in .pnpm store`);
          continue;
        }

        const realPath = fs.existsSync(storeLocation) && fs.lstatSync(storeLocation).isSymbolicLink()
          ? fs.realpathSync(storeLocation)
          : storeLocation;

        // For scoped packages, ensure the scope directory exists
        if (dep.startsWith("@")) {
          const scopeDir = path.join(nodeModulesDir, dep.split("/")[0]);
          if (!fs.existsSync(scopeDir)) fs.mkdirSync(scopeDir, { recursive: true });
        }

        fs.cpSync(realPath, depDir, { recursive: true });
        hoisted++;
        foundNew = true;
        console.log(`[flatten-deps] Hoisted ${dep} (needed by ${pkg})`);
      }
    }
  }
}

console.log("[flatten-deps] Pass 1: Resolving symlinks in node_modules...");
flattenSymlinks(nodeModulesDir, 0);
console.log(`[flatten-deps] Flattened ${flattened} symlinks`);

console.log("[flatten-deps] Pass 2: Hoisting missing transitive dependencies...");
hoistMissingDeps();
console.log(`[flatten-deps] Hoisted ${hoisted} missing transitive deps`);
console.log("[flatten-deps] Done");
