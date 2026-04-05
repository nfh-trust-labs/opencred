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
let missing = 0;

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

// Cache the .pnpm store listing (read once, reused across all lookups)
let _storeEntries = null;
function getStoreEntries() {
  if (_storeEntries) return _storeEntries;
  if (!fs.existsSync(pnpmStoreDir)) return [];
  try {
    _storeEntries = fs.readdirSync(pnpmStoreDir);
  } catch {
    _storeEntries = [];
  }
  return _storeEntries;
}

/**
 * Find a package inside the .pnpm virtual store.
 *
 * When parentName + parentVersion are provided, looks for the dep as a
 * sibling in the parent's store entry first. This ensures we get the
 * exact version pnpm resolved for that parent (avoids hoisting ajv@6
 * when the parent needs ajv@8).
 *
 * Falls back to a global store scan if the parent lookup fails.
 */
function findInPnpmStore(pkgName, parentName, parentVersion) {
  const entries = getStoreEntries();
  if (entries.length === 0) return null;

  // Strategy 1: look for pkgName as a sibling of the parent package.
  // .pnpm/<parent>@<version>/node_modules/<pkgName> is the exact version
  // pnpm resolved for this parent.
  if (parentName && parentVersion) {
    const parentKey = parentName.replace("/", "+") + "@" + parentVersion;
    for (const entry of entries) {
      if (!entry.startsWith(parentKey)) continue;
      const candidate = path.join(pnpmStoreDir, entry, "node_modules", pkgName);
      if (fs.existsSync(candidate)) return candidate;
    }
  }

  // Strategy 2: global scan — when multiple versions exist, prefer the highest
  // semver (app packages generally need newer versions; build tools that need
  // older versions are typically .ignored_ and not packaged).
  const storeKey = pkgName.replace("/", "+");
  let bestCanonical = null;
  let bestVersion = "";
  let fallback = null;
  for (const entry of entries) {
    const candidate = path.join(pnpmStoreDir, entry, "node_modules", pkgName);
    if (!fs.existsSync(candidate)) continue;
    if (entry.startsWith(storeKey + "@")) {
      const ver = entry.slice(storeKey.length + 1).split("_")[0]; // strip peer-dep suffix
      if (!bestCanonical || ver > bestVersion) {
        bestCanonical = candidate;
        bestVersion = ver;
      }
    } else if (!fallback) {
      fallback = candidate;
    }
  }
  return bestCanonical || fallback;
}

/**
 * Read package.json and return production deps + package metadata.
 */
function readPackageInfo(pkgDir) {
  const pkgJsonPath = path.join(pkgDir, "package.json");
  if (!fs.existsSync(pkgJsonPath)) return { deps: [], name: null, version: null };
  try {
    const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
    return {
      deps: Object.keys(pkg.dependencies || {}),
      name: pkg.name || null,
      version: pkg.version || null,
    };
  } catch {
    return { deps: [], name: null, version: null };
  }
}

/**
 * Iteratively hoist all missing transitive deps. Keeps going until no
 * new deps are found (handles chains like conf -> dot-prop -> type-fest).
 */
function hoistMissingDeps() {
  let foundNew = true;
  const visited = new Set();
  let iterations = 0;
  const MAX_ITERATIONS = 50;

  while (foundNew) {
    if (++iterations > MAX_ITERATIONS) {
      console.error(`[flatten-deps] ERROR: exceeded ${MAX_ITERATIONS} iterations — possible circular dependency`);
      process.exit(1);
    }
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

      const pkgDir = path.join(nodeModulesDir, pkg);
      const { deps, name: parentName, version: parentVersion } = readPackageInfo(pkgDir);

      for (const dep of deps) {
        const depDir = path.join(nodeModulesDir, dep);
        if (fs.existsSync(depDir)) continue; // already present

        // Missing — find in .pnpm store, preferring the version resolved for this parent
        const storeLocation = findInPnpmStore(dep, parentName, parentVersion);
        if (!storeLocation) {
          console.warn(`[flatten-deps] WARN: ${dep} (needed by ${pkg}) not found in .pnpm store`);
          missing++;
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
if (missing > 0) {
  console.error(`[flatten-deps] ERROR: ${missing} dependencies could not be found in the pnpm store`);
  process.exit(1);
}
console.log("[flatten-deps] Done");
