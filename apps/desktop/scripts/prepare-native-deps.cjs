/**
 * prepare-native-deps.cjs — Set up minimal node_modules for electron-builder.
 *
 * After esbuild bundles all JS dependencies into single files, the only
 * packages that need to remain in node_modules are native .node addons
 * that can't be bundled:
 *
 *   - pkcs11js (PKCS#11 hardware token support)
 *   - node-addon-api (pkcs11js dependency)
 *   - node-gyp-build (pkcs11js dependency)
 *
 * This script ensures these packages are present in the local node_modules
 * (resolved from the pnpm virtual store) and strips everything else to
 * keep the app bundle small.
 *
 * electron-builder will include these based on the `files` pattern in
 * package.json and use @electron/rebuild to recompile them for the
 * Electron ABI.
 */

const fs = require("fs");
const path = require("path");

const nodeModulesDir = path.resolve(__dirname, "..", "node_modules");
const rootNodeModulesDir = path.resolve(__dirname, "..", "..", "..", "node_modules");

// Packages that must remain in node_modules (native addons + their deps)
const REQUIRED_PACKAGES = ["pkcs11js", "node-addon-api", "node-gyp-build"];

/**
 * Ensure a package exists in the local node_modules.
 * In pnpm monorepos, packages may be symlinks to the virtual store.
 * We resolve them to real directories so electron-builder can pack them.
 */
function ensurePackage(pkgName) {
  const localPath = path.join(nodeModulesDir, pkgName);

  if (fs.existsSync(localPath)) {
    const stat = fs.lstatSync(localPath);
    if (stat.isSymbolicLink()) {
      // Resolve symlink to real directory
      const realPath = fs.realpathSync(localPath);
      fs.unlinkSync(localPath);
      fs.cpSync(realPath, localPath, { recursive: true });
      console.log(`[prepare-native] Resolved symlink: ${pkgName}`);
    } else {
      console.log(`[prepare-native] Already present: ${pkgName}`);
    }
    return true;
  }

  // Try to find in the pnpm virtual store at repo root
  const pnpmDir = path.join(rootNodeModulesDir, ".pnpm");
  if (!fs.existsSync(pnpmDir)) {
    console.warn(`[prepare-native] WARN: .pnpm store not found at ${pnpmDir}`);
    return false;
  }

  const storeKey = pkgName.replace("/", "+");
  const entries = fs.readdirSync(pnpmDir);
  for (const entry of entries) {
    if (!entry.startsWith(storeKey + "@")) continue;
    const candidate = path.join(pnpmDir, entry, "node_modules", pkgName);
    if (fs.existsSync(candidate)) {
      fs.cpSync(candidate, localPath, { recursive: true });
      console.log(`[prepare-native] Copied from store: ${pkgName}`);
      return true;
    }
  }

  console.warn(`[prepare-native] WARN: ${pkgName} not found in .pnpm store`);
  return false;
}

console.log("[prepare-native] Ensuring native addon packages are present...");

let allPresent = true;
for (const pkg of REQUIRED_PACKAGES) {
  if (!ensurePackage(pkg)) {
    allPresent = false;
  }
}

if (!allPresent) {
  console.warn("[prepare-native] Some native packages were not found.");
  console.warn("[prepare-native] PKCS#11 hardware token support may not work in the packaged app.");
  // Don't exit with error — the app works without PKCS#11 support
}

// -------------------------------------------------------------------------
// Strip bundled dependencies from package.json
// -------------------------------------------------------------------------
// electron-builder reads package.json `dependencies` to determine which
// packages to include in the asar. Since esbuild bundles ALL JS deps into
// the main process file, we only need pkcs11js (native addon) at runtime.
// Stripping the rest prevents electron-builder from following pnpm symlinks
// to workspace packages outside apps/desktop/.

const pkgJsonPath = path.resolve(__dirname, "..", "package.json");
try {
  const pkg = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
  const originalDeps = { ...pkg.dependencies };
  // Keep only native addon packages
  pkg.dependencies = {};
  if (originalDeps.pkcs11js) {
    pkg.dependencies.pkcs11js = originalDeps.pkcs11js;
  }
  fs.writeFileSync(pkgJsonPath, JSON.stringify(pkg, null, 2) + "\n");
  console.log(
    `[prepare-native] Stripped package.json dependencies: kept pkcs11js, removed ${
      Object.keys(originalDeps).length - (originalDeps.pkcs11js ? 1 : 0)
    } bundled deps`
  );
} catch (err) {
  console.warn(`[prepare-native] WARN: could not update package.json: ${err.message}`);
}

console.log("[prepare-native] Done");
