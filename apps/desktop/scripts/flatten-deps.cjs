/**
 * flatten-deps.cjs — Resolve pnpm workspace symlinks before electron-builder.
 *
 * pnpm uses symlinks for workspace dependencies and the pnpm virtual store.
 * electron-builder resolves these symlinks and fails because target paths
 * are outside apps/desktop/.
 *
 * This script recursively replaces all symlinks under node_modules/ with
 * real copies so electron-builder can pack them without path errors.
 *
 * Runs as part of build:dist, after tsc + vite build, before electron-builder.
 */

const fs = require("fs");
const path = require("path");

const nodeModulesDir = path.resolve(__dirname, "..", "node_modules");
let flattened = 0;

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

console.log("[flatten-deps] Resolving symlinks in node_modules...");
flattenSymlinks(nodeModulesDir, 0);
console.log(`[flatten-deps] Flattened ${flattened} symlinks`);
