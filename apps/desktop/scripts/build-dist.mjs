#!/usr/bin/env node
/**
 * build-dist.mjs — orchestrates the desktop production build.
 *
 * prepare-native-deps.cjs mutates apps/desktop/package.json in-place
 * (strips workspace/runtime deps so electron-builder packages only
 * pkcs11js). Without a restore step, any local build leaves the working
 * tree dirty and can silently break subsequent `pnpm install` runs.
 *
 * This wrapper saves a backup before running the pipeline, restores
 * the original package.json on every exit path (success, failure,
 * Ctrl+C, SIGTERM), and forwards electron-builder's exit code.
 *
 * The backup file is .gitignored.
 */

import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const desktopDir = path.resolve(__dirname, "..");
const pkgPath = path.join(desktopDir, "package.json");
const backupPath = pkgPath + ".bak";

/**
 * Pipeline steps. Each step is an argv array passed to spawnSync —
 * no shell interpolation, no injection risk. The final electron-builder
 * step receives whatever extra flags were passed to this wrapper
 * (e.g. --mac, --config.mac.identity=null).
 */
const steps = [
  ["npm", ["run", "rebuild:native"]],
  ["npx", ["vite", "build"]],
  ["node", ["scripts/bundle-main.mjs"]],
  ["node", ["scripts/prepare-native-deps.cjs"]],
  ["npx", ["electron-builder", ...process.argv.slice(2)]],
];

function restore() {
  if (fs.existsSync(backupPath)) {
    fs.copyFileSync(backupPath, pkgPath);
    fs.unlinkSync(backupPath);
    console.log("[build-dist] Restored package.json from backup");
  }
}

// Save backup before anything mutates package.json
fs.copyFileSync(pkgPath, backupPath);
console.log("[build-dist] Saved package.json backup");

// Restore on signals too (Ctrl+C, SIGTERM)
process.on("SIGINT", () => {
  restore();
  process.exit(130);
});
process.on("SIGTERM", () => {
  restore();
  process.exit(143);
});

let exitCode = 0;
try {
  for (const [cmd, args] of steps) {
    console.log(`\n[build-dist] $ ${cmd} ${args.join(" ")}`);
    const result = spawnSync(cmd, args, { stdio: "inherit", cwd: desktopDir });
    if (result.status !== 0) {
      exitCode = result.status ?? 1;
      console.error(`[build-dist] Failed at exit ${exitCode}: ${cmd} ${args.join(" ")}`);
      break;
    }
  }
} finally {
  restore();
}

process.exit(exitCode);
