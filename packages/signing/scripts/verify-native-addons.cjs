#!/usr/bin/env node
"use strict";

/**
 * Verify that native addons were compiled for the current platform.
 *
 * Exit codes:
 *   0 — expected addon(s) found, or platform has no expected addons
 *   1 — expected addon missing (build pipeline is broken)
 */

const fs = require("fs");
const path = require("path");
const os = require("os");

const buildDir = path.join(__dirname, "..", "native", "build", "Release");
const platform = os.platform();

const expected = {
  darwin: "macos-keychain.node",
  win32: "windows-cng.node",
};

const addonName = expected[platform];

if (!addonName) {
  console.log(
    `[verify-native-addons] Platform "${platform}" has no native cert-store addon — skipping.`
  );
  process.exit(0);
}

const addonPath = path.join(buildDir, addonName);

if (fs.existsSync(addonPath)) {
  const stat = fs.statSync(addonPath);
  console.log(
    `[verify-native-addons] OK: ${addonPath} (${stat.size} bytes)`
  );
  process.exit(0);
} else {
  console.error(
    `[verify-native-addons] MISSING: ${addonPath}\n` +
      `  The native build step did not produce the expected addon.\n` +
      `  Run "pnpm --filter @opencred/signing build:native" to debug.`
  );
  process.exit(1);
}
