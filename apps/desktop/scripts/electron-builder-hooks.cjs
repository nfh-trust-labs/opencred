"use strict";

/**
 * electron-builder-hooks.cjs — per-architecture native rebuild + arch guard.
 *
 * THE BUG THIS FIXES (#641 / #642)
 * --------------------------------
 * The macOS release packages BOTH x64 and arm64 from one runner
 * (`electron-builder --mac --x64 --arm64`). Native addons used to be rebuilt
 * ONCE, for the runner's host arch only (rebuild-native.cjs defaulted to
 * `process.arch`), so the same single-arch `.node` files were copied into
 * both DMGs. With `macos-latest` being arm64, the Intel DMG shipped arm64
 * binaries — Intel users (and Apple Silicon users who downloaded the
 * no-suffix DMG and ran under Rosetta) crashed at the first native call.
 *
 * THE FIX
 * -------
 * electron-builder packs each arch sequentially and calls `beforePack` once
 * per (platform, arch) BEFORE copying any files into the .app — see
 * app-builder-lib/out/platformPackager.js (doPack: beforePack →
 * installAppDependencies → copy files → afterPack → sign). So:
 *
 *   beforePack: rebuild pkcs11js + opencred-native-addons for the TARGET
 *     arch (rebuild-native.cjs --arch=<target>), then refresh the copy of
 *     the signing addons that bundle-main.mjs baked into
 *     dist/main/main/native/ (that copy was made from the host-arch build).
 *
 *   afterPack: walk the packed appOutDir and FAIL the build if any `.node`
 *     binary does not contain code for the target arch
 *     (scripts/verify-packaged-arch.cjs). Runs before signing and before
 *     DMG/zip creation, on every platform — the regression guard.
 *
 * Why beforePack and not beforeBuild: `--config.npmRebuild=false` (required
 * to keep electron-builder's bundled @electron/rebuild from hanging on
 * Windows pnpm symlink trees, #501) short-circuits installAppDependencies
 * BEFORE the beforeBuild hook is resolved (app-builder-lib/out/packager.js),
 * and a beforeBuild hook returning false would flip
 * `areNodeModulesHandledExternally`, changing how electron-builder collects
 * node_modules. beforePack runs unconditionally and changes neither.
 */

const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const { verifyPackagedArch } = require("./verify-packaged-arch.cjs");

const desktopDir = path.resolve(__dirname, "..");
const repoRoot = path.resolve(desktopDir, "..", "..");
// Where node-gyp puts the freshly compiled signing addons.
const signingNativeRelease = path.join(
  repoRoot,
  "packages",
  "signing",
  "native",
  "build",
  "Release"
);
// Where bundle-main.mjs copies them for packaging (included in the asar via
// the `dist/**/*` files pattern, unpacked via asarUnpack `dist/**/*.node`).
const distNativeDir = path.join(desktopDir, "dist", "main", "main", "native");

// electron-builder passes `arch` as the builder-util Arch enum (a number).
const ARCH_NAMES = {
  0: "ia32",
  1: "x64",
  2: "armv7l",
  3: "arm64",
  4: "universal",
};

function archName(arch) {
  if (typeof arch === "string") return arch;
  const name = ARCH_NAMES[arch];
  if (!name) throw new Error(`[eb-hooks] Unknown electron-builder arch value: ${arch}`);
  return name;
}

/** Map electron-builder's electronPlatformName to Node's process.platform. */
function nodePlatform(electronPlatformName) {
  return electronPlatformName === "mas" ? "darwin" : electronPlatformName;
}

exports.beforePack = async function beforePack(context) {
  const arch = archName(context.arch);
  const platform = context.electronPlatformName;

  if (arch === "universal") {
    // Universal builds are assembled from the per-arch builds, which were
    // each already rebuilt/verified. Nothing to compile here.
    console.log("[eb-hooks] beforePack: universal target — skipping native rebuild.");
    return;
  }
  if (nodePlatform(platform) !== process.platform) {
    // Cross-OS packaging can't run node-gyp for the target OS. Not used by
    // our CI (every platform builds on its own OS) — warn loudly and let the
    // afterPack guard catch any resulting mismatch.
    console.warn(
      `[eb-hooks] beforePack: host ${process.platform} cannot rebuild natives for ` +
        `${platform} — skipping. The afterPack arch guard will still verify the output.`
    );
    return;
  }

  console.log(`[eb-hooks] beforePack: rebuilding native addons for ${platform}/${arch} (#641/#642)`);
  const result = spawnSync(
    process.execPath,
    [path.join(__dirname, "rebuild-native.cjs"), `--arch=${arch}`],
    { cwd: desktopDir, stdio: "inherit" }
  );
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`[eb-hooks] rebuild-native.cjs --arch=${arch} exited with code ${result.status}`);
  }

  // bundle-main.mjs copied the signing addons into dist/main/main/native/ at
  // build:main time — from the HOST-arch build. Refresh that copy with the
  // target-arch binaries we just compiled, before electron-builder copies
  // dist/ into the app.
  if (fs.existsSync(signingNativeRelease)) {
    const nodeFiles = fs
      .readdirSync(signingNativeRelease)
      .filter((f) => f.endsWith(".node"));
    if (nodeFiles.length > 0) {
      fs.mkdirSync(distNativeDir, { recursive: true });
      for (const f of nodeFiles) {
        fs.copyFileSync(path.join(signingNativeRelease, f), path.join(distNativeDir, f));
        console.log(`[eb-hooks] Refreshed dist native addon for ${arch}: ${f}`);
      }
    }
  }
};

exports.afterPack = async function afterPack(context) {
  const arch = archName(context.arch);

  if (arch === "universal") {
    console.log("[eb-hooks] afterPack: universal target — per-arch builds already verified.");
    return;
  }

  console.log(`[eb-hooks] afterPack: verifying native binary architectures (${arch}) in ${context.appOutDir}`);
  const result = verifyPackagedArch(context.appOutDir, arch);
  for (const c of result.checked) {
    console.log(`[eb-hooks]   ${c.file}: ${c.format} [${c.archs.join(", ")}]`);
  }
  if (!result.ok) {
    throw new Error(
      `Packaged native binaries do not match target arch ${arch}:\n` +
        result.problems.map((p) => `  - ${p}`).join("\n") +
        `\nRefusing to produce a broken artefact (#641/#642).`
    );
  }
  console.log(
    `[eb-hooks] afterPack: OK — ${result.checked.length} native binar` +
      `${result.checked.length === 1 ? "y" : "ies"} match ${arch}.`
  );
};
