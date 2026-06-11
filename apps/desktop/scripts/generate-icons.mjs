#!/usr/bin/env node
/**
 * generate-icons.mjs — rasterize the OpenCred brand SVGs into the binary
 * icon assets electron-builder needs so the OpenCred logo shows up on the
 * built app, in the DMG, and in the installer.
 *
 * Produces (all under build/):
 *   - icon.png            1024×1024  → Linux app icon + source of truth
 *   - icon.icns           macOS app icon (iconset → iconutil)
 *   - icon.ico            Windows app + NSIS installer icon
 *   - dmg-background.png   660×420   → DMG window background (@1x)
 *   - dmg-background@2x.png 1320×840 → DMG window background (retina)
 *
 * electron-builder does NOT rasterize SVG. Without these files the build
 * falls back to the default Electron icon — which is why the OpenCred logo
 * was missing on download. Run this whenever build/icon.svg changes:
 *
 *   node scripts/generate-icons.mjs
 *
 * Requires ImageMagick (`magick`) and, for .icns, macOS `iconutil`.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const BUILD_DIR = join(dirname(fileURLToPath(import.meta.url)), "..", "build");
const ICON_SVG = join(BUILD_DIR, "icon.svg");
const DMG_SVG = join(BUILD_DIR, "dmg-background.svg");

// Scratch dir inside the project — the system temp dir may be sandboxed,
// which makes ImageMagick's intermediate writes fail.
const WORK_ROOT = join(BUILD_DIR, ".icongen");
mkdirSync(WORK_ROOT, { recursive: true });

function have(bin) {
  try {
    execFileSync(bin, ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/** `--version`-less binaries (e.g. iconutil) — probe with `which`. */
function onPath(bin) {
  try {
    execFileSync("/usr/bin/which", [bin], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const MAGICK = have("magick") ? "magick" : have("convert") ? "convert" : null;
if (!MAGICK) {
  console.error("✗ ImageMagick not found. Install it: brew install imagemagick");
  process.exit(1);
}

/** Rasterize an SVG to a PNG at an exact pixel size. */
function svgToPng(svg, png, w, h = w) {
  execFileSync(MAGICK, [
    "-background", "none",
    "-density", "512",
    svg,
    "-resize", `${w}x${h}`,
    "-extent", `${w}x${h}`,
    png,
  ]);
}

// ---------------------------------------------------------------------------
// 1. icon.png (1024) — Linux + source for the rest
// ---------------------------------------------------------------------------
console.log("→ icon.png (1024×1024)");
svgToPng(ICON_SVG, join(BUILD_DIR, "icon.png"), 1024);

// ---------------------------------------------------------------------------
// 2. icon.icns (macOS) via iconset + iconutil
// ---------------------------------------------------------------------------
if (onPath("iconutil")) {
  console.log("→ icon.icns (macOS)");
  const work = mkdtempSync(join(WORK_ROOT,"oc-iconset-"));
  const iconset = join(work, "icon.iconset");
  mkdirSync(iconset);
  // iconutil expects these exact names/sizes.
  const variants = [
    [16, "16x16"], [32, "16x16@2x"],
    [32, "32x32"], [64, "32x32@2x"],
    [128, "128x128"], [256, "128x128@2x"],
    [256, "256x256"], [512, "256x256@2x"],
    [512, "512x512"], [1024, "512x512@2x"],
  ];
  for (const [size, name] of variants) {
    svgToPng(ICON_SVG, join(iconset, `icon_${name}.png`), size);
  }
  execFileSync("iconutil", ["-c", "icns", iconset, "-o", join(BUILD_DIR, "icon.icns")]);
  rmSync(work, { recursive: true, force: true });
} else {
  console.warn("⚠ iconutil not found (macOS only) — skipping icon.icns");
}

// ---------------------------------------------------------------------------
// 3. icon.ico (Windows) — multi-resolution
// ---------------------------------------------------------------------------
console.log("→ icon.ico (Windows)");
{
  const work = mkdtempSync(join(WORK_ROOT,"oc-ico-"));
  const sizes = [16, 24, 32, 48, 64, 128, 256];
  const pngs = sizes.map((s) => {
    const p = join(work, `${s}.png`);
    svgToPng(ICON_SVG, p, s);
    return p;
  });
  execFileSync(MAGICK, [...pngs, join(BUILD_DIR, "icon.ico")]);
  rmSync(work, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// 4. DMG background (@1x + @2x)
// ---------------------------------------------------------------------------
if (existsSync(DMG_SVG)) {
  console.log("→ dmg-background.png (660×420) + @2x");
  svgToPng(DMG_SVG, join(BUILD_DIR, "dmg-background.png"), 660, 420);
  svgToPng(DMG_SVG, join(BUILD_DIR, "dmg-background@2x.png"), 1320, 840);
} else {
  console.warn("⚠ build/dmg-background.svg not found — skipping DMG background");
}

rmSync(WORK_ROOT, { recursive: true, force: true });
console.log("✓ Icons generated in build/");
