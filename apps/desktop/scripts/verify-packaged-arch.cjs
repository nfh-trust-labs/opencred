#!/usr/bin/env node
"use strict";

/**
 * verify-packaged-arch.cjs — assert every native `.node` binary inside a
 * packaged app directory was compiled for the expected CPU architecture.
 *
 * WHY THIS EXISTS (#641 / #642)
 * -----------------------------
 * The macOS release packages BOTH x64 and arm64 from a single runner. The
 * native addons (pkcs11js + opencred-native-addons) are compiled by
 * rebuild-native.cjs — historically only for the runner's host arch — so the
 * x64 DMG silently shipped arm64 `.node` files (and vice versa) and users on
 * the "other" architecture crashed on first native call (`dlopen` failure;
 * Rosetta cannot load arm64 .node files into a translated x64 process).
 *
 * This script is the regression guard: it walks an appOutDir (the unpacked
 * .app / *-unpacked directory electron-builder produces), finds every .node
 * file (asarUnpack guarantees they are on disk, never inside the asar), reads
 * each binary's header (Mach-O / ELF / PE — no `lipo`/`file` dependency, so
 * it works identically on all three CI platforms) and FAILS if any binary
 * does not contain code for the target architecture.
 *
 * It runs automatically as part of the electron-builder `afterPack` hook
 * (scripts/electron-builder-hooks.cjs) — i.e. for every packaged build on
 * every platform, before signing and before any DMG/zip/exe is produced.
 *
 * CLI usage (manual / debugging):
 *   node scripts/verify-packaged-arch.cjs --arch=x64 <appOutDir>
 */

const fs = require("fs");
const path = require("path");

// --------------------------------------------------------------------------
// Binary header parsing
// --------------------------------------------------------------------------

// Mach-O magic numbers (value once read in the file's own byte order).
const MACHO_MAGIC_64 = 0xfeedfacf;
const MACHO_MAGIC_32 = 0xfeedface;
// Fat (universal) Mach-O magics — always stored big-endian.
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;

// Mach-O cputype → electron-builder arch name.
const MACHO_CPU = {
  0x01000007: "x64", // CPU_TYPE_X86_64
  0x0100000c: "arm64", // CPU_TYPE_ARM64
  0x00000007: "ia32", // CPU_TYPE_X86
  0x0000000c: "armv7l", // CPU_TYPE_ARM
};

// ELF e_machine → arch name.
const ELF_MACHINE = {
  0x3e: "x64", // EM_X86_64
  0xb7: "arm64", // EM_AARCH64
  0x03: "ia32", // EM_386
  0x28: "armv7l", // EM_ARM
};

// PE IMAGE_FILE_HEADER.Machine → arch name.
const PE_MACHINE = {
  0x8664: "x64", // IMAGE_FILE_MACHINE_AMD64
  0xaa64: "arm64", // IMAGE_FILE_MACHINE_ARM64
  0x014c: "ia32", // IMAGE_FILE_MACHINE_I386
  0x01c4: "armv7l", // IMAGE_FILE_MACHINE_ARMNT
};

/**
 * Detect the binary format and architecture(s) contained in a buffer.
 *
 * @param {Buffer} buf — at least the first 64 bytes of the file (plus fat
 *   headers if applicable; pass the whole file to be safe — .node files
 *   are small).
 * @returns {{ format: string, archs: string[] } | null} `null` when the
 *   buffer is not a recognised native binary format. Unknown cputypes are
 *   reported as `"unknown(0x…)"` so mismatches stay loud rather than silent.
 */
function detectBinaryArchs(buf) {
  if (buf.length < 8) return null;

  // ---- Fat / universal Mach-O (big-endian header) ----
  const beMagic = buf.readUInt32BE(0);
  if (beMagic === FAT_MAGIC || beMagic === FAT_MAGIC_64) {
    const nfat = buf.readUInt32BE(4);
    // Java .class files share the 0xCAFEBABE magic; a real fat header has a
    // tiny arch count. Anything implausible is "not a fat binary".
    if (nfat === 0 || nfat > 30) return null;
    const entrySize = beMagic === FAT_MAGIC_64 ? 32 : 20;
    const archs = [];
    for (let i = 0; i < nfat; i++) {
      const off = 8 + i * entrySize;
      if (off + 4 > buf.length) return null;
      const cputype = buf.readUInt32BE(off);
      archs.push(MACHO_CPU[cputype] || `unknown(0x${cputype.toString(16)})`);
    }
    return { format: "mach-o-fat", archs };
  }

  // ---- Thin Mach-O (header in the file's native byte order) ----
  const leMagic = buf.readUInt32LE(0);
  if (leMagic === MACHO_MAGIC_64 || leMagic === MACHO_MAGIC_32) {
    const cputype = buf.readUInt32LE(4);
    return {
      format: "mach-o",
      archs: [MACHO_CPU[cputype] || `unknown(0x${cputype.toString(16)})`],
    };
  }
  if (beMagic === MACHO_MAGIC_64 || beMagic === MACHO_MAGIC_32) {
    const cputype = buf.readUInt32BE(4);
    return {
      format: "mach-o",
      archs: [MACHO_CPU[cputype] || `unknown(0x${cputype.toString(16)})`],
    };
  }

  // ---- ELF ----
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) {
    if (buf.length < 20) return null;
    const littleEndian = buf[5] !== 2; // EI_DATA: 1 = LSB, 2 = MSB
    const machine = littleEndian ? buf.readUInt16LE(18) : buf.readUInt16BE(18);
    return {
      format: "elf",
      archs: [ELF_MACHINE[machine] || `unknown(0x${machine.toString(16)})`],
    };
  }

  // ---- PE (Windows) ----
  if (buf[0] === 0x4d && buf[1] === 0x5a /* "MZ" */ && buf.length >= 0x40) {
    const peOffset = buf.readUInt32LE(0x3c);
    if (peOffset + 6 <= buf.length && buf.readUInt32LE(peOffset) === 0x00004550 /* "PE\0\0" */) {
      const machine = buf.readUInt16LE(peOffset + 4);
      return {
        format: "pe",
        archs: [PE_MACHINE[machine] || `unknown(0x${machine.toString(16)})`],
      };
    }
  }

  return null;
}

/**
 * Recursively find every `*.node` file under `dir`.
 * Symlinks are not followed (packaged apps must not contain symlinked
 * native addons; following them could also escape the app dir).
 */
function findNodeBinaries(dir) {
  const results = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      results.push(...findNodeBinaries(full));
    } else if (entry.isFile() && entry.name.endsWith(".node")) {
      results.push(full);
    }
  }
  return results;
}

/**
 * Verify every `.node` binary under `dir` contains code for `expectedArch`.
 *
 * A fat/universal Mach-O passes as long as it CONTAINS the expected arch.
 *
 * @param {string} dir — directory to scan (electron-builder appOutDir).
 * @param {string} expectedArch — "x64" | "arm64" | "ia32" | "armv7l".
 * @returns {{ ok: boolean, checked: Array<{file: string, format: string, archs: string[]}>, problems: string[] }}
 */
function verifyPackagedArch(dir, expectedArch) {
  const checked = [];
  const problems = [];

  const files = findNodeBinaries(dir);
  if (files.length === 0) {
    problems.push(
      `No .node native binaries found under ${dir} — the packaged app is expected ` +
        `to contain at least pkcs11js's pkcs11.node. The native build/packaging ` +
        `pipeline is broken.`
    );
    return { ok: false, checked, problems };
  }

  for (const file of files) {
    const buf = fs.readFileSync(file);
    const info = detectBinaryArchs(buf);
    const rel = path.relative(dir, file);
    if (info == null) {
      problems.push(`${rel}: unrecognised binary format — cannot verify architecture.`);
      continue;
    }
    checked.push({ file: rel, format: info.format, archs: info.archs });
    if (!info.archs.includes(expectedArch)) {
      problems.push(
        `${rel}: built for [${info.archs.join(", ")}] (${info.format}), ` +
          `but this package targets ${expectedArch}. ` +
          `The app would crash at the first native call on the target machine (#641/#642).`
      );
    }
  }

  return { ok: problems.length === 0, checked, problems };
}

module.exports = { detectBinaryArchs, findNodeBinaries, verifyPackagedArch };

// --------------------------------------------------------------------------
// CLI entry point
// --------------------------------------------------------------------------

if (require.main === module) {
  const args = process.argv.slice(2);
  let expectedArch = null;
  let dir = null;
  for (const a of args) {
    const m = /^--arch=(.+)$/.exec(a);
    if (m) expectedArch = m[1];
    else dir = a;
  }
  if (!expectedArch || !dir) {
    console.error("Usage: node scripts/verify-packaged-arch.cjs --arch=<x64|arm64> <appOutDir>");
    process.exit(2);
  }

  const result = verifyPackagedArch(path.resolve(dir), expectedArch);
  for (const c of result.checked) {
    console.log(`[verify-packaged-arch] ${c.file}: ${c.format} [${c.archs.join(", ")}]`);
  }
  if (!result.ok) {
    for (const p of result.problems) {
      console.error(`[verify-packaged-arch] FAIL: ${p}`);
    }
    process.exit(1);
  }
  console.log(
    `[verify-packaged-arch] OK: ${result.checked.length} native binar` +
      `${result.checked.length === 1 ? "y" : "ies"} match ${expectedArch}.`
  );
}
