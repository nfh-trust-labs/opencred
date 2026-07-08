/**
 * Tests for scripts/verify-packaged-arch.cjs — the packaging-time guard that
 * fails the build when a packaged `.node` native binary was compiled for the
 * wrong CPU architecture (#641/#642: mac x64 DMGs shipped arm64 addons).
 *
 * Binary fixtures are synthesised in-memory: only the header bytes matter
 * for arch detection (Mach-O / fat Mach-O / ELF / PE).
 */
import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createRequire } from "node:module";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

const require = createRequire(import.meta.url);
const {
  detectBinaryArchs,
  findNodeBinaries,
  verifyPackagedArch,
} = require("../../scripts/verify-packaged-arch.cjs");

// ---------------------------------------------------------------------------
// Synthetic binary builders
// ---------------------------------------------------------------------------

const MACHO_CPU_X86_64 = 0x01000007;
const MACHO_CPU_ARM64 = 0x0100000c;

function machO64(cputype: number): Buffer {
  const buf = Buffer.alloc(32);
  buf.writeUInt32LE(0xfeedfacf, 0); // MH_MAGIC_64 in the file's byte order
  buf.writeUInt32LE(cputype, 4);
  return buf;
}

function machOFat(cputypes: number[]): Buffer {
  const buf = Buffer.alloc(8 + cputypes.length * 20);
  buf.writeUInt32BE(0xcafebabe, 0); // FAT_MAGIC — always big-endian
  buf.writeUInt32BE(cputypes.length, 4);
  cputypes.forEach((cputype, i) => {
    buf.writeUInt32BE(cputype, 8 + i * 20);
  });
  return buf;
}

function elf(machine: number): Buffer {
  const buf = Buffer.alloc(64);
  buf.write("\x7fELF", 0, "latin1");
  buf[4] = 2; // ELFCLASS64
  buf[5] = 1; // little-endian
  buf.writeUInt16LE(machine, 18);
  return buf;
}

function pe(machine: number): Buffer {
  const buf = Buffer.alloc(0x80);
  buf.write("MZ", 0, "latin1");
  buf.writeUInt32LE(0x40, 0x3c); // e_lfanew → PE header at 0x40
  buf.writeUInt32LE(0x00004550, 0x40); // "PE\0\0"
  buf.writeUInt16LE(machine, 0x44);
  return buf;
}

// ---------------------------------------------------------------------------
// detectBinaryArchs
// ---------------------------------------------------------------------------

describe("detectBinaryArchs", () => {
  it("detects arm64 thin Mach-O", () => {
    expect(detectBinaryArchs(machO64(MACHO_CPU_ARM64))).toEqual({
      format: "mach-o",
      archs: ["arm64"],
    });
  });

  it("detects x86_64 thin Mach-O", () => {
    expect(detectBinaryArchs(machO64(MACHO_CPU_X86_64))).toEqual({
      format: "mach-o",
      archs: ["x64"],
    });
  });

  it("detects both archs in a fat (universal) Mach-O", () => {
    const info = detectBinaryArchs(machOFat([MACHO_CPU_X86_64, MACHO_CPU_ARM64]));
    expect(info.format).toBe("mach-o-fat");
    expect(info.archs.sort()).toEqual(["arm64", "x64"]);
  });

  it("does not mistake a Java class file (same magic as fat Mach-O) for a binary", () => {
    const javaClass = Buffer.alloc(16);
    javaClass.writeUInt32BE(0xcafebabe, 0);
    javaClass.writeUInt32BE(0x00000041, 4); // minor=0, major=65 — implausible fat arch count
    expect(detectBinaryArchs(javaClass)).toBeNull();
  });

  it("detects x64 and arm64 ELF", () => {
    expect(detectBinaryArchs(elf(0x3e))).toEqual({ format: "elf", archs: ["x64"] });
    expect(detectBinaryArchs(elf(0xb7))).toEqual({ format: "elf", archs: ["arm64"] });
  });

  it("detects x64 and arm64 PE", () => {
    expect(detectBinaryArchs(pe(0x8664))).toEqual({ format: "pe", archs: ["x64"] });
    expect(detectBinaryArchs(pe(0xaa64))).toEqual({ format: "pe", archs: ["arm64"] });
  });

  it("reports unknown cputypes loudly instead of guessing", () => {
    const info = detectBinaryArchs(machO64(0x12345678));
    expect(info.archs[0]).toMatch(/^unknown\(0x/);
  });

  it("returns null for unrecognised formats and short buffers", () => {
    expect(detectBinaryArchs(Buffer.from("not a binary at all, just text"))).toBeNull();
    expect(detectBinaryArchs(Buffer.alloc(4))).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// verifyPackagedArch against a fixture directory tree
// ---------------------------------------------------------------------------

describe("verifyPackagedArch", () => {
  let dir: string;

  beforeAll(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-arch-guard-"));
  });

  afterAll(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function writeTree(root: string, files: Record<string, Buffer>) {
    fs.mkdirSync(root, { recursive: true });
    for (const [rel, content] of Object.entries(files)) {
      const full = path.join(root, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, content);
    }
  }

  it("passes when every .node matches the target arch (the fixed layout)", () => {
    const appDir = path.join(dir, "ok-arm64");
    writeTree(appDir, {
      "OpenCred.app/Contents/Resources/app.asar.unpacked/dist/main/main/native/macos-keychain.node":
        machO64(MACHO_CPU_ARM64),
      "OpenCred.app/Contents/Resources/app.asar.unpacked/node_modules/pkcs11js/build/Release/pkcs11.node":
        machO64(MACHO_CPU_ARM64),
    });
    const result = verifyPackagedArch(appDir, "arm64");
    expect(result.problems).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.checked).toHaveLength(2);
  });

  it("fails when an x64 package contains arm64 addons (the #641/#642 bug)", () => {
    const appDir = path.join(dir, "bug-x64");
    writeTree(appDir, {
      "OpenCred.app/Contents/Resources/app.asar.unpacked/dist/main/main/native/macos-keychain.node":
        machO64(MACHO_CPU_ARM64), // host-arch binary leaked into the x64 build
      "OpenCred.app/Contents/Resources/app.asar.unpacked/node_modules/pkcs11js/build/Release/pkcs11.node":
        machO64(MACHO_CPU_X86_64),
    });
    const result = verifyPackagedArch(appDir, "x64");
    expect(result.ok).toBe(false);
    expect(result.problems).toHaveLength(1);
    expect(result.problems[0]).toContain("macos-keychain.node");
    expect(result.problems[0]).toContain("arm64");
  });

  it("accepts a fat binary that contains the target arch", () => {
    const appDir = path.join(dir, "fat");
    writeTree(appDir, {
      "app/some.node": machOFat([MACHO_CPU_X86_64, MACHO_CPU_ARM64]),
    });
    expect(verifyPackagedArch(appDir, "x64").ok).toBe(true);
    expect(verifyPackagedArch(appDir, "arm64").ok).toBe(true);
  });

  it("fails when the app contains NO native binaries (pipeline broken)", () => {
    const appDir = path.join(dir, "empty");
    writeTree(appDir, { "app/index.js": Buffer.from("// no natives") });
    const result = verifyPackagedArch(appDir, "x64");
    expect(result.ok).toBe(false);
    expect(result.problems[0]).toContain("No .node native binaries");
  });

  it("fails on unrecognisable .node files instead of skipping them", () => {
    const appDir = path.join(dir, "garbage");
    writeTree(appDir, { "app/broken.node": Buffer.from("garbage contents") });
    const result = verifyPackagedArch(appDir, "x64");
    expect(result.ok).toBe(false);
    expect(result.problems[0]).toContain("unrecognised binary format");
  });

  it("verifies linux (ELF) and windows (PE) outputs too", () => {
    const linuxDir = path.join(dir, "linux");
    writeTree(linuxDir, { "linux-unpacked/resources/x.node": elf(0x3e) });
    expect(verifyPackagedArch(linuxDir, "x64").ok).toBe(true);
    expect(verifyPackagedArch(linuxDir, "arm64").ok).toBe(false);

    const winDir = path.join(dir, "win");
    writeTree(winDir, { "win-unpacked/resources/y.node": pe(0x8664) });
    expect(verifyPackagedArch(winDir, "x64").ok).toBe(true);
    expect(verifyPackagedArch(winDir, "arm64").ok).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// findNodeBinaries
// ---------------------------------------------------------------------------

describe("findNodeBinaries", () => {
  it("finds nested .node files and ignores other extensions", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-find-node-"));
    try {
      fs.mkdirSync(path.join(dir, "a", "b"), { recursive: true });
      fs.writeFileSync(path.join(dir, "a", "b", "x.node"), Buffer.alloc(1));
      fs.writeFileSync(path.join(dir, "a", "y.txt"), "nope");
      fs.writeFileSync(path.join(dir, "z.node"), Buffer.alloc(1));
      const found = findNodeBinaries(dir).map((f: string) => path.relative(dir, f));
      expect(found.sort()).toEqual([path.join("a", "b", "x.node"), "z.node"]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// On macOS, sanity-check against a REAL system binary so the synthetic
// fixtures can't drift from reality.
// ---------------------------------------------------------------------------

describe.runIf(process.platform === "darwin")("real binary sanity check (macOS)", () => {
  it("detects the host arch inside /bin/ls", () => {
    const info = detectBinaryArchs(fs.readFileSync("/bin/ls"));
    expect(info).not.toBeNull();
    // /bin/ls on modern macOS is a universal binary; at minimum it must
    // contain the arch this test process is running on.
    expect(info.archs).toContain(process.arch);
  });
});
