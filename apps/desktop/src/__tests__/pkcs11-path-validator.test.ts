/**
 * Tests for `pkcs11-path-validator.ts` (HIGH-03).
 *
 * These tests verify that the validator:
 *  - Accepts real paths inside the platform allowlist.
 *  - Rejects non-existent files, symlink escapes, world-writable files,
 *    wrong extensions, and unknown platforms.
 *  - Never leaks the user-provided path in error messages.
 */

import { describe, it, expect, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

import {
  validatePkcs11Path,
  ALLOWED_PKCS11_DIRS_BY_PLATFORM,
} from "../main/pkcs11-path-validator.js";
import { ValidationError } from "@opencred/shared";

/**
 * Build a realpath of a temp file whose first path segment is the supplied
 * prefix. This lets us exercise the allowlist check with a real filesystem
 * object that we can `fs.stat` against — rather than mocking.
 *
 * On macOS, `/tmp` realpath-resolves to `/private/tmp`, so we avoid using
 * `/tmp` directly in positive-path tests.
 */
function makeTempFile(extension: string): { filePath: string; cleanup: () => void } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-pkcs11-valid-"));
  const filePath = path.join(dir, `library${extension}`);
  fs.writeFileSync(filePath, "fake-native-library-content", { mode: 0o644 });
  return {
    filePath,
    cleanup: () => {
      try {
        fs.rmSync(dir, { recursive: true, force: true });
      } catch {
        /* swallow */
      }
    },
  };
}

/**
 * Restore `process.platform` after a test mutates it. Node lets you redefine
 * the property via Object.defineProperty; vitest's `vi.stubGlobal` doesn't
 * apply to `process.platform` directly.
 */
function withPlatform(platform: NodeJS.Platform, fn: () => Promise<void>): Promise<void> {
  const original = process.platform;
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
  return fn().finally(() => {
    Object.defineProperty(process, "platform", { value: original, configurable: true });
  });
}

describe("validatePkcs11Path", () => {
  const cleanups: Array<() => void> = [];

  afterEach(() => {
    while (cleanups.length) {
      cleanups.pop()?.();
    }
    vi.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // Positive: happy path on the current platform
  // ---------------------------------------------------------------------------

  it("accepts a real file in the current platform's allowlist", async () => {
    // Pick a path inside the current platform's allowlist that actually exists
    // on disk. We can't rely on a specific OS library being present, so we
    // create a symlink named like a PKCS#11 library that points at a real
    // file. BUT — symlinks are resolved by realpath and checked against the
    // allowlist, so the symlink approach doesn't help us here.
    //
    // Instead we use Node's `fs.realpathSync` to discover where `/usr/lib/`
    // is actually mounted and, if any regular file inside it ends with `.so`
    // / `.dylib`, run the validator against that real path. This yields a
    // deterministic positive test on a developer's machine.
    const allowed = ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform];
    if (!allowed || allowed.length === 0) {
      // Skip — platform not supported. The wrong-platform test below
      // exercises the negative branch.
      return;
    }

    // Search for an existing shared library under each allowlist entry.
    const validExtensions =
      process.platform === "darwin"
        ? [".dylib"]
        : process.platform === "win32"
          ? [".dll"]
          : [".so"];

    let real: string | null = null;
    for (const dir of allowed) {
      try {
        const entries = fs.readdirSync(dir);
        for (const entry of entries) {
          if (!validExtensions.some((ext) => entry.toLowerCase().endsWith(ext))) {
            continue;
          }
          const candidate = path.join(dir, entry);
          try {
            const stat = fs.statSync(candidate);
            if (stat.isFile() && (stat.mode & 0o002) === 0) {
              real = candidate;
              break;
            }
          } catch {
            /* not readable, try next */
          }
        }
      } catch {
        /* directory not accessible, try next */
      }
      if (real) break;
    }

    if (!real) {
      // No suitable library found in the allowlist on this machine (common
      // on CI). Skip — this test is best-effort for developers.
      return;
    }

    const resolved = await validatePkcs11Path(real);
    expect(resolved).toBe(fs.realpathSync(real));
  });

  // ---------------------------------------------------------------------------
  // Negative: non-existent file
  // ---------------------------------------------------------------------------

  it("rejects a non-existent file", async () => {
    await expect(validatePkcs11Path("/tmp/does-not-exist-xyz.so")).rejects.toThrow(
      ValidationError,
    );
    await expect(validatePkcs11Path("/tmp/does-not-exist-xyz.so")).rejects.toThrow(
      /does not exist/,
    );
  });

  // ---------------------------------------------------------------------------
  // Negative: symlink escape
  // ---------------------------------------------------------------------------

  it("rejects a symlink that escapes the allowlist", async () => {
    const allowed = ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform];
    if (!allowed || allowed.length === 0) return;

    // Create a file outside the allowlist, then a symlink inside a tmp dir
    // that points at it. realpath will resolve to the outside path, so the
    // allowlist check must reject.
    const outside = makeTempFile(".so");
    cleanups.push(outside.cleanup);

    const linkDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-pkcs11-link-"));
    cleanups.push(() => fs.rmSync(linkDir, { recursive: true, force: true }));
    const symlink = path.join(linkDir, "alias.so");
    fs.symlinkSync(outside.filePath, symlink);

    await expect(validatePkcs11Path(symlink)).rejects.toThrow(ValidationError);
    await expect(validatePkcs11Path(symlink)).rejects.toThrow(/outside the trusted/);
  });

  // ---------------------------------------------------------------------------
  // Negative: world-writable (POSIX only)
  // ---------------------------------------------------------------------------

  it("rejects a world-writable file on POSIX", async () => {
    if (process.platform === "win32") return;

    const tmp = makeTempFile(".so");
    cleanups.push(tmp.cleanup);
    fs.chmodSync(tmp.filePath, 0o666); // world-writable

    // Stub the allowlist for this platform so the tmp path is accepted
    // prefix-wise; we want the *only* rejection reason to be the mode bit.
    const tmpDirPrefix = fs.realpathSync(os.tmpdir()) + path.sep;
    const original = [...ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform]];
    (ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform] as string[]).push(tmpDirPrefix);

    try {
      await expect(validatePkcs11Path(tmp.filePath)).rejects.toThrow(ValidationError);
      await expect(validatePkcs11Path(tmp.filePath)).rejects.toThrow(/world-writable/);
    } finally {
      (ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform] as string[]).length = 0;
      (ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform] as string[]).push(...original);
    }
  });

  // ---------------------------------------------------------------------------
  // Negative: wrong extension
  // ---------------------------------------------------------------------------

  it("rejects a file without a recognised shared-library extension", async () => {
    if (process.platform === "win32") return;

    const tmp = makeTempFile(".txt");
    cleanups.push(tmp.cleanup);

    // Temporarily add the tmp prefix to the allowlist so we isolate the
    // extension check.
    const tmpDirPrefix = fs.realpathSync(os.tmpdir()) + path.sep;
    const original = [...ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform]];
    (ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform] as string[]).push(tmpDirPrefix);

    try {
      await expect(validatePkcs11Path(tmp.filePath)).rejects.toThrow(ValidationError);
      await expect(validatePkcs11Path(tmp.filePath)).rejects.toThrow(/extension/);
    } finally {
      (ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform] as string[]).length = 0;
      (ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform] as string[]).push(...original);
    }
  });

  // ---------------------------------------------------------------------------
  // Negative: unknown platform
  // ---------------------------------------------------------------------------

  it("rejects when the runtime platform is not supported", async () => {
    await withPlatform("freebsd", async () => {
      // Create a real file — the platform check fires before the stat.
      const tmp = makeTempFile(".so");
      cleanups.push(tmp.cleanup);

      await expect(validatePkcs11Path(tmp.filePath)).rejects.toThrow(ValidationError);
      await expect(validatePkcs11Path(tmp.filePath)).rejects.toThrow(/platform not supported/);
    });
  });

  // ---------------------------------------------------------------------------
  // Negative: empty / non-string
  // ---------------------------------------------------------------------------

  it("rejects empty string", async () => {
    await expect(validatePkcs11Path("")).rejects.toThrow(ValidationError);
    await expect(validatePkcs11Path("")).rejects.toThrow(/empty or non-string/);
  });

  it("rejects non-string input", async () => {
    // @ts-expect-error — testing runtime validation
    await expect(validatePkcs11Path(null)).rejects.toThrow(ValidationError);
  });

  // ---------------------------------------------------------------------------
  // Negative: error messages never echo user input
  // ---------------------------------------------------------------------------

  it("never includes the user-provided path in rejection messages", async () => {
    const evilPath = "/tmp/PAYLOAD-MARKER-SHOULD-NOT-APPEAR-IN-ERROR.so";
    try {
      await validatePkcs11Path(evilPath);
      throw new Error("expected ValidationError");
    } catch (err) {
      expect(err).toBeInstanceOf(ValidationError);
      if (err instanceof Error) {
        expect(err.message).not.toContain("PAYLOAD-MARKER");
        expect(err.message).not.toContain(evilPath);
      }
    }
  });

  // ---------------------------------------------------------------------------
  // Negative: directory instead of file
  // ---------------------------------------------------------------------------

  it("rejects a directory path", async () => {
    if (process.platform === "win32") return;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-pkcs11-dir-"));
    cleanups.push(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

    const tmpDirPrefix = fs.realpathSync(os.tmpdir()) + path.sep;
    const original = [...ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform]];
    (ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform] as string[]).push(tmpDirPrefix);

    try {
      await expect(validatePkcs11Path(tmpDir)).rejects.toThrow(ValidationError);
      await expect(validatePkcs11Path(tmpDir)).rejects.toThrow(/not a regular file/);
    } finally {
      (ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform] as string[]).length = 0;
      (ALLOWED_PKCS11_DIRS_BY_PLATFORM[process.platform] as string[]).push(...original);
    }
  });
});

describe("ALLOWED_PKCS11_DIRS_BY_PLATFORM", () => {
  it("has an entry for every major platform we support", () => {
    expect(ALLOWED_PKCS11_DIRS_BY_PLATFORM.darwin.length).toBeGreaterThan(0);
    expect(ALLOWED_PKCS11_DIRS_BY_PLATFORM.linux.length).toBeGreaterThan(0);
    expect(ALLOWED_PKCS11_DIRS_BY_PLATFORM.win32.length).toBeGreaterThan(0);
  });

  it("entries end with path separators to prevent prefix-based bypasses", () => {
    for (const platform of ["darwin", "linux"] as const) {
      for (const dir of ALLOWED_PKCS11_DIRS_BY_PLATFORM[platform]) {
        expect(dir.endsWith("/")).toBe(true);
      }
    }
    for (const dir of ALLOWED_PKCS11_DIRS_BY_PLATFORM.win32) {
      expect(dir.endsWith("\\")).toBe(true);
    }
  });
});
