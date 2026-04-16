/**
 * PKCS#11 library path validator.
 *
 * Validates that a user-supplied PKCS#11 shared-library path points to a file
 * in a trusted system directory and is not a symlink escape, a world-writable
 * drop-in, or a non-library file.
 *
 * This addresses the HIGH-03 finding from the security audit: previously the
 * PKCS#11 IPC handlers accepted any filesystem path (after a toLowerCase()
 * extension check), so a compromised renderer could coerce the main process
 * into dlopen()ing an arbitrary shared library and executing native code.
 *
 * SECURITY INVARIANTS:
 *   - The real, canonical path (after resolving symlinks) MUST live inside one
 *     of the platform allowlist directories.
 *   - On POSIX, world-writable files are rejected to prevent an unprivileged
 *     user from swapping the library underneath us.
 *   - Unknown platforms are rejected — we'd rather fail-closed than guess.
 *   - Error messages NEVER echo the user-provided path: that would let a
 *     crafted error (or error log) leak the path normalization logic back to
 *     an attacker. Callers see only "<reason>" strings.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { ValidationError } from "@opencred/shared";

/**
 * Per-platform list of directory prefixes from which PKCS#11 shared libraries
 * may be loaded. Every entry ends with the platform's path separator so that
 * `/usr/lib/` does NOT accidentally match `/usr/libevil/foo.so`.
 *
 * NOTE: Windows paths are compared case-insensitively (Windows filesystems are
 * case-insensitive and the canonical path returned by `realpath` can differ
 * in case from the allowlist entry). All other platforms compare byte-for-byte.
 */
export const ALLOWED_PKCS11_DIRS_BY_PLATFORM: Record<NodeJS.Platform, readonly string[]> = {
  aix: [],
  android: [],
  darwin: [
    "/usr/lib/",
    "/usr/local/lib/",
    "/opt/homebrew/lib/",
    "/Library/OpenSC/lib/",
  ],
  freebsd: [],
  haiku: [],
  linux: [
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/lib/x86_64-linux-gnu/",
    "/usr/local/lib/",
    "/usr/local/lib64/",
    "/opt/",
  ],
  openbsd: [],
  sunos: [],
  win32: [
    "C:\\Windows\\System32\\",
    "C:\\Program Files\\",
    "C:\\Program Files (x86)\\",
  ],
  cygwin: [],
  netbsd: [],
};

/** Allowed extensions per platform in priority order, checked case-insensitively. */
const ALLOWED_EXTENSIONS: readonly string[] = [".so", ".dll", ".dylib"];

/**
 * Case-insensitive prefix check. On Windows we lower-case both sides because
 * NTFS and the canonical path from realpath can differ in capitalization; on
 * other platforms we compare byte-for-byte.
 */
function hasAllowedPrefix(
  realpath: string,
  allowedPrefixes: readonly string[],
  platform: NodeJS.Platform,
): boolean {
  if (platform === "win32") {
    const lower = realpath.toLowerCase();
    return allowedPrefixes.some((p) => lower.startsWith(p.toLowerCase()));
  }
  return allowedPrefixes.some((p) => realpath.startsWith(p));
}

function hasAllowedExtension(realpath: string): boolean {
  const lower = realpath.toLowerCase();
  return ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext));
}

/**
 * Validate a user-supplied PKCS#11 library path.
 *
 * @param userPath - The path the renderer provided. May or may not exist,
 *   may be a symlink, may point outside the allowlist. This function treats
 *   it as fully untrusted input.
 * @returns The canonical (realpath-resolved) library path that callers should
 *   pass to `initializePkcs11`. Callers MUST use the returned value — using
 *   the original `userPath` defeats the symlink check.
 * @throws {ValidationError} with a generic "PKCS#11 library path rejected:
 *   <reason>" message. The user-provided path is NEVER included in the error
 *   (see file-level comment).
 */
export async function validatePkcs11Path(userPath: string): Promise<string> {
  if (typeof userPath !== "string" || userPath.length === 0) {
    throw new ValidationError("PKCS#11 library path rejected: empty or non-string path.");
  }

  // Step 1: resolve symlinks. realpath() throws ENOENT for missing files.
  let realpath: string;
  try {
    realpath = await fs.promises.realpath(userPath);
  } catch {
    throw new ValidationError("PKCS#11 library path rejected: file does not exist.");
  }

  // Step 2: platform allowlist.
  const platform = process.platform;
  const allowed = ALLOWED_PKCS11_DIRS_BY_PLATFORM[platform];
  if (!allowed || allowed.length === 0) {
    throw new ValidationError(
      "PKCS#11 library path rejected: platform not supported for PKCS#11 loading.",
    );
  }

  if (!hasAllowedPrefix(realpath, allowed, platform)) {
    throw new ValidationError(
      "PKCS#11 library path rejected: resolved path is outside the trusted system library directories.",
    );
  }

  // Step 3: stat checks — real file, not a world-writable drop-in on POSIX.
  let stat: fs.Stats;
  try {
    stat = await fs.promises.stat(realpath);
  } catch {
    throw new ValidationError("PKCS#11 library path rejected: unable to stat resolved path.");
  }

  if (!stat.isFile()) {
    throw new ValidationError("PKCS#11 library path rejected: resolved path is not a regular file.");
  }

  if (platform !== "win32") {
    // 0o002 = other-writable. A library an unprivileged user could overwrite
    // is a privilege-escalation vector even if it lives in /usr/lib.
    // eslint-disable-next-line no-bitwise
    if ((stat.mode & 0o002) !== 0) {
      throw new ValidationError(
        "PKCS#11 library path rejected: library is world-writable and cannot be trusted.",
      );
    }
  }

  // Step 4: extension gate.
  if (!hasAllowedExtension(realpath)) {
    throw new ValidationError(
      "PKCS#11 library path rejected: file does not have a recognised shared-library extension (.so, .dll, .dylib).",
    );
  }

  // Step 5: defense-in-depth — reject paths containing NUL bytes (shouldn't
  // happen post-realpath, but cheap to check) and `..` remnants.
  if (realpath.includes("\0") || realpath.split(path.sep).includes("..")) {
    throw new ValidationError(
      "PKCS#11 library path rejected: resolved path contains suspicious components.",
    );
  }

  return realpath;
}
