#!/usr/bin/env node
/**
 * packaged-smoke.mjs — boot smoke test for the PACKAGED desktop app.
 *
 * Proves that the electron-builder output (out/<platform>-unpacked or
 * out/mac-<arch>/OpenCred.app) launches, loads the PRODUCTION renderer
 * (dist/renderer/index.html via loadFile — not the Vite dev server) and that
 * the React app actually mounted. The in-app side of this handshake lives in
 * src/main/index.ts, guarded by OPENCRED_SMOKE_TEST=1: on success the app
 * prints "[smoke] renderer loaded <url>" and exits 0; on did-fail-load,
 * render-process-gone, an empty #root or a 30s timeout it prints
 * "[smoke] FAIL: ..." and exits 1.
 *
 * Usage:
 *   pnpm package:ci        # build the unsigned --dir package first
 *   pnpm smoke:packaged    # then run this (under xvfb-run on headless Linux)
 *
 * The app is launched with a throwaway userData dir (OPENCRED_SMOKE_USER_DATA)
 * so smoke runs never touch a real OpenCred profile.
 */

import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.resolve(__dirname, "..", "out");

// Overall budget: the in-app hook self-terminates at 30s; this outer guard
// covers a hung main process that never reaches the hook.
const TIMEOUT_MS = 90_000;

const SUCCESS_RE = /^\[smoke\] renderer loaded (.+)$/m;

function fail(message) {
  console.error(`[packaged-smoke] FAIL: ${message}`);
  process.exit(1);
}

/** Locate the unpacked packaged binary produced by `electron-builder --dir`. */
function findPackagedBinary() {
  const candidates = [];
  if (process.platform === "darwin") {
    // out/mac/, out/mac-arm64/, out/mac-universal/ ...
    for (const entry of fs.existsSync(outDir) ? fs.readdirSync(outDir) : []) {
      if (entry === "mac" || entry.startsWith("mac-")) {
        candidates.push(path.join(outDir, entry, "OpenCred.app", "Contents", "MacOS", "OpenCred"));
      }
    }
  } else if (process.platform === "win32") {
    candidates.push(path.join(outDir, "win-unpacked", "OpenCred.exe"));
  } else {
    // linux.executableName is "opencred" (see package.json "build" section)
    candidates.push(path.join(outDir, "linux-unpacked", "opencred"));
  }

  const binary = candidates.find((p) => fs.existsSync(p));
  if (!binary) {
    fail(
      `packaged binary not found. Looked for:\n  ${candidates.join("\n  ")}\n` +
        "Run `pnpm package:ci` (apps/desktop) first.",
    );
  }
  return binary;
}

const binary = findPackagedBinary();
console.log(`[packaged-smoke] launching ${binary}`);

const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "opencred-smoke-"));

let child;
try {
  child = spawn(binary, [], {
    env: {
      ...process.env,
      OPENCRED_SMOKE_TEST: "1",
      OPENCRED_SMOKE_USER_DATA: userDataDir,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
} catch (err) {
  // Some spawn failures (e.g. ENOEXEC) throw synchronously.
  cleanup();
  fail(`failed to spawn packaged app: ${err.message}`);
}

let stdout = "";
let stderr = "";
child.stdout.on("data", (chunk) => {
  stdout += chunk;
  process.stdout.write(chunk);
});
child.stderr.on("data", (chunk) => {
  stderr += chunk;
  process.stderr.write(chunk);
});

let timedOut = false;
const timer = setTimeout(() => {
  timedOut = true;
  child.kill("SIGKILL");
}, TIMEOUT_MS);

child.on("error", (err) => {
  clearTimeout(timer);
  cleanup();
  fail(`failed to spawn packaged app: ${err.message}`);
});

child.on("exit", (code, signal) => {
  clearTimeout(timer);
  cleanup();

  if (timedOut) {
    fail(`packaged app did not exit within ${TIMEOUT_MS / 1000}s (killed)`);
  }
  if (code !== 0) {
    fail(`packaged app exited with code ${code ?? `signal ${signal}`} (expected 0)`);
  }

  const match = stdout.match(SUCCESS_RE);
  if (!match) {
    fail('exit code was 0 but no "[smoke] renderer loaded <url>" line was printed');
  }

  const url = match[1].trim();
  // loadFile() yields a file:// URL ending in .../renderer/index.html. Seeing
  // the Vite dev server here would mean we exercised dev mode, not the
  // packaged production path.
  if (!url.startsWith("file://")) {
    fail(`renderer URL is not a file:// URL (got: ${url}) — dev server was loaded?`);
  }
  if (!url.endsWith("/renderer/index.html")) {
    fail(`renderer URL does not end with /renderer/index.html (got: ${url})`);
  }
  if (stdout.includes("localhost:5174") || stderr.includes("localhost:5174")) {
    fail("output references the Vite dev server (localhost:5174)");
  }

  console.log(`[packaged-smoke] PASS: packaged app booted, production renderer mounted (${url})`);
  process.exit(0);
});

function cleanup() {
  try {
    fs.rmSync(userDataDir, { recursive: true, force: true });
  } catch {
    // Best effort — CI runners are throwaway.
  }
}
