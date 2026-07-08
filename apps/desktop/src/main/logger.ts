/**
 * Persistent structured logger for the Electron main process.
 *
 * Backed by electron-log — writes to rotating log files at platform-standard
 * paths (~/Library/Logs on macOS, %APPDATA%/logs on Windows, ~/.config/logs
 * on Linux). Logs persist across app restarts.
 *
 * SECURITY NOTES:
 *  - A redaction hook strips PEM blocks, long base64 strings, and JWK "d"
 *    (private key) fields before anything reaches disk.
 *  - NEVER pass private key material to any log method.
 *  - Log key IDs or fingerprints only — never raw key bytes.
 */

import log from "electron-log";
import * as fs from "node:fs";

// ---------------------------------------------------------------------------
// Types (unchanged public interface)
// ---------------------------------------------------------------------------

export interface Logger {
  info(msg: string, data?: Record<string, unknown>): void;
  warn(msg: string, data?: Record<string, unknown>): void;
  error(msg: string, data?: Record<string, unknown>): void;
  debug(msg: string, data?: Record<string, unknown>): void;
  child(bindings: Record<string, unknown>): Logger;
}

// ---------------------------------------------------------------------------
// Key-material redaction (exported for testing)
// ---------------------------------------------------------------------------

const PEM_BLOCK_RE = /-----BEGIN[A-Z ]+-----[\s\S]*?-----END[A-Z ]+-----/g;
const JWK_D_FIELD_RE = /"d"\s*:\s*"[^"]+"/g;
// Match long standard base64 strings (40+ chars).
// Standard base64 uses +/ so we require "+" (slash alone matches URLs).
const LONG_BASE64_STD_RE = /(?=[A-Za-z0-9+/]*\+)[A-Za-z0-9+/]{40,}={0,3}/g;
// Match long base64url strings (40+ chars).
// Base64url uses -_ instead of +/; we require at least one "-" or "_".
// Checked separately with an entropy filter to avoid false-positives on
// kebab-case identifiers, CSS classes, and SCREAMING_SNAKE constants.
const LONG_BASE64URL_RE = /(?=[A-Za-z0-9_-]*[_-])[A-Za-z0-9_-]{40,}={0,3}/g;

/**
 * Returns true when a candidate base64url string has high character-class
 * diversity — all four of: uppercase, lowercase, digits, and special [-_].
 *
 * Real base64url-encoded binary data (keys, signatures) virtually always
 * contains all four classes across 40+ characters.  Identifiers like
 * kebab-case build strings, SCREAMING_SNAKE constants, CSS classes, and
 * compound UUIDs typically use only 2-3 classes.
 *
 * The base64url regex already guarantees at least one "-" or "_", so
 * this effectively requires uppercase + lowercase + digits in addition.
 */
export function isHighEntropy(s: string): boolean {
  return /[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s) && /[-_]/.test(s);
}

export function redact(input: string): string {
  return input
    .replace(PEM_BLOCK_RE, "[REDACTED-PEM]")
    .replace(JWK_D_FIELD_RE, '"d":"[REDACTED]"')
    .replace(LONG_BASE64_STD_RE, "[REDACTED]")
    .replace(LONG_BASE64URL_RE, (match) => (isHighEntropy(match) ? "[REDACTED]" : match));
}

export function redactValue(value: unknown): unknown {
  if (typeof value === "string") return redact(value);
  if (typeof value === "object" && value !== null) {
    try {
      return JSON.parse(redact(JSON.stringify(value)));
    } catch {
      return value;
    }
  }
  return value;
}

// ---------------------------------------------------------------------------
// Configure electron-log
// ---------------------------------------------------------------------------

// File transport: rotate at 5 MB, keep old log as .old
log.transports.file.maxSize = 5 * 1024 * 1024;
log.transports.file.format = "[{y}-{m}-{d} {h}:{i}:{s}.{ms}] [{level}]{scope} {text}";

// Console transport in dev
log.transports.console.format = "[{h}:{i}:{s}] [{level}]{scope} {text}";

// Redaction hook — runs before any transport writes
log.hooks.push((message) => {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
  message.data = message.data.map((arg: unknown) => redactValue(arg));
  return message;
});

// Initialise renderer → main IPC forwarding so renderer logs go to file too
try {
  log.initialize();
} catch {
  // Fails in test environments where app is not ready — safe to ignore
}

// ---------------------------------------------------------------------------
// Logger factory
// ---------------------------------------------------------------------------

function createLoggerImpl(component?: string): Logger {
  const scoped = component ? log.scope(component) : log;

  return {
    info(msg: string, data?: Record<string, unknown>): void {
      if (data) scoped.info(msg, data);
      else scoped.info(msg);
    },
    warn(msg: string, data?: Record<string, unknown>): void {
      if (data) scoped.warn(msg, data);
      else scoped.warn(msg);
    },
    error(msg: string, data?: Record<string, unknown>): void {
      if (data) scoped.error(msg, data);
      else scoped.error(msg);
    },
    debug(msg: string, data?: Record<string, unknown>): void {
      if (data) scoped.debug(msg, data);
      else scoped.debug(msg);
    },
    child(bindings: Record<string, unknown>): Logger {
      const childComponent = (bindings.component as string) ?? component;
      return createLoggerImpl(childComponent);
    },
  };
}

/**
 * Create a logger for a specific component.
 *
 * @param component — short name shown in log output (e.g. "main", "ipc", "updater")
 */
export function createLogger(component: string): Logger {
  return createLoggerImpl(component);
}

// ---------------------------------------------------------------------------
// Log file utilities
// ---------------------------------------------------------------------------

/** Returns the absolute path to the current log file. */
export function getLogFilePath(): string {
  return log.transports.file.getFile().path;
}

/** Read the last N lines from the current log file. */
export async function readRecentLogs(lines = 200): Promise<string> {
  const logPath = getLogFilePath();
  try {
    const content = await fs.promises.readFile(logPath, "utf-8");
    const allLines = content.split("\n");
    return allLines.slice(-lines).join("\n");
  } catch {
    return "";
  }
}
