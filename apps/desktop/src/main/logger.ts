/**
 * Persistent structured logger for the Electron main process.
 *
 * Backed by electron-log — writes to rotating log files at platform-standard
 * paths (~/Library/Logs on macOS, %APPDATA%/logs on Windows, ~/.config/logs
 * on Linux). Logs persist across app restarts.
 *
 * SECURITY NOTES:
 *  - A redaction hook strips PEM blocks, long base64/base64url blobs, and
 *    JWK "d" (private key) fields before anything reaches disk. Buffers and
 *    typed arrays are replaced with length-only summaries.
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

// JWK "d" field redaction. Covers several quoting/shape variants:
//  - JSON double-quoted: "d":"..."
//  - Single-quoted (e.g. JS object literal in error messages): 'd':'...'
//  - URL-encoded form (e.g. d=...&x=...): d=<base64url-chars> up to the
//    next ampersand or whitespace.
const JWK_D_FIELD_JSON_RE = /"d"\s*:\s*"[^"]+"/g;
const JWK_D_FIELD_SINGLE_RE = /'d'\s*:\s*'[^']+'/g;
const JWK_D_FIELD_URL_RE = /(^|[?&])d=[A-Za-z0-9_\-+/%=]+/g;

// Long base64/base64url blob redaction.
//
// Prior to #330 this required "+" to be present (to disambiguate standard
// base64 from URL path segments or DIDs). That heuristic missed base64url
// encodings — JWK private-key blobs and most private-key serialisations —
// which use "-" and "_" instead of "+" and "/" and therefore never
// triggered the old pattern.
//
// The new pattern matches any run of >=40 chars from the combined alphabet
// (base64 *and* base64url) followed by optional "=" padding. To avoid
// mauling legitimate strings such as URLs, we skip strings that contain
// "://" or look like filesystem paths. DIDs are protected before the pass
// runs (see `redact`) and restored after.
const LONG_BASE64_ANY_RE = /[A-Za-z0-9_\-+/]{40,}={0,3}/g;

/** True if `s` looks like a URL (contains a scheme separator). */
function looksLikeUrl(s: string): boolean {
  return s.includes("://");
}

/** True if `s` looks like an absolute filesystem path with an extension. */
function looksLikePath(s: string): boolean {
  return /^([A-Za-z]:|[/\\])[A-Za-z0-9_.\-/\\]+\.[A-Za-z0-9]{1,6}$/.test(s.trim());
}

/** Regex matching a full DID identifier or verification method ID. */
const DID_RE = /did:[a-zA-Z0-9]+:[A-Za-z0-9._\-:%#?=]+/g;

export function redact(input: string): string {
  // Step 1: strip PEM blocks and JWK "d" fields first. These always indicate
  // key material regardless of context.
  let result = input
    .replace(PEM_BLOCK_RE, "[REDACTED-PEM]")
    .replace(JWK_D_FIELD_JSON_RE, '"d":"[REDACTED]"')
    .replace(JWK_D_FIELD_SINGLE_RE, "'d':'[REDACTED]'")
    .replace(JWK_D_FIELD_URL_RE, (_match, lead: string | undefined) => `${lead ?? ""}d=[REDACTED]`);

  // Step 2: skip the base64url pass entirely if the string looks like a URL
  // or an absolute filesystem path. Both contain long runs from the base64
  // alphabet that are not key material.
  if (looksLikeUrl(result) || looksLikePath(result)) {
    return result;
  }

  // Step 3: protect DID identifiers before the base64url pass runs. DIDs are
  // public identifiers and MUST remain readable in logs — they are the
  // fingerprint we want to see. We replace each DID with a placeholder token
  // that is not in the base64 alphabet, run the redaction pass, and then
  // restore the DIDs.
  const dids: string[] = [];
  result = result.replace(DID_RE, (match) => {
    dids.push(match);
    return `\u0000DID${dids.length - 1}\u0000`;
  });

  // Step 4: base64url redaction pass.
  result = result.replace(LONG_BASE64_ANY_RE, "[REDACTED]");

  // Step 5: restore the protected DIDs.
  // eslint-disable-next-line no-control-regex
  result = result.replace(/\u0000DID(\d+)\u0000/g, (_match, idx: string) => {
    const n = parseInt(idx, 10);
    return dids[n] ?? "[REDACTED]";
  });

  return result;
}

/**
 * Redact a Buffer or Uint8Array to a length-only summary, never exposing
 * its contents. This is the defence-in-depth path for the case where a
 * future code change accidentally passes raw key material as a log field.
 */
export function redactBuffer(value: Buffer | Uint8Array): string {
  return `[BUFFER len=${value.byteLength}]`;
}

export function redactValue(value: unknown): unknown {
  if (typeof value === "string") return redact(value);
  if (Buffer.isBuffer(value)) return redactBuffer(value);
  if (value instanceof Uint8Array) return redactBuffer(value);
  if (Array.isArray(value)) return value.map((v) => redactValue(v));
  if (typeof value === "object" && value !== null) {
    const result: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      result[k] = redactValue(v);
    }
    return result;
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
