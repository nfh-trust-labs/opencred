/**
 * Shape of the sanitized error body emitted to HTTP clients.
 */
export interface OpenCredErrorBody {
  error: {
    code: string;
    message: string;
    [key: string]: unknown;
  };
}

/**
 * Replacement spec: either a literal string or a function that maps the
 * matched substring to a replacement.
 */
type SanitizeReplacement = string | ((match: string) => string);

/**
 * Extract the final path segment (basename) from a POSIX-style path.
 * Used by the POSIX path sanitizer so "/Users/alice/opencred/data/f.bin"
 * is replaced with "[PATH]/f.bin" even though there are multiple segments
 * between "/Users/" and the basename.
 */
function posixBasename(match: string): string {
  const segments = match.split("/").filter(Boolean);
  const basename = segments[segments.length - 1] ?? "";
  return basename.length > 0 ? `[PATH]/${basename}` : "[PATH]";
}

/**
 * Extract the final path segment from a Windows-style path. Same idea
 * as {@link posixBasename} but splits on backslashes.
 */
function windowsBasename(match: string): string {
  const segments = match.split("\\").filter(Boolean);
  const basename = segments[segments.length - 1] ?? "";
  return basename.length > 0 ? `[PATH]\\${basename}` : "[PATH]";
}

/**
 * Regex patterns that match things we refuse to leak into HTTP responses.
 *
 * Each pattern has a replacement. The patterns are applied in order.
 * Order matters — PEM blocks and stack frames are stripped BEFORE
 * path-stripping, because a PEM block contains newlines and characters
 * that would otherwise interact poorly with the path regexes. Hex
 * sanitization runs BEFORE base64 because hex strings are a subset of
 * base64 strings and the base64 pattern would otherwise swallow a
 * fingerprint and label it `[REDACTED_B64]`.
 */
const SANITIZE_PATTERNS: ReadonlyArray<readonly [RegExp, SanitizeReplacement]> = [
  // PEM blocks (private keys, encrypted keys, certificates). Match
  // greedily across newlines so the entire block is redacted.
  [/-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g, "[REDACTED_PEM]"],

  // Stack-trace lines (Node V8 format): "    at functionName (file:line:col)"
  // Strip the whole "at ..." frame; it contains both the file path and
  // internal symbol names. Do this BEFORE path stripping so the frame
  // collapses cleanly.
  [/\s*at\s+[^\n]+\([^)]*\)/g, ""],
  [/\s*at\s+[^\n]+:\d+:\d+/g, ""],

  // POSIX absolute paths — /home/..., /Users/..., /tmp/..., /var/...,
  // /private/..., /opt/..., /srv/..., /root/..., /etc/... — keep only
  // the final basename. A function replacement is used so "a/b/c/f.bin"
  // collapses to "[PATH]/f.bin" without having to spell out a multi-
  // segment capture group.
  [/\/(?:home|Users|tmp|var|private|opt|srv|root|etc|usr|mnt)\/[^\s:"'<>()]+/g, posixBasename],

  // Windows absolute paths: C:\Users\..., D:\Windows\..., etc.
  [
    /[A-Za-z]:\\(?:Users|Windows|Program Files|Program Files \(x86\)|ProgramData|Temp)\\[^\s:"'<>()]+/g,
    windowsBasename,
  ],
  // UNC paths (\\server\share\...)
  [/\\\\[^\s\\"'<>()]+\\[^\s"'<>()]+/g, "[PATH]"],

  // file:// URLs — these embed absolute paths.
  [/file:\/\/[^\s"'<>()]+/g, "[FILE_URL]"],

  // Hex blobs of 40+ chars — likely fingerprints, signatures, keys.
  // 40 chars is the length of a SHA-1 digest. Must run BEFORE the
  // base64 pattern because hex is a subset of base64.
  [/\b[0-9a-fA-F]{40,}\b/g, "[REDACTED_HEX]"],

  // Long base64 blobs (40+ chars) — almost always key material,
  // signatures, or ciphertext. Short base64 (e.g. short IDs under
  // 40 chars) is left alone so legitimate identifiers still surface.
  [/[A-Za-z0-9+/]{40,}={0,2}/g, "[REDACTED_B64]"],
];

/**
 * Maximum length of a sanitized HTTP message. Anything longer is
 * truncated with an ellipsis. Prevents an error handler from being
 * used as an amplifier for large blobs.
 */
const MAX_HTTP_MESSAGE_LENGTH = 512;

/**
 * Scrub a raw error message so it is safe to emit in an HTTP response.
 *
 * Strips:
 * - PEM blocks (any BEGIN/END block)
 * - Stack-trace lines (V8 "at ..." frames)
 * - Absolute filesystem paths (POSIX and Windows)
 * - file:// URLs
 * - Long base64 and hex blobs (likely key material or signatures)
 *
 * Also truncates to MAX_HTTP_MESSAGE_LENGTH, collapses whitespace, and
 * falls back to a generic "An error occurred" if scrubbing empties the
 * message (which only happens if the entire message was redacted).
 *
 * Exported so call sites that need to sanitize an arbitrary string
 * before logging it to a client-facing channel can reuse the same rules.
 */
export function sanitizeErrorMessage(raw: unknown): string {
  if (typeof raw !== "string") {
    return "An error occurred";
  }

  let out = raw;
  for (const [pattern, replacement] of SANITIZE_PATTERNS) {
    if (typeof replacement === "string") {
      out = out.replace(pattern, replacement);
    } else {
      out = out.replace(pattern, replacement);
    }
  }

  // Collapse whitespace runs so multi-line stack traces or split paths
  // don't look ugly.
  out = out.replace(/\s+/g, " ").trim();

  if (out.length > MAX_HTTP_MESSAGE_LENGTH) {
    out = `${out.slice(0, MAX_HTTP_MESSAGE_LENGTH - 3)}...`;
  }

  if (out.length === 0) {
    return "An error occurred";
  }

  return out;
}

/**
 * OpenCred error hierarchy.
 *
 * SECURITY INVARIANT (CLAUDE.md rule 5):
 * Error responses must never leak key material, internal paths, or
 * signing buffers. The OpenCredError hierarchy sanitizes by design.
 *
 * Design:
 * - `.message` holds the original, un-sanitized message the constructor
 *   received. It is still suitable for server-side logging (where the
 *   logger is trusted) and is preserved for backwards compatibility
 *   with callers that read `err.message` directly.
 * - `toJSON()` returns a sanitized HTTP-visible body: the raw message
 *   is scrubbed of filesystem paths, stack-trace lines, PEM blocks, and
 *   long base64 blobs before being emitted. Stack traces are NEVER
 *   included. This is the representation that must be sent over the wire.
 * - `toHttpBody()` is an alias for `toJSON()` preferred in HTTP
 *   middleware because the intent is clearer at the call site.
 *
 * Call sites that build error messages from untrusted `error.message`
 * strings (e.g. Node filesystem errors containing absolute paths) are
 * therefore safe — the path will be scrubbed before it ever reaches an
 * HTTP response body.
 */
/**
 * Canonical error-code strings emitted in `OpenCredErrorBody.error.code`.
 *
 * API consumers should import this object (or `OpenCredErrorCodeValue`)
 * and switch on the resulting union instead of hard-coding string
 * literals. Every subclass constructor passes one of these values as
 * the second argument to the OpenCredError super() call; ad-hoc codes
 * from individual route handlers (e.g. `WEBHOOK_SECRET_REQUIRED`) are
 * NOT part of this enum and SHOULD be consolidated here in a follow-up.
 */
export const OpenCredErrorCode = {
  VALIDATION: "VALIDATION_ERROR",
  AUTHENTICATION: "AUTHENTICATION_ERROR",
  AUTHORIZATION: "AUTHORIZATION_ERROR",
  NOT_FOUND: "NOT_FOUND",
  CONFLICT: "CONFLICT",
  PAYLOAD_TOO_LARGE: "PAYLOAD_TOO_LARGE",
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
  CRYPTO: "CRYPTO_ERROR",
  DID_RESOLUTION: "DID_RESOLUTION_ERROR",
  SCHEMA_VALIDATION: "SCHEMA_VALIDATION_ERROR",
  DELEGATION: "DELEGATION_ERROR",
  DEDI_CLIENT: "DEDI_CLIENT_ERROR",
  SESSION_EXPIRED: "SESSION_EXPIRED",
  VERIFICATION: "VERIFICATION_ERROR",
  NOT_IMPLEMENTED: "NOT_IMPLEMENTED",
} as const;

export type OpenCredErrorCodeValue = (typeof OpenCredErrorCode)[keyof typeof OpenCredErrorCode];

/**
 * String-literal discriminator carried on every OpenCredError subclass.
 *
 * Prefer `err.kind === "CryptoError"` over `err instanceof CryptoError`
 * when the error may cross a realm boundary (Electron IPC, Vitest
 * vi.mock, worker threads). `instanceof` is fragile across realms —
 * `kind` is stable as long as the instance serializes its own-properties.
 */
export type OpenCredErrorKind =
  | "OpenCredError"
  | "ValidationError"
  | "AuthenticationError"
  | "AuthorizationError"
  | "NotFoundError"
  | "ConflictError"
  | "PayloadTooLargeError"
  | "RateLimitError"
  | "CryptoError"
  | "DIDResolutionError"
  | "SchemaValidationError"
  | "DelegationError"
  | "DeDiClientError"
  | "SessionExpiredError"
  | "VerificationError"
  | "NotImplementedError";

export class OpenCredError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly kind: OpenCredErrorKind;

  constructor(
    message: string,
    code: string,
    statusCode: number = 500,
    options?: { cause?: unknown; kind?: OpenCredErrorKind },
  ) {
    // Forward the cause to Error (supported since Node 16.9). The cause is
    // preserved on the .cause property for operator-facing logging and the
    // `toJSON` / `toHttpBody` path still sanitizes the wire payload so the
    // cause does not leak over HTTP.
    super(message, options);
    this.name = "OpenCredError";
    this.code = code;
    this.statusCode = statusCode;
    this.kind = options?.kind ?? "OpenCredError";
    Object.setPrototypeOf(this, new.target.prototype);
  }

  /**
   * Return the sanitized HTTP-visible body for this error.
   *
   * The body contains only `code` and a sanitized `message`. It never
   * contains stack traces, filesystem paths, PEM blocks, or raw key
   * material, even if the underlying `.message` did.
   *
   * Subclasses that want to expose additional safe fields should
   * override this method and call `super.toJSON()` to obtain the
   * sanitized base body first.
   */
  toJSON(): OpenCredErrorBody {
    return {
      error: {
        code: this.code,
        message: sanitizeErrorMessage(this.message),
      },
    };
  }

  /**
   * Explicit alias for `toJSON()` — returns the sanitized HTTP body.
   *
   * Preferred in HTTP middleware because the intent ("this is the body
   * I'm about to send over the wire") is clearer at the call site.
   */
  toHttpBody(): OpenCredErrorBody {
    return this.toJSON();
  }
}

export class ValidationError extends OpenCredError {
  constructor(message: string) {
    super(message, "VALIDATION_ERROR", 400, { kind: "ValidationError" });
    this.name = "ValidationError";
  }
}

export class AuthenticationError extends OpenCredError {
  constructor(message: string = "Authentication required") {
    super(message, "AUTHENTICATION_ERROR", 401, { kind: "AuthenticationError" });
    this.name = "AuthenticationError";
  }
}

export class AuthorizationError extends OpenCredError {
  constructor(message: string = "Insufficient permissions") {
    super(message, "AUTHORIZATION_ERROR", 403, { kind: "AuthorizationError" });
    this.name = "AuthorizationError";
  }
}

export class NotFoundError extends OpenCredError {
  constructor(message: string = "Resource not found") {
    super(message, "NOT_FOUND", 404, { kind: "NotFoundError" });
    this.name = "NotFoundError";
  }
}

export class ConflictError extends OpenCredError {
  constructor(message: string) {
    super(message, "CONFLICT", 409, { kind: "ConflictError" });
    this.name = "ConflictError";
  }
}

export class PayloadTooLargeError extends OpenCredError {
  constructor(message: string = "Payload too large") {
    super(message, "PAYLOAD_TOO_LARGE", 413, { kind: "PayloadTooLargeError" });
    this.name = "PayloadTooLargeError";
  }
}

export class RateLimitError extends OpenCredError {
  constructor(message: string = "Rate limit exceeded") {
    super(message, "RATE_LIMIT_EXCEEDED", 429, { kind: "RateLimitError" });
    this.name = "RateLimitError";
  }
}

export class CryptoError extends OpenCredError {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, "CRYPTO_ERROR", 500, { ...(options ?? {}), kind: "CryptoError" });
    this.name = "CryptoError";
  }
}

export class DIDResolutionError extends OpenCredError {
  constructor(message: string) {
    super(message, "DID_RESOLUTION_ERROR", 500, { kind: "DIDResolutionError" });
    this.name = "DIDResolutionError";
  }
}

export class SchemaValidationError extends OpenCredError {
  public readonly validationErrors: unknown[];

  constructor(message: string, validationErrors: unknown[] = []) {
    super(message, "SCHEMA_VALIDATION_ERROR", 400, { kind: "SchemaValidationError" });
    this.name = "SchemaValidationError";
    this.validationErrors = validationErrors;
  }

  override toJSON(): OpenCredErrorBody {
    const base = super.toJSON();
    return {
      error: {
        ...base.error,
        validationErrors: this.validationErrors,
      },
    };
  }
}

export class DelegationError extends OpenCredError {
  constructor(message: string) {
    super(message, "DELEGATION_ERROR", 400, { kind: "DelegationError" });
    this.name = "DelegationError";
  }
}

export class DeDiClientError extends OpenCredError {
  constructor(message: string, statusCode: number = 502) {
    super(message, "DEDI_CLIENT_ERROR", statusCode, { kind: "DeDiClientError" });
    this.name = "DeDiClientError";
  }
}

export class SessionExpiredError extends OpenCredError {
  constructor(message: string = "Session expired") {
    super(message, "SESSION_EXPIRED", 410, { kind: "SessionExpiredError" });
    this.name = "SessionExpiredError";
  }
}

export class VerificationError extends OpenCredError {
  constructor(message: string) {
    super(message, "VERIFICATION_ERROR", 400, { kind: "VerificationError" });
    this.name = "VerificationError";
  }
}

export class NotImplementedError extends OpenCredError {
  constructor(message: string = "Not implemented") {
    super(message, "NOT_IMPLEMENTED", 501, { kind: "NotImplementedError" });
    this.name = "NotImplementedError";
  }
}

/**
 * Discriminated union of every concrete OpenCredError subclass. Reviewers
 * can `const _: never = err.kind;` in a default clause to enforce
 * exhaustive matching.
 */
export type AnyOpenCredError =
  | OpenCredError
  | ValidationError
  | AuthenticationError
  | AuthorizationError
  | NotFoundError
  | ConflictError
  | PayloadTooLargeError
  | RateLimitError
  | CryptoError
  | DIDResolutionError
  | SchemaValidationError
  | DelegationError
  | DeDiClientError
  | SessionExpiredError
  | VerificationError
  | NotImplementedError;
