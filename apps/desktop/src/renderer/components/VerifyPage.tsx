/**
 * VerifyPage — credential verification with detailed check results.
 *
 * Supports:
 *  - Pasting credential JSON directly into a textarea
 *  - Loading a credential from a file via native dialog
 *  - Drag-and-drop of .json files onto the input area
 *  - Verifying the credential and displaying per-check results
 *  - Downloading a verification report (plain-text)
 *  - Session-scoped recent verification history (last 5)
 *
 * Verification happens in the main process via IPC. When offline,
 * only signature and date checks are possible. Revocation checks
 * require connectivity and show appropriate messaging.
 */

import { useState, useCallback, type DragEvent } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface VerificationCheck {
  name: string;
  passed: boolean;
  detail?: string;
}

type VerificationStatus = "VALID" | "INVALID" | "EXPIRED" | "ERROR";

interface VerificationHistoryEntry {
  id: string;
  credential: string;
  status: VerificationStatus;
  issuer: string;
  timestamp: string;
  checks: VerificationCheck[];
  message: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function statusToBadgeVariant(
  status: VerificationStatus,
): "success" | "error" | "warning" {
  switch (status) {
    case "VALID":
      return "success";
    case "EXPIRED":
      return "warning";
    case "INVALID":
    case "ERROR":
      return "error";
  }
}

function deriveStatus(valid: boolean, checks: VerificationCheck[]): VerificationStatus {
  if (valid) return "VALID";
  const hasExpired = checks.some(
    (c) => !c.passed && c.name.toLowerCase().includes("expir"),
  );
  if (hasExpired) return "EXPIRED";
  return "INVALID";
}

const CHECK_HINTS: Record<string, string> = {
  'signature': 'Confirms the credential was digitally sealed by the issuer',
  'not-before': 'The credential\'s start date has passed',
  'expiry': 'The credential has not expired',
  'revocation': 'The credential has not been revoked',
  'context': 'The credential\'s context is valid and resolvable',
};

function getCheckHint(checkName: string): string | undefined {
  const lower = checkName.toLowerCase();
  for (const [key, hint] of Object.entries(CHECK_HINTS)) {
    if (lower.includes(key)) return hint;
  }
  return undefined;
}

function getErrorHint(message: string): string | null {
  if (!message) return null;
  const lower = message.toLowerCase();
  if (lower.includes("no proof found") || lower.includes("missing a proof") || lower.includes("proof is missing")) {
    return "This document is missing a digital seal. Make sure you received the complete credential file.";
  }
  if (lower.includes("context") && (lower.includes("missing") || lower.includes("not found") || lower.includes("could not"))) {
    return "The credential references a context that could not be found. This may mean the issuer's context is not published.";
  }
  if (lower.includes("failed") || lower.includes("invalid") || lower.includes("error")) {
    return "If you copied the text, make sure you copied the entire content including all brackets.";
  }
  return null;
}

/** Extract the issuer DID from a credential JSON string. */
function extractIssuerDid(credentialJson: string): string {
  try {
    const parsed = JSON.parse(credentialJson);
    if (typeof parsed.issuer === "string") return parsed.issuer;
    if (typeof parsed.issuer === "object" && parsed.issuer?.id) return parsed.issuer.id;
  } catch {
    // not valid JSON
  }
  return "Unknown";
}

/** Generate a unique ID for history entries. */
let historyCounter = 0;
function nextHistoryId(): string {
  historyCounter += 1;
  return `vh-${Date.now()}-${historyCounter}`;
}

/** Format a date as YYYY-MM-DD for filename. */
function formatDateForFilename(date: Date): string {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, "0");
  const d = String(date.getDate()).padStart(2, "0");
  return `${y}-${m}-${d}`;
}

/** Format a date/time for display in reports. */
function formatDateTime(date: Date): string {
  return date.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Build a plain-text verification report. */
function buildReport(
  credential: string,
  status: VerificationStatus,
  resultMessage: string,
  verificationChecks: VerificationCheck[],
  verifiedAt: Date,
): string {
  // Parse once and derive issuer + subject from the parsed object
  let parsed: Record<string, unknown> | null = null;
  try { parsed = JSON.parse(credential) as Record<string, unknown>; } catch { /* ignore */ }

  const issuer = parsed
    ? (typeof parsed.issuer === "string" ? parsed.issuer : (parsed.issuer as Record<string, unknown> | undefined)?.id as string ?? "Unknown")
    : "Unknown";
  const subject = parsed?.credentialSubject as Record<string, unknown> | null ?? null;

  const lines: string[] = [];
  lines.push("===============================================");
  lines.push("       OPENCRED VERIFICATION REPORT");
  lines.push("===============================================");
  lines.push("");
  lines.push(`Date/Time:  ${formatDateTime(verifiedAt)}`);
  lines.push(`Result:     ${status}`);
  lines.push(`Summary:    ${resultMessage}`);
  lines.push("");
  lines.push("-----------------------------------------------");
  lines.push("ISSUER");
  lines.push("-----------------------------------------------");
  lines.push(`DID: ${issuer}`);
  lines.push("");

  if (subject) {
    lines.push("-----------------------------------------------");
    lines.push("CREDENTIAL SUBJECT");
    lines.push("-----------------------------------------------");
    for (const [key, value] of Object.entries(subject)) {
      if (key === "id") {
        lines.push(`  ${key}: ${String(value)}`);
      } else if (typeof value === "object" && value !== null) {
        lines.push(`  ${key}: ${JSON.stringify(value)}`);
      } else {
        lines.push(`  ${key}: ${String(value)}`);
      }
    }
    lines.push("");
  }

  if (verificationChecks.length > 0) {
    lines.push("-----------------------------------------------");
    lines.push("VERIFICATION CHECKS");
    lines.push("-----------------------------------------------");
    for (const check of verificationChecks) {
      const icon = check.passed ? "[PASS]" : "[FAIL]";
      lines.push(`  ${icon} ${check.name}`);
      if (check.detail) {
        lines.push(`         ${check.detail}`);
      }
    }
    lines.push("");
  }

  lines.push("-----------------------------------------------");
  lines.push("RAW CREDENTIAL (abbreviated)");
  lines.push("-----------------------------------------------");
  try {
    const parsed = JSON.parse(credential);
    const pretty = JSON.stringify(parsed, null, 2);
    // Truncate very long credentials in the report
    if (pretty.length > 3000) {
      lines.push(pretty.slice(0, 3000));
      lines.push(`... (${pretty.length - 3000} characters omitted)`);
    } else {
      lines.push(pretty);
    }
  } catch {
    const truncated = credential.length > 3000
      ? credential.slice(0, 3000) + `\n... (${credential.length - 3000} characters omitted)`
      : credential;
    lines.push(truncated);
  }

  lines.push("");
  lines.push("===============================================");
  lines.push("Generated by OpenCred Desktop");
  lines.push("===============================================");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_HISTORY = 5;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function VerifyPage() {
  const [credential, setCredential] = useState("");
  const [valid, setValid] = useState<boolean | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [checks, setChecks] = useState<VerificationCheck[]>([]);
  const [loading, setLoading] = useState(false);
  const [isOffline, setIsOffline] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);
  const [history, setHistory] = useState<VerificationHistoryEntry[]>([]);
  const [verifiedAt, setVerifiedAt] = useState<Date | null>(null);

  // ------------------------------------------------------------------
  // Drag-and-drop handlers
  // ------------------------------------------------------------------

  const handleDragOver = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDragEnter = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    // Only set false when leaving the drop zone (not entering a child)
    const rect = e.currentTarget.getBoundingClientRect();
    const { clientX, clientY } = e;
    if (
      clientX <= rect.left ||
      clientX >= rect.right ||
      clientY <= rect.top ||
      clientY >= rect.bottom
    ) {
      setIsDragOver(false);
    }
  }, []);

  const handleDrop = useCallback((e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    const files = e.dataTransfer?.files;
    if (!files || files.length === 0) return;

    const file = files[0];
    // Accept .json, .jsonld, or any file that looks like JSON
    const validExtensions = [".json", ".jsonld"];
    const hasValidExt = validExtensions.some((ext) =>
      file.name.toLowerCase().endsWith(ext),
    );

    if (!hasValidExt) {
      // Silently ignore non-JSON files
      return;
    }

    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target?.result;
      if (typeof content === "string" && content.trim()) {
        setCredential(content);
        setValid(null);
        setMessage(null);
        setChecks([]);
      }
    };
    reader.readAsText(file);
  }, []);

  // ------------------------------------------------------------------
  // Handlers
  // ------------------------------------------------------------------

  async function handleVerify() {
    if (!credential.trim()) return;

    setLoading(true);
    setValid(null);
    setMessage(null);
    setChecks([]);

    const now = new Date();
    setVerifiedAt(now);

    try {
      // Check connectivity for user messaging
      try {
        const offline = await window.opencred.getOfflineStatus();
        setIsOffline(offline);
      } catch {
        setIsOffline(true);
      }

      const response = await window.opencred.verifyCredential({ credential });

      if (response.success) {
        const isValid = response.valid ?? false;
        const msg = response.message ?? (isValid ? "Valid." : "Invalid.");
        const responseChecks = response.checks ?? [];

        setValid(isValid);
        setMessage(msg);
        setChecks(responseChecks);

        // Add to history
        const derivedStatus = deriveStatus(isValid, responseChecks);
        const issuer = extractIssuerDid(credential);
        const entry: VerificationHistoryEntry = {
          id: nextHistoryId(),
          credential,
          status: derivedStatus,
          issuer,
          timestamp: now.toISOString(),
          checks: responseChecks,
          message: msg,
        };
        setHistory((prev) => [entry, ...prev].slice(0, MAX_HISTORY));
      } else {
        const errMsg = response.error ?? "Verification failed.";
        setValid(false);
        setMessage(errMsg);

        // Add failed verification to history
        const issuer = extractIssuerDid(credential);
        const entry: VerificationHistoryEntry = {
          id: nextHistoryId(),
          credential,
          status: "ERROR",
          issuer,
          timestamp: now.toISOString(),
          checks: [],
          message: errMsg,
        };
        setHistory((prev) => [entry, ...prev].slice(0, MAX_HISTORY));
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : "Verification failed.";
      setValid(false);
      setMessage(errMsg);
    } finally {
      setLoading(false);
    }
  }

  async function handleLoadFile() {
    try {
      const result = await window.opencred.openFile({
        title: "Load Verifiable Credential",
        filters: [
          { name: "JSON", extensions: ["json", "jsonld"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (result.content) {
        setCredential(result.content);
        setValid(null);
        setMessage(null);
        setChecks([]);
      }
    } catch {
      // User cancelled
    }
  }

  function handleClear() {
    setCredential("");
    setValid(null);
    setMessage(null);
    setChecks([]);
    setVerifiedAt(null);
  }

  async function handleDownloadReport() {
    if (status === null || !message || !verifiedAt) return;

    const report = buildReport(credential, status, message, checks, verifiedAt);
    const filename = `verification-report-${formatDateForFilename(verifiedAt)}.txt`;

    try {
      await window.opencred.saveFile({
        defaultName: filename,
        content: report,
        filters: [
          { name: "Text", extensions: ["txt"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });
    } catch {
      // User cancelled the save dialog
    }
  }

  function handleLoadFromHistory(entry: VerificationHistoryEntry) {
    setCredential(entry.credential);
    setValid(null);
    setMessage(null);
    setChecks([]);
    setVerifiedAt(null);
  }

  // ------------------------------------------------------------------
  // Derived state
  // ------------------------------------------------------------------

  const status: VerificationStatus | null =
    valid !== null ? deriveStatus(valid, checks) : null;

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  return (
    <div className="space-y-4">
      {/* Input with drag-and-drop */}
      <Card className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="oc-card-label">Input</h2>
          <div className="flex gap-2">
            <button
              onClick={() => void handleLoadFile()}
              className="rounded-md bg-gray-100 px-3 py-1.5 text-xs text-gray-700 hover:bg-gray-200"
            >
              Upload File
            </button>
            {credential && (
              <button
                onClick={handleClear}
                className="rounded-md bg-gray-100 px-3 py-1.5 text-xs text-gray-500 hover:bg-gray-200"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {!credential && (
          <p className="text-xs text-gray-500">
            You can get this from the person or organization that issued the credential.
          </p>
        )}

        <div
          className="relative"
          onDragOver={handleDragOver}
          onDragEnter={handleDragEnter}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          <textarea
            rows={8}
            value={credential}
            onChange={(e) => {
              setCredential(e.target.value);
              setValid(null);
              setMessage(null);
              setChecks([]);
            }}
            placeholder="Paste credential text here, drag a .json file, or use 'Upload File'"
            className={`block w-full rounded-md border px-3 py-2 font-mono text-xs shadow-sm transition-colors duration-150 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 ${
              isDragOver
                ? "border-2 border-dashed border-blue-400 bg-blue-50"
                : "border-gray-300"
            }`}
          />
          {isDragOver && (
            <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-md bg-blue-50/80">
              <p className="text-sm font-medium text-blue-600">
                Drop credential file here
              </p>
            </div>
          )}
        </div>

        <Button
          onClick={() => void handleVerify()}
          disabled={!credential.trim() || loading}
        >
          {loading ? "Verifying..." : "Verify"}
        </Button>
      </Card>

      {/* Overall result */}
      {status !== null && message && (
        <Card
          className={`space-y-3 ${
            status === "VALID"
              ? "border-green-200 bg-green-50"
              : status === "EXPIRED"
                ? "border-amber-200 bg-amber-50"
                : "border-red-200 bg-red-50"
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Badge variant={statusToBadgeVariant(status)}>{status}</Badge>
              <p
                className={`text-sm font-medium ${
                  status === "VALID"
                    ? "text-green-800"
                    : status === "EXPIRED"
                      ? "text-amber-800"
                      : "text-red-800"
                }`}
              >
                {status === "VALID"
                  ? "Valid Credential"
                  : status === "EXPIRED"
                    ? "Expired Credential"
                    : "Invalid Credential"}
              </p>
            </div>
            <button
              onClick={() => void handleDownloadReport()}
              className="rounded-md bg-white/80 px-3 py-1.5 text-xs font-medium text-gray-700 shadow-sm ring-1 ring-gray-200 hover:bg-white hover:ring-gray-300 transition-colors"
            >
              Download Report
            </button>
          </div>
          <p
            className={`text-sm ${
              status === "VALID"
                ? "text-green-700"
                : status === "EXPIRED"
                  ? "text-amber-700"
                  : "text-red-700"
            }`}
          >
            {message}
          </p>
          {status !== "VALID" && message && getErrorHint(message) && (
            <p className="mt-1 text-xs text-gray-500">
              {getErrorHint(message)}
            </p>
          )}
        </Card>
      )}

      {/* Per-check results */}
      {checks.length > 0 && (
        <Card className="space-y-3">
          <h3 className="oc-card-label">Verification Checks</h3>
          <div className="space-y-2">
            {checks.map((check, i) => {
              const hint = getCheckHint(check.name);
              return (
                <div
                  key={i}
                  className={`flex items-start gap-3 rounded-md border px-3 py-2.5 ${
                    check.passed
                      ? "border-green-200 bg-green-50"
                      : "border-red-200 bg-red-50"
                  }`}
                >
                  <span
                    className={`flex-shrink-0 mt-0.5 text-xs font-semibold ${
                      check.passed ? "text-green-600" : "text-red-600"
                    }`}
                  >
                    {check.passed ? "PASS" : "FAIL"}
                  </span>
                  <div className="min-w-0">
                    <span className="text-xs font-medium text-gray-700">
                      {check.name}
                    </span>
                    {hint && (
                      <p className="mt-0.5 text-xs text-gray-400">{hint}</p>
                    )}
                    {check.detail && (
                      <p className="mt-0.5 text-xs text-gray-500">{check.detail}</p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* Offline warning */}
      {isOffline && valid !== null && (
        <Card className="border-amber-200 bg-amber-50">
          <p className="text-xs text-amber-700">
            You are offline. Only signature and date checks were performed. Revocation
            status could not be verified.
          </p>
        </Card>
      )}

      {/* Recent verifications (session-only) */}
      {history.length > 0 && (
        <Card variant="neutral" className="space-y-3">
          <h3 className="oc-card-label">Recent Verifications</h3>
          <div className="space-y-1.5">
            {history.map((entry) => (
              <button
                key={entry.id}
                onClick={() => handleLoadFromHistory(entry)}
                className="flex w-full items-center gap-3 rounded-md border border-gray-100 px-3 py-2 text-left transition-colors hover:bg-gray-50"
              >
                <span
                  className={`flex-shrink-0 text-[0.6rem] font-mono font-semibold uppercase ${
                    entry.status === "VALID"
                      ? "text-green-600"
                      : entry.status === "EXPIRED"
                        ? "text-amber-600"
                        : "text-red-600"
                  }`}
                >
                  {entry.status === "VALID"
                    ? "VALID"
                    : entry.status === "EXPIRED"
                      ? "EXPD"
                      : "INVLD"}
                </span>
                <span className="min-w-0 flex-1 truncate text-xs text-gray-700">
                  {entry.issuer}
                </span>
                <span className="flex-shrink-0 text-[0.6rem] text-gray-400">
                  {new Date(entry.timestamp).toLocaleTimeString(undefined, {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
              </button>
            ))}
          </div>
          <p className="text-[0.6rem] text-gray-400">
            Click to reload a credential. History is session-only and not persisted.
          </p>
        </Card>
      )}
    </div>
  );
}
