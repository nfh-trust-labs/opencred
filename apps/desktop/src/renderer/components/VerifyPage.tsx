/**
 * VerifyPage — credential verification with detailed check results.
 *
 * Supports:
 *  - Pasting credential JSON directly into a textarea
 *  - Loading a credential from a file via native dialog
 *  - Drag-and-drop of .json files onto the input area
 *  - Scanning QR codes via camera or image file
 *  - Pasting encoded QR strings (PixelPass QR data, JWT, SD-JWT)
 *  - Verifying the credential and displaying per-check results
 *  - Downloading a verification report (plain-text)
 *  - Session-scoped recent verification history (last 5)
 *
 * Verification happens in the main process via IPC. When offline,
 * only signature and date checks are possible. Revocation checks
 * require connectivity and show appropriate messaging.
 */

import { useState, useCallback, useRef, useEffect, type DragEvent } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { Badge } from "./ui/Badge";

// ---------------------------------------------------------------------------
// Input mode types
// ---------------------------------------------------------------------------

type InputMode = "paste-json" | "upload-file" | "scan-qr" | "paste-qr-string";

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

function statusToBadgeVariant(status: VerificationStatus): "success" | "error" | "warning" {
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
  const hasExpired = checks.some((c) => !c.passed && c.name.toLowerCase().includes("expir"));
  if (hasExpired) return "EXPIRED";
  return "INVALID";
}

const CHECK_HINTS: Record<string, string> = {
  signature: "Confirms the credential was digitally sealed by the issuer",
  "not-before": "The credential's start date has passed",
  expiry: "The credential has not expired",
  revocation: "The credential has not been revoked",
  context: "The credential's context is valid and resolvable",
  keyrotation: "Whether the issuer has rotated to a new signing key",
  registryanchor: "Whether the issuer's DID record is anchored on the CORD blockchain",
};

/**
 * Per-check advisory list — these checks contribute information to the
 * verifier UI but do NOT count against the headline VALID/INVALID outcome.
 * Failed advisory checks render with neutral amber styling instead of red
 * to communicate "still cryptographically valid, but worth knowing" rather
 * than "rejected".
 */
const ADVISORY_CHECK_NAMES = new Set(["keyRotation", "registryAnchor"]);

/**
 * Issuer key status shown as a distinct badge above the per-check list.
 *
 * - `"current"`  — DeDi reports `keyStatus: "current"` for this DID.
 * - `"rotated"`  — DeDi reports the issuer has rotated to a new key
 *                  (credential is still cryptographically valid against
 *                  the old key).
 * - `"unknown"`  — no DeDi lookup happened (verifier offline, no client,
 *                  or no DID extracted). The badge is hidden in this
 *                  case; the issuer DID itself is shown in the
 *                  credential body for the user to read directly.
 */
type AttributionState = "current" | "rotated" | "unknown";

/**
 * Derive a single key-status summary from the checks array.
 *
 * Priority order:
 *   1. keyRotation failure → red "Rotated" badge (issuer rotated away)
 *   2. keyRotation passed (DeDi present) → green "Current" badge
 *   3. no keyRotation check ran → "unknown" — render no badge
 */
function deriveAttributionBadge(checks: VerificationCheck[]): {
  state: AttributionState;
  message?: string;
} {
  const rotation = checks.find((c) => c.name === "keyRotation");
  if (!rotation) return { state: "unknown" };
  if (rotation.passed) return { state: "current", message: rotation.detail };
  return { state: "rotated", message: rotation.detail };
}

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
  if (
    lower.includes("no proof found") ||
    lower.includes("missing a proof") ||
    lower.includes("proof is missing")
  ) {
    return "This document is missing a digital seal. Make sure you received the complete credential file.";
  }
  if (
    lower.includes("context") &&
    (lower.includes("missing") || lower.includes("not found") || lower.includes("could not"))
  ) {
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
  let parsed: Record<string, unknown> | null = null;
  try {
    parsed = JSON.parse(credential) as Record<string, unknown>;
  } catch {
    /* ignore */
  }

  const issuer = parsed
    ? typeof parsed.issuer === "string"
      ? parsed.issuer
      : (((parsed.issuer as Record<string, unknown> | undefined)?.id as string) ?? "Unknown")
    : "Unknown";
  const subject = (parsed?.credentialSubject as Record<string, unknown> | null) ?? null;

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
    if (pretty.length > 3000) {
      lines.push(pretty.slice(0, 3000));
      lines.push(`... (${pretty.length - 3000} characters omitted)`);
    } else {
      lines.push(pretty);
    }
  } catch {
    const truncated =
      credential.length > 3000
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
  const [inputMode, setInputMode] = useState<InputMode>("paste-json");
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [scannerActive, setScannerActive] = useState(false);
  const scannerRef = useRef<{ stop: () => Promise<void>; clear: () => void } | null>(null);
  const scannerContainerRef = useRef<HTMLDivElement | null>(null);

  const stopScanner = useCallback(async () => {
    if (scannerRef.current) {
      try {
        await scannerRef.current.stop();
        scannerRef.current.clear();
      } catch {
        // scanner may already be stopped
      }
      scannerRef.current = null;
    }
    setScannerActive(false);
  }, []);

  const startScanner = useCallback(async () => {
    setCameraError(null);
    try {
      const { Html5Qrcode } = await import("html5-qrcode");
      const containerId = "qr-scanner-container";
      const scanner = new Html5Qrcode(containerId);
      scannerRef.current = scanner;

      await scanner.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: { width: 250, height: 250 } },
        (decodedText) => {
          void scanner.stop().then(() => {
            scanner.clear();
            scannerRef.current = null;
            setScannerActive(false);
            setCredential(decodedText);
            setValid(null);
            setMessage(null);
            setChecks([]);
          });
        },
        () => {},
      );
      setScannerActive(true);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("NotAllowedError") || msg.includes("Permission")) {
        setCameraError(
          "Camera permission denied. Please allow camera access in your system settings.",
        );
      } else if (msg.includes("NotFoundError") || msg.includes("no camera")) {
        setCameraError("No camera found. Please connect a camera and try again.");
      } else {
        setCameraError(`Camera error: ${msg}`);
      }
      setScannerActive(false);
    }
  }, []);

  useEffect(() => {
    if (inputMode !== "scan-qr") {
      void stopScanner();
    }
    return () => {
      void stopScanner();
    };
  }, [inputMode, stopScanner]);

  async function handleImageQrDecode(file: File) {
    try {
      const { Html5Qrcode } = await import("html5-qrcode");
      // `scanFile` is an instance method; the older `Html5Qrcode.scanFile`
      // static-form compiled against some earlier typings but does not
      // actually exist on the class in html5-qrcode ≥2.3. Use an instance
      // pointed at a throwaway off-DOM element — no scanner UI is needed
      // for a file decode.
      const host = document.createElement("div");
      host.style.display = "none";
      host.id = `qr-file-scan-${Date.now()}`;
      document.body.appendChild(host);
      const scanner = new Html5Qrcode(host.id);
      try {
        const decoded = await scanner.scanFile(file, false);
        setCredential(decoded);
        setValid(null);
        setMessage(null);
        setChecks([]);
      } finally {
        host.remove();
      }
    } catch {
      setMessage(
        "Could not decode a QR code from this image. Make sure the image contains a clear QR code.",
      );
      setValid(false);
    }
  }

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
    const validExtensions = [".json", ".jsonld"];
    const hasValidExt = validExtensions.some((ext) => file.name.toLowerCase().endsWith(ext));

    if (!hasValidExt) {
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

  async function handleVerify() {
    if (!credential.trim()) return;

    setLoading(true);
    setValid(null);
    setMessage(null);
    setChecks([]);

    const now = new Date();
    setVerifiedAt(now);

    try {
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
      const isImageMode = inputMode === "upload-file";
      const result = await window.opencred.openFile({
        title: isImageMode
          ? "Load Credential, PDF, or QR Code Image"
          : "Load Verifiable Credential",
        filters: isImageMode
          ? [
              { name: "JSON", extensions: ["json", "jsonld"] },
              { name: "PDF certificate", extensions: ["pdf"] },
              { name: "Images", extensions: ["png", "jpg", "jpeg", "gif", "bmp", "webp"] },
              { name: "All Files", extensions: ["*"] },
            ]
          : [
              { name: "JSON", extensions: ["json", "jsonld"] },
              { name: "All Files", extensions: ["*"] },
            ],
      });

      if (result.filePath && result.content) {
        const ext = result.filePath.toLowerCase();
        const isPdf = ext.endsWith(".pdf");
        const isImage = [".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"].some((e) =>
          ext.endsWith(e),
        );
        // PDF: route through verifyCredential's `pdfBase64` branch. The
        // base64 payload travels as-is over IPC; the main process decodes
        // and runs `verifyPdf`. We immediately call handleVerifyPdf rather
        // than stashing the bytes into `credential`, since the textarea
        // is for text-shaped formats only.
        if (isPdf && result.encoding === "base64") {
          await handleVerifyPdf(result.content);
          return;
        }
        if (isImage && result.encoding === "base64") {
          const binary = Uint8Array.from(atob(result.content), (c) => c.charCodeAt(0));
          const file = new File([binary], result.filePath.split("/").pop() ?? "image.png");
          await handleImageQrDecode(file);
          return;
        }
        setCredential(result.content);
        setValid(null);
        setMessage(null);
        setChecks([]);
      } else if (result.content) {
        setCredential(result.content);
        setValid(null);
        setMessage(null);
        setChecks([]);
      }
    } catch {
      // User cancelled
    }
  }

  /**
   * Verify a PDF certificate by sending its base64-encoded bytes to the
   * main process. Mirrors `handleVerify` for state side-effects so the
   * result panel renders the same way regardless of input form.
   *
   * @internal
   */
  async function handleVerifyPdf(pdfBase64: string) {
    setLoading(true);
    setValid(null);
    setMessage(null);
    setChecks([]);
    setCredential("");

    const now = new Date();
    setVerifiedAt(now);

    try {
      try {
        const offline = await window.opencred.getOfflineStatus();
        setIsOffline(offline);
      } catch {
        setIsOffline(true);
      }

      const response = await window.opencred.verifyCredential({ pdfBase64 });
      if (response.success) {
        const isValid = response.valid ?? false;
        const msg = response.message ?? (isValid ? "Valid." : "PDF verification did not succeed.");
        const responseChecks = response.checks ?? [];
        setValid(isValid);
        setMessage(msg);
        setChecks(responseChecks);
      } else {
        setValid(false);
        setMessage(response.error ?? "PDF verification failed.");
      }
    } catch (err) {
      setValid(false);
      setMessage(err instanceof Error ? err.message : "PDF verification failed.");
    } finally {
      setLoading(false);
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

  const status: VerificationStatus | null = valid !== null ? deriveStatus(valid, checks) : null;

  return (
    <div className="space-y-4">
      <Card className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="oc-card-label">Input</h2>
          {credential && (
            <button
              onClick={handleClear}
              className="rounded-md bg-surface-warm px-3 py-1.5 text-xs text-txt-muted hover:bg-gray-200"
            >
              Clear
            </button>
          )}
        </div>

        {/* Mode selector tabs */}
        <div className="flex gap-1 rounded-lg bg-surface-warm p-1">
          {(
            [
              { key: "paste-json", label: "Paste JSON" },
              { key: "upload-file", label: "Upload File" },
              { key: "scan-qr", label: "Scan QR" },
              { key: "paste-qr-string", label: "Paste QR String" },
            ] as const
          ).map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setInputMode(key)}
              className={`flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
                inputMode === key
                  ? "bg-white text-txt-primary shadow-sm"
                  : "text-txt-muted hover:text-txt-secondary"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {!credential && inputMode !== "scan-qr" && (
          <p className="text-xs text-txt-muted">
            You can get this from the person or organization that issued the credential.
          </p>
        )}

        {inputMode === "paste-json" && (
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
              placeholder="Paste credential JSON here, or drag a .json file onto this area"
              className={`block w-full rounded-md border px-3 py-2 font-mono text-xs shadow-sm transition-colors duration-150 focus:border-brand focus:ring-1 focus:ring-blue-500 ${
                isDragOver ? "border-2 border-dashed border-blue-400 bg-brand-light" : "border-border"
              }`}
            />
            {isDragOver && (
              <div className="pointer-events-none absolute inset-0 flex items-center justify-center rounded-md bg-brand-light/80">
                <p className="text-sm font-medium text-brand">Drop credential file here</p>
              </div>
            )}
          </div>
        )}

        {inputMode === "upload-file" && (
          <div className="space-y-3">
            <button
              onClick={() => void handleLoadFile()}
              className="w-full rounded-md border-2 border-dashed border-border px-4 py-8 text-center text-sm text-txt-muted hover:border-blue-400 hover:bg-brand-light hover:text-brand transition-colors"
            >
              Click to select a credential file (.json) or QR code image (.png, .jpg)
            </button>
            {credential && (
              <div className="rounded-md border border-border-light bg-surface-warm p-3">
                <p className="text-xs text-txt-muted mb-1">Loaded content:</p>
                <pre className="max-h-32 overflow-auto text-xs font-mono text-txt-secondary">
                  {credential.slice(0, 500)}
                  {credential.length > 500 ? "..." : ""}
                </pre>
              </div>
            )}
          </div>
        )}

        {inputMode === "scan-qr" && (
          <div className="space-y-3">
            <div
              id="qr-scanner-container"
              ref={scannerContainerRef}
              className="w-full overflow-hidden rounded-md bg-black"
              style={{ minHeight: scannerActive ? 300 : 0 }}
            />
            {cameraError && (
              <div className="rounded-md border border-state-danger-border bg-state-danger-bg px-3 py-2">
                <p className="text-xs text-state-danger">{cameraError}</p>
              </div>
            )}
            <div className="flex gap-2">
              {!scannerActive ? (
                <Button onClick={() => void startScanner()}>Start Camera</Button>
              ) : (
                <Button onClick={() => void stopScanner()}>Stop Camera</Button>
              )}
            </div>
            {credential && (
              <div className="rounded-md border border-state-success-border bg-state-success-bg p-3">
                <p className="text-xs text-state-success mb-1">QR code decoded:</p>
                <pre className="max-h-32 overflow-auto text-xs font-mono text-state-success">
                  {credential.slice(0, 500)}
                  {credential.length > 500 ? "..." : ""}
                </pre>
              </div>
            )}
          </div>
        )}

        {inputMode === "paste-qr-string" && (
          <textarea
            rows={8}
            value={credential}
            onChange={(e) => {
              setCredential(e.target.value);
              setValid(null);
              setMessage(null);
              setChecks([]);
            }}
            placeholder="Paste PixelPass QR data, a JWT (eyJ...), or an SD-JWT here"
            className="block w-full rounded-md border border-border px-3 py-2 font-mono text-xs shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500"
          />
        )}

        <Button onClick={() => void handleVerify()} disabled={!credential.trim() || loading}>
          {loading ? "Verifying..." : "Verify"}
        </Button>
      </Card>

      {status !== null && message && (
        <Card
          className={`space-y-3 ${
            status === "VALID"
              ? "border-state-success-border bg-state-success-bg"
              : status === "EXPIRED"
                ? "border-state-warning-border bg-state-warning-bg"
                : "border-state-danger-border bg-state-danger-bg"
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Badge variant={statusToBadgeVariant(status)}>{status}</Badge>
              <p
                className={`text-sm font-medium ${
                  status === "VALID"
                    ? "text-state-success"
                    : status === "EXPIRED"
                      ? "text-state-warning"
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
              className="rounded-md bg-white/80 px-3 py-1.5 text-xs font-medium text-txt-secondary shadow-sm ring-1 ring-gray-200 hover:bg-white hover:ring-gray-300 transition-colors"
            >
              Download Report
            </button>
          </div>
          <p
            className={`text-sm ${
              status === "VALID"
                ? "text-state-success"
                : status === "EXPIRED"
                  ? "text-state-warning"
                  : "text-state-danger"
            }`}
          >
            {message}
          </p>
          {status !== "VALID" && message && getErrorHint(message) && (
            <p className="mt-1 text-xs text-txt-muted">{getErrorHint(message)}</p>
          )}
        </Card>
      )}

      {/* Issuer key-status badge — surfaced separately from the per-check
          list so users can see "is this issuer's key still current?" at a
          glance without parsing the full check details. The headline
          VALID/INVALID badge above is unchanged — it reflects crypto
          correctness only. The issuer DID itself is rendered in the
          credential body where the user can read it directly. */}
      {checks.length > 0 &&
        (() => {
          const attribution = deriveAttributionBadge(checks);
          if (attribution.state === "unknown") return null;
          const palette = {
            current: { border: "border-state-success-border", bg: "bg-state-success-bg", text: "text-state-success" },
            rotated: { border: "border-state-danger-border", bg: "bg-state-danger-bg", text: "text-red-800" },
            unknown: { border: "border-border-light", bg: "bg-surface-warm", text: "text-txt-secondary" },
          }[attribution.state];
          const heading = {
            current: "Issuer key current",
            rotated: "Issuer key rotated",
            unknown: "",
          }[attribution.state];
          return (
            <Card className={`${palette.border} ${palette.bg}`}>
              <div className="space-y-1">
                <p className={`text-sm font-medium ${palette.text}`}>{heading}</p>
                {attribution.message && (
                  <p className={`text-xs ${palette.text} opacity-80`}>{attribution.message}</p>
                )}
              </div>
            </Card>
          );
        })()}

      {checks.length > 0 && (
        <Card className="space-y-3">
          <h3 className="oc-card-label">Verification Checks</h3>
          <div className="space-y-2">
            {checks.map((check, i) => {
              const hint = getCheckHint(check.name);
              const isAdvisory = ADVISORY_CHECK_NAMES.has(check.name);
              // Advisory check failures render amber, not red — they
              // surface information but don't reject the credential.
              const failedPalette = isAdvisory
                ? "border-state-warning-border bg-state-warning-bg"
                : "border-state-danger-border bg-state-danger-bg";
              const failedLabel = isAdvisory ? "text-state-warning" : "text-state-danger";
              const failedText = isAdvisory ? "INFO" : "FAIL";
              return (
                <div
                  key={i}
                  className={`flex items-start gap-3 rounded-md border px-3 py-2.5 ${
                    check.passed ? "border-state-success-border bg-state-success-bg" : failedPalette
                  }`}
                >
                  <span
                    className={`flex-shrink-0 mt-0.5 text-xs font-semibold ${
                      check.passed ? "text-state-success" : failedLabel
                    }`}
                  >
                    {check.passed ? "PASS" : failedText}
                  </span>
                  <div className="min-w-0">
                    <span className="text-xs font-medium text-txt-secondary">{check.name}</span>
                    {hint && <p className="mt-0.5 text-xs text-txt-muted">{hint}</p>}
                    {check.detail && <p className="mt-0.5 text-xs text-txt-muted">{check.detail}</p>}
                  </div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {isOffline && valid !== null && (
        <Card className="border-state-warning-border bg-state-warning-bg">
          <p className="text-xs text-state-warning">
            You are offline. Only signature and date checks were performed. Revocation status could
            not be verified.
          </p>
        </Card>
      )}

      {history.length > 0 && (
        <Card variant="neutral" className="space-y-3">
          <h3 className="oc-card-label">Recent Verifications</h3>
          <div className="space-y-1.5">
            {history.map((entry) => (
              <button
                key={entry.id}
                onClick={() => handleLoadFromHistory(entry)}
                className="flex w-full items-center gap-3 rounded-md border border-border-light px-3 py-2 text-left transition-colors hover:bg-surface-warm"
              >
                <span
                  className={`flex-shrink-0 text-body-2xs font-mono font-semibold uppercase ${
                    entry.status === "VALID"
                      ? "text-state-success"
                      : entry.status === "EXPIRED"
                        ? "text-amber-600"
                        : "text-state-danger"
                  }`}
                >
                  {entry.status === "VALID"
                    ? "VALID"
                    : entry.status === "EXPIRED"
                      ? "EXPD"
                      : "INVLD"}
                </span>
                <span className="min-w-0 flex-1 truncate text-xs text-txt-secondary">
                  {entry.issuer}
                </span>
                <span className="flex-shrink-0 text-body-2xs text-txt-muted">
                  {new Date(entry.timestamp).toLocaleTimeString(undefined, {
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
              </button>
            ))}
          </div>
          <p className="text-body-2xs text-txt-muted">
            Click to reload a credential. History is session-only and not persisted.
          </p>
        </Card>
      )}
    </div>
  );
}
