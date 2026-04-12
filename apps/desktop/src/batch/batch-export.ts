/**
 * Batch export — creates a ZIP archive of all successfully packaged credentials.
 *
 * Supports JSON-LD, QR PNG, and PDF outputs. Uses the `archiver` npm package
 * for ZIP creation. Works entirely offline.
 *
 * Naming convention: credential-{rowIndex}-{subjectId}.{ext}
 *
 * SECURITY: No key material is involved in export. Only signed credentials
 * and their packaged output are archived.
 */

import { createWriteStream } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";
import { mkdir } from "node:fs/promises";
import archiver from "archiver";
import type { BatchRowResult } from "./batch-engine.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Options for the batch export. */
export interface BatchExportOptions {
  /** The batch row results (only successful rows will be exported). */
  rows: BatchRowResult[];
  /** Output file path for the ZIP. If not provided, a temp file is created. */
  outputPath?: string;
}

/** Result of the batch export. */
export interface BatchExportResult {
  /** Absolute path to the created ZIP file. */
  filePath: string;
  /** Number of credentials exported. */
  credentialCount: number;
  /** Total number of files in the ZIP. */
  fileCount: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Derive a subject identifier from a credential for file naming.
 *
 * Uses the credentialSubject.id, or falls back to the credential ID,
 * or a short random hex string.
 */
function deriveSubjectId(row: BatchRowResult): string {
  // Compact tokens (SD-JWT-VC) don't have structured fields — use random ID
  if (typeof row.credential === "string") {
    return randomBytes(4).toString("hex");
  }

  if (row.credential?.credentialSubject?.id) {
    // Use last segment of DID or full ID, sanitized
    const subjectId = String(row.credential.credentialSubject.id);
    const segment = subjectId.includes(":") ? subjectId.split(":").pop() : subjectId;
    return sanitizeFileName(segment ?? "unknown").slice(0, 32);
  }

  if (row.credential?.id) {
    const idSegment = row.credential.id.includes(":")
      ? row.credential.id.split(":").pop()
      : row.credential.id;
    return sanitizeFileName(idSegment ?? "unknown").slice(0, 16);
  }

  return randomBytes(4).toString("hex");
}

/**
 * Sanitize a string for use as a file name component.
 */
function sanitizeFileName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_-]/g, "_");
}

/**
 * Map a package format MIME type or format name to a file extension.
 */
function formatToExtension(format: string): string {
  switch (format) {
    case "json":
      return "jsonld";
    case "json-compact":
      return "json";
    case "qr-png":
      return "png";
    case "qr-svg":
      return "svg";
    case "pdf":
      return "pdf";
    default:
      return "bin";
  }
}

// ---------------------------------------------------------------------------
// Export function
// ---------------------------------------------------------------------------

/**
 * Export batch results as a ZIP archive.
 *
 * Only rows with status === 'success' and a credential are included.
 * Each credential's packaged outputs (JSON-LD, QR, PDF, etc.) are added
 * to the archive.
 *
 * @param options - Export configuration.
 * @returns BatchExportResult with the file path and counts.
 */
export async function exportBatchAsZip(options: BatchExportOptions): Promise<BatchExportResult> {
  const successRows = options.rows.filter((r) => r.status === "success" && r.credential);

  // Determine output path
  const outputDir = options.outputPath ? join(options.outputPath, "..") : tmpdir();
  const outputPath =
    options.outputPath ?? join(outputDir, `opencred-batch-${randomBytes(6).toString("hex")}.zip`);

  // Ensure output directory exists
  await mkdir(join(outputPath, ".."), { recursive: true });

  // Create the ZIP archive
  return new Promise<BatchExportResult>((resolve, reject) => {
    const output = createWriteStream(outputPath);
    const archive = archiver("zip", { zlib: { level: 6 } });

    let fileCount = 0;

    output.on("close", () => {
      resolve({
        filePath: outputPath,
        credentialCount: successRows.length,
        fileCount,
      });
    });

    archive.on("error", (err: Error) => {
      reject(err);
    });

    archive.pipe(output);

    for (const row of successRows) {
      const subjectId = deriveSubjectId(row);
      const baseName = `credential-${row.rowIndex}-${subjectId}`;

      // Include the credential in the appropriate format
      if (row.credential) {
        if (row.isCompactToken && typeof row.credential === "string") {
          // SD-JWT-VC compact token
          archive.append(row.credential, { name: `${baseName}.sd-jwt` });
        } else {
          // JSON-LD credential
          const jsonContent = JSON.stringify(row.credential, null, 2);
          archive.append(jsonContent, { name: `${baseName}.json` });
        }
        fileCount++;
      }

      // Add packaged outputs
      if (row.packagingResult) {
        for (const output of row.packagingResult.outputs) {
          const ext = formatToExtension(output.format);
          const fileName = `${baseName}.${ext}`;

          if (Buffer.isBuffer(output.data)) {
            archive.append(output.data, { name: fileName });
          } else if (typeof output.data === "string") {
            // For data URLs (QR PNGs), extract the base64 data
            if (output.data.startsWith("data:")) {
              const base64Data = output.data.split(",")[1];
              if (base64Data) {
                archive.append(Buffer.from(base64Data, "base64"), {
                  name: fileName,
                });
              }
            } else {
              archive.append(output.data, { name: fileName });
            }
          }

          fileCount++;
        }
      }
    }

    void archive.finalize();
  });
}
