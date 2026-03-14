/**
 * BatchIssuance — full batch credential issuance from CSV files.
 *
 * Provides a complete workflow:
 *   1. Import CSV file via native file dialog
 *   2. Preview parsed data (first 5 rows)
 *   3. Map CSV columns to schema fields
 *   4. Select schema, signing key, issuer DID, dates
 *   5. Start batch processing with progress tracking
 *   6. View per-row results (success/error)
 *   7. Export all packaged credentials as ZIP
 *
 * All operations work entirely offline. Private keys never leave
 * the main process.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import type { KeyMetadata, BatchRowStatus } from "../../shared/ipc-types";
import { SchemaSelector } from "./SchemaSelector";
import { BATCH_ROW_LIMIT } from "../../shared/constants";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  format?: string;
}

interface RowResult {
  rowIndex: number;
  status: BatchRowStatus;
  error?: string;
}

type BatchPhase = "upload" | "mapping" | "config" | "processing" | "complete";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function BatchIssuance() {
  // Phase control
  const [phase, setPhase] = useState<BatchPhase>("upload");

  // CSV data
  const [csvContent, setCsvContent] = useState<string | null>(null);
  const [csvFileName, setCsvFileName] = useState<string>("");
  const [csvHeaders, setCsvHeaders] = useState<string[]>([]);
  const [csvPreview, setCsvPreview] = useState<string[][]>([]);
  const [csvRowCount, setCsvRowCount] = useState(0);

  // Schema & field mapping
  const [schemaId, setSchemaId] = useState("");
  const [schemaFields, setSchemaFields] = useState<SchemaField[]>([]);
  const [columnMapping, setColumnMapping] = useState<Record<string, string>>({});

  // Issuance config
  const [issuerDid, setIssuerDid] = useState("");
  const [validFrom, setValidFrom] = useState(new Date().toISOString().split("T")[0]);
  const [validUntil, setValidUntil] = useState("");
  const [revocationUrl, setRevocationUrl] = useState("");
  const [selectedKeyId, setSelectedKeyId] = useState("");
  const [keys, setKeys] = useState<KeyMetadata[]>([]);
  const [packageFormats, setPackageFormats] = useState<string[]>(["json-ld"]);

  // Processing state
  const [processing, setProcessing] = useState(false);
  const [total, setTotal] = useState(0);
  const [completed, setCompleted] = useState(0);
  const [successCount, setSuccessCount] = useState(0);
  const [errorCount, setErrorCount] = useState(0);
  const [skippedCount, setSkippedCount] = useState(0);
  const [rowResults, setRowResults] = useState<RowResult[]>([]);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [parseErrors, setParseErrors] = useState<
    Array<{ rowIndex: number; errors: Array<{ field: string; message: string }> }>
  >([]);

  // Export state
  const [exporting, setExporting] = useState(false);
  const [exportResult, setExportResult] = useState<string | null>(null);

  // Poll interval ref
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Load keys on mount
  const loadKeys = useCallback(async () => {
    try {
      const response = await window.opencred.listKeys();
      setKeys(response.keys);
      if (response.keys.length > 0 && !selectedKeyId) {
        setSelectedKeyId(response.keys[0].id);
      }
    } catch {
      // Keys may not be loaded yet
    }
  }, [selectedKeyId]);

  useEffect(() => {
    void loadKeys();
  }, [loadKeys]);

  // Cleanup polling on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) {
        clearInterval(pollRef.current);
      }
    };
  }, []);

  // ---------------------------------------------------------------------------
  // CSV Import
  // ---------------------------------------------------------------------------

  async function handleImportCsv() {
    try {
      const result = await window.opencred.openFile({
        title: "Select CSV File",
        filters: [
          { name: "CSV Files", extensions: ["csv", "tsv", "txt"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (!result.content || !result.filePath) return;

      setCsvContent(result.content);
      setCsvFileName(result.filePath.split("/").pop() ?? "file.csv");

      // Parse preview (first 6 lines: 1 header + 5 data rows)
      const lines = result.content.split(/\r?\n/).filter((l: string) => l.trim().length > 0);
      if (lines.length > 0) {
        // Simple preview parsing (just split by common delimiters)
        const firstLine = lines[0];
        const delimiter = firstLine.includes("\t") ? "\t" : firstLine.includes(";") ? ";" : ",";
        const headers = firstLine
          .split(delimiter)
          .map((h: string) => h.trim().replace(/^"|"$/g, ""));
        setCsvHeaders(headers);

        // Count data rows (excluding header)
        const dataRowCount = lines.length - 1;
        setCsvRowCount(dataRowCount);

        const previewRows = lines
          .slice(1, 6)
          .map((line: string) =>
            line.split(delimiter).map((v: string) => v.trim().replace(/^"|"$/g, "")),
          );
        setCsvPreview(previewRows);

        // Initialize column mapping (identity mapping by default)
        const initialMapping: Record<string, string> = {};
        for (const header of headers) {
          initialMapping[header] = header;
        }
        setColumnMapping(initialMapping);

        // Check row limit
        if (dataRowCount > BATCH_ROW_LIMIT) {
          setBatchError(
            `CSV contains ${dataRowCount.toLocaleString()} rows, which exceeds the maximum of ${BATCH_ROW_LIMIT.toLocaleString()} rows. Please split your CSV into smaller files.`,
          );
        } else {
          setBatchError(null);
        }

        setPhase("mapping");
      }
    } catch {
      setBatchError("Failed to open CSV file.");
    }
  }

  // ---------------------------------------------------------------------------
  // Schema selection
  // ---------------------------------------------------------------------------

  function handleSchemaSelect(id: string, fields: SchemaField[]) {
    setSchemaId(id);
    setSchemaFields(fields);

    // Auto-map columns that match schema field names
    const newMapping: Record<string, string> = {};
    for (const header of csvHeaders) {
      const matchingField = fields.find((f) => f.name.toLowerCase() === header.toLowerCase());
      if (matchingField) {
        newMapping[header] = matchingField.name;
      } else {
        newMapping[header] = "";
      }
    }
    setColumnMapping(newMapping);
  }

  // ---------------------------------------------------------------------------
  // Column mapping
  // ---------------------------------------------------------------------------

  function handleMappingChange(csvColumn: string, schemaField: string) {
    setColumnMapping((prev) => ({ ...prev, [csvColumn]: schemaField }));
  }

  function handleMappingComplete() {
    setPhase("config");
  }

  // ---------------------------------------------------------------------------
  // Batch processing
  // ---------------------------------------------------------------------------

  const isOverRowLimit = csvRowCount > BATCH_ROW_LIMIT;

  async function handleStartBatch() {
    if (!csvContent || !schemaId || !issuerDid || !selectedKeyId) {
      setBatchError("Please complete all required fields.");
      return;
    }

    if (isOverRowLimit) {
      setBatchError(
        `CSV contains ${csvRowCount.toLocaleString()} rows, which exceeds the maximum of ${BATCH_ROW_LIMIT.toLocaleString()} rows. Please split your CSV into smaller files.`,
      );
      return;
    }

    setBatchError(null);
    setParseErrors([]);
    setProcessing(true);
    setPhase("processing");
    setRowResults([]);
    setCompleted(0);
    setSuccessCount(0);
    setErrorCount(0);
    setSkippedCount(0);
    setExportResult(null);

    try {
      // Build the effective column mapping (only include mapped columns)
      const effectiveMapping: Record<string, string> = {};
      for (const [csvCol, schemaField] of Object.entries(columnMapping)) {
        if (schemaField) {
          effectiveMapping[csvCol] = schemaField;
        }
      }

      const response = await window.opencred.batchStart({
        csvContent,
        schemaId,
        issuerDid,
        validFrom: new Date(validFrom).toISOString(),
        validUntil: validUntil ? new Date(validUntil).toISOString() : undefined,
        revocationRegistryUrl: revocationUrl || undefined,
        keyId: selectedKeyId,
        columnMapping: Object.keys(effectiveMapping).length > 0 ? effectiveMapping : undefined,
        packageFormats,
      });

      if (!response.success) {
        setBatchError(response.error ?? "Failed to start batch.");
        setProcessing(false);
        setPhase("config");
        return;
      }

      setTotal(response.totalCount ?? 0);
      if (response.parseErrors) {
        setParseErrors(response.parseErrors);
      }

      // Start polling for progress
      pollRef.current = setInterval(() => {
        void pollProgress();
      }, 500);
    } catch (err) {
      setBatchError(err instanceof Error ? err.message : "Failed to start batch.");
      setProcessing(false);
      setPhase("config");
    }
  }

  async function pollProgress() {
    try {
      const status = await window.opencred.batchStatus();
      setTotal(status.total);
      setCompleted(status.completed);
      setSuccessCount(status.successCount);
      setErrorCount(status.errorCount);
      setSkippedCount(status.skippedCount);
      setRowResults(
        status.rows.map((r) => ({
          rowIndex: r.rowIndex,
          status: r.status,
          error: r.error,
        })),
      );

      if (!status.running) {
        // Batch is done
        if (pollRef.current) {
          clearInterval(pollRef.current);
          pollRef.current = null;
        }
        setProcessing(false);
        setPhase("complete");
      }
    } catch {
      // Ignore poll errors
    }
  }

  async function handleCancel() {
    try {
      await window.opencred.batchCancel();
    } catch {
      // Ignore
    }
  }

  // ---------------------------------------------------------------------------
  // Export
  // ---------------------------------------------------------------------------

  async function handleExport() {
    setExporting(true);
    setExportResult(null);

    try {
      // Use native save dialog to get path
      const saveResult = await window.opencred.saveFile({
        defaultName: `batch-credentials-${new Date().toISOString().split("T")[0]}.zip`,
        content: "", // We just need the path
        filters: [{ name: "ZIP Archive", extensions: ["zip"] }],
      });

      if (!saveResult.filePath) {
        setExporting(false);
        return;
      }

      const result = await window.opencred.batchExport({
        outputPath: saveResult.filePath,
      });

      if (result.success) {
        setExportResult(
          `Exported ${result.credentialCount} credentials (${result.fileCount} files) to ${result.filePath}`,
        );
      } else {
        setBatchError(result.error ?? "Export failed.");
      }
    } catch (err) {
      setBatchError(err instanceof Error ? err.message : "Export failed.");
    } finally {
      setExporting(false);
    }
  }

  // ---------------------------------------------------------------------------
  // Reset
  // ---------------------------------------------------------------------------

  function handleReset() {
    setCsvContent(null);
    setCsvFileName("");
    setCsvHeaders([]);
    setCsvPreview([]);
    setCsvRowCount(0);
    setSchemaId("");
    setSchemaFields([]);
    setColumnMapping({});
    setIssuerDid("");
    setValidFrom(new Date().toISOString().split("T")[0]);
    setValidUntil("");
    setRevocationUrl("");
    setTotal(0);
    setCompleted(0);
    setSuccessCount(0);
    setErrorCount(0);
    setSkippedCount(0);
    setRowResults([]);
    setBatchError(null);
    setParseErrors([]);
    setExportResult(null);
    setPhase("upload");
  }

  // ---------------------------------------------------------------------------
  // Format toggle
  // ---------------------------------------------------------------------------

  function toggleFormat(format: string) {
    setPackageFormats((prev) =>
      prev.includes(format) ? prev.filter((f) => f !== format) : [...prev, format],
    );
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  const progressPercent = total > 0 ? Math.round((completed / total) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* Phase: Upload CSV */}
      {phase === "upload" && (
        <div className="rounded-lg border border-gray-200 bg-white p-6 space-y-4">
          <h2 className="text-sm font-medium text-gray-700">Batch Credential Issuance</h2>
          <p className="text-sm text-gray-500">
            Issue multiple credentials at once from a CSV file. All processing happens locally -- no
            network required.
          </p>
          <button
            onClick={() => void handleImportCsv()}
            className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
          >
            Import CSV File
          </button>
          {batchError && <p className="text-sm text-red-600">{batchError}</p>}
        </div>
      )}

      {/* Phase: Column Mapping */}
      {phase === "mapping" && (
        <div className="space-y-4">
          {/* CSV Preview */}
          <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-gray-700">CSV Preview: {csvFileName}</h2>
              <button onClick={handleReset} className="text-xs text-gray-500 hover:text-gray-700">
                Change File
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="min-w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-200">
                    {csvHeaders.map((h, i) => (
                      <th key={i} className="px-2 py-1 text-left font-medium text-gray-600">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {csvPreview.map((row, ri) => (
                    <tr key={ri} className="border-b border-gray-100">
                      {row.map((val, ci) => (
                        <td key={ci} className="px-2 py-1 text-gray-700">
                          {val}
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {csvPreview.length >= 5 && (
              <p className="text-xs text-gray-400">
                Showing first 5 of {csvRowCount.toLocaleString()} rows...
              </p>
            )}

            {/* Row limit warning */}
            {isOverRowLimit && (
              <div className="rounded-md bg-red-50 border border-red-200 p-3">
                <p className="text-sm text-red-700">
                  This CSV contains {csvRowCount.toLocaleString()} rows, which exceeds the maximum of{" "}
                  {BATCH_ROW_LIMIT.toLocaleString()} rows per batch. Please split your CSV into smaller
                  files before continuing.
                </p>
              </div>
            )}
          </div>

          {/* Schema Selection */}
          <SchemaSelector onSchemaSelect={handleSchemaSelect} selectedSchema={schemaId} />

          {/* Column Mapping UI */}
          {schemaId && schemaFields.length > 0 && (
            <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-3">
              <h2 className="text-sm font-medium text-gray-700">Column Mapping</h2>
              <p className="text-xs text-gray-500">
                Map each CSV column to a credential schema field.
              </p>
              <div className="space-y-2">
                {csvHeaders.map((header) => (
                  <div key={header} className="flex items-center gap-3">
                    <span className="w-1/3 text-xs font-mono text-gray-600 truncate" title={header}>
                      {header}
                    </span>
                    <span className="text-gray-400 text-xs">-&gt;</span>
                    <select
                      value={columnMapping[header] ?? ""}
                      onChange={(e) => handleMappingChange(header, e.target.value)}
                      className="flex-1 rounded-md border border-gray-300 bg-white px-2 py-1 text-xs text-gray-700"
                    >
                      <option value="">(skip this column)</option>
                      {schemaFields.map((field) => (
                        <option key={field.name} value={field.name}>
                          {field.name}
                          {field.required ? " *" : ""}
                        </option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
              <button
                onClick={handleMappingComplete}
                className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
              >
                Continue
              </button>
            </div>
          )}
        </div>
      )}

      {/* Phase: Issuance Configuration */}
      {phase === "config" && (
        <div className="space-y-4">
          <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-gray-700">Issuance Settings</h2>
              <button
                onClick={() => setPhase("mapping")}
                className="text-xs text-gray-500 hover:text-gray-700"
              >
                Back to Mapping
              </button>
            </div>

            <div>
              <label htmlFor="batch-issuer-did" className="block text-xs font-medium text-gray-600">
                Issuer DID <span className="text-red-500">*</span>
              </label>
              <input
                id="batch-issuer-did"
                type="text"
                value={issuerDid}
                onChange={(e) => setIssuerDid(e.target.value)}
                placeholder="did:web:example.com"
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label
                  htmlFor="batch-valid-from"
                  className="block text-xs font-medium text-gray-600"
                >
                  Valid From <span className="text-red-500">*</span>
                </label>
                <input
                  id="batch-valid-from"
                  type="date"
                  value={validFrom}
                  onChange={(e) => setValidFrom(e.target.value)}
                  className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                />
              </div>
              <div>
                <label
                  htmlFor="batch-valid-until"
                  className="block text-xs font-medium text-gray-600"
                >
                  Valid Until (optional)
                </label>
                <input
                  id="batch-valid-until"
                  type="date"
                  value={validUntil}
                  onChange={(e) => setValidUntil(e.target.value)}
                  className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                />
              </div>
            </div>

            <div>
              <label
                htmlFor="batch-revocation-url"
                className="block text-xs font-medium text-gray-600"
              >
                Revocation Registry URL (optional)
              </label>
              <input
                id="batch-revocation-url"
                type="url"
                value={revocationUrl}
                onChange={(e) => setRevocationUrl(e.target.value)}
                placeholder="https://dedi.example/revocations/..."
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>

            <div>
              <label
                htmlFor="batch-signing-key"
                className="block text-xs font-medium text-gray-600"
              >
                Signing Key <span className="text-red-500">*</span>
              </label>
              {keys.length === 0 ? (
                <p className="mt-1 text-xs text-gray-400 italic">
                  No keys imported. Go to Key Management to import a key.
                </p>
              ) : (
                <select
                  id="batch-signing-key"
                  value={selectedKeyId}
                  onChange={(e) => setSelectedKeyId(e.target.value)}
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                >
                  {keys.map((key) => (
                    <option key={key.id} value={key.id}>
                      {key.label ?? key.algorithm} -- {key.fingerprint.slice(0, 16)}...
                    </option>
                  ))}
                </select>
              )}
            </div>

            {/* Output format selection */}
            <div>
              <span className="block text-xs font-medium text-gray-600 mb-1">Output Formats</span>
              <div className="flex flex-wrap gap-2">
                {["json-ld", "qr-png", "pdf"].map((fmt) => (
                  <label key={fmt} className="flex items-center gap-1 text-xs text-gray-600">
                    <input
                      type="checkbox"
                      checked={packageFormats.includes(fmt)}
                      onChange={() => toggleFormat(fmt)}
                      className="rounded border-gray-300"
                    />
                    {fmt === "json-ld" ? "JSON-LD" : fmt === "qr-png" ? "QR Code" : "PDF"}
                  </label>
                ))}
              </div>
            </div>
          </div>

          {batchError && <p className="text-sm text-red-600">{batchError}</p>}

          <div className="flex gap-3">
            <button
              onClick={() => void handleStartBatch()}
              disabled={!schemaId || !issuerDid || !selectedKeyId || isOverRowLimit}
              className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Start Batch Issuance
            </button>
            <button
              onClick={handleReset}
              className="rounded-md bg-gray-100 px-4 py-2 text-sm text-gray-700 hover:bg-gray-200"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Phase: Processing */}
      {phase === "processing" && (
        <div className="space-y-4">
          <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-medium text-gray-700">Batch Processing</h2>
              {processing && (
                <button
                  onClick={() => void handleCancel()}
                  className="rounded-md bg-red-100 px-3 py-1 text-xs text-red-700 hover:bg-red-200"
                >
                  Cancel
                </button>
              )}
            </div>

            {/* Progress bar */}
            <div>
              <div className="flex justify-between text-xs text-gray-500 mb-1">
                <span>
                  {completed} of {total} complete
                </span>
                <span>{progressPercent}%</span>
              </div>
              <div className="w-full bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
            </div>

            {/* Summary stats */}
            <div className="flex gap-4 text-xs">
              <span className="text-green-600">Success: {successCount}</span>
              <span className="text-red-600">Errors: {errorCount}</span>
              <span className="text-gray-400">Skipped: {skippedCount}</span>
            </div>
          </div>

          {/* Per-row status */}
          <div className="rounded-lg border border-gray-200 bg-white p-4">
            <h3 className="text-xs font-medium text-gray-600 mb-2">Row Status</h3>
            <div className="max-h-60 overflow-auto space-y-1">
              {rowResults.map((row) => (
                <div
                  key={row.rowIndex}
                  className={`flex items-center gap-2 text-xs px-2 py-1 rounded ${
                    row.status === "success"
                      ? "bg-green-50 text-green-700"
                      : row.status === "error"
                        ? "bg-red-50 text-red-700"
                        : row.status === "processing"
                          ? "bg-blue-50 text-blue-700"
                          : row.status === "skipped"
                            ? "bg-gray-50 text-gray-400"
                            : "bg-gray-50 text-gray-600"
                  }`}
                >
                  <span className="font-mono w-8">#{row.rowIndex + 1}</span>
                  <span className="flex-1">
                    {row.status === "success" && "OK"}
                    {row.status === "error" && (row.error ?? "Error")}
                    {row.status === "processing" && "Processing..."}
                    {row.status === "skipped" && (row.error ?? "Skipped")}
                    {row.status === "pending" && "Pending"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Phase: Complete */}
      {phase === "complete" && (
        <div className="space-y-4">
          <div className="rounded-lg border border-green-200 bg-green-50 p-4 space-y-3">
            <h2 className="text-sm font-medium text-green-800">Batch Complete</h2>
            <div className="flex gap-4 text-sm">
              <span className="text-green-700">Success: {successCount}</span>
              <span className="text-red-600">Errors: {errorCount}</span>
              <span className="text-gray-500">Skipped: {skippedCount}</span>
              <span className="text-gray-500">Total: {total}</span>
            </div>
          </div>

          {/* Parse errors */}
          {parseErrors.length > 0 && (
            <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4 space-y-2">
              <h3 className="text-xs font-medium text-yellow-800">
                Validation Errors (skipped rows)
              </h3>
              <div className="max-h-40 overflow-auto space-y-1">
                {parseErrors.map((pe) => (
                  <div key={pe.rowIndex} className="text-xs text-yellow-700">
                    Row #{pe.rowIndex + 1}:{" "}
                    {pe.errors.map((e) => `${e.field}: ${e.message}`).join("; ")}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Per-row results */}
          <div className="rounded-lg border border-gray-200 bg-white p-4">
            <h3 className="text-xs font-medium text-gray-600 mb-2">Row Results</h3>
            <div className="max-h-60 overflow-auto space-y-1">
              {rowResults.map((row) => (
                <div
                  key={row.rowIndex}
                  className={`flex items-center gap-2 text-xs px-2 py-1 rounded ${
                    row.status === "success"
                      ? "bg-green-50 text-green-700"
                      : row.status === "error"
                        ? "bg-red-50 text-red-700"
                        : "bg-gray-50 text-gray-400"
                  }`}
                >
                  <span className="font-mono w-8">#{row.rowIndex + 1}</span>
                  <span>
                    {row.status === "success" && "OK"}
                    {row.status === "error" && (row.error ?? "Error")}
                    {row.status === "skipped" && (row.error ?? "Skipped (invalid)")}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Export */}
          {successCount > 0 && (
            <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-3">
              <h3 className="text-sm font-medium text-gray-700">Export Results</h3>
              <p className="text-xs text-gray-500">
                Export all {successCount} successfully issued credentials as a ZIP archive.
              </p>
              <button
                onClick={() => void handleExport()}
                disabled={exporting}
                className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-40"
              >
                {exporting ? "Exporting..." : "Export as ZIP"}
              </button>
              {exportResult && <p className="text-xs text-green-700">{exportResult}</p>}
            </div>
          )}

          {batchError && <p className="text-sm text-red-600">{batchError}</p>}

          <button
            onClick={handleReset}
            className="rounded-md bg-gray-100 px-4 py-2 text-sm text-gray-700 hover:bg-gray-200"
          >
            Start New Batch
          </button>
        </div>
      )}
    </div>
  );
}
