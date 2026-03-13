/**
 * IssuePage — credential issuance form with schema-driven fields.
 *
 * Workflow:
 *  1. Select a credential schema from the dropdown
 *  2. Fill in dynamic form fields generated from the schema
 *  3. Select a signing key and validity dates
 *  4. Build and sign the credential
 *  5. View the signed credential and export as JSON/PDF/QR
 *
 * All signing happens in the main process. The private key NEVER
 * reaches the renderer — only key metadata (ID, fingerprint) is used.
 */

import { useState, useEffect, useCallback } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  format?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Map schema IDs to user-friendly display labels. */
const SCHEMA_LABELS: Record<string, string> = {
  education: "Education Credential",
  employment: "Employment Credential",
  identity: "Identity Credential",
  health: "Health Credential",
  business: "Business Credential",
};

/** Extract field information from a JSON Schema definition. */
function extractFields(schema: Record<string, unknown>): SchemaField[] {
  const properties = schema["properties"] as
    | Record<string, Record<string, unknown>>
    | undefined;
  const required = (schema["required"] as string[]) ?? [];

  if (!properties) return [];

  return Object.entries(properties).map(([name, prop]) => ({
    name,
    type: String(prop["type"] ?? "string"),
    required: required.includes(name),
    format: prop["format"] as string | undefined,
  }));
}

/** Map schema field type/format to HTML input type. */
function inputTypeForField(field: SchemaField): string {
  if (field.format === "date") return "date";
  if (field.format === "date-time") return "datetime-local";
  if (field.format === "email") return "email";
  if (field.format === "uri") return "url";
  if (field.type === "number" || field.type === "integer") return "number";
  return "text";
}

/** Capitalize and split camelCase names for display. */
function labelForField(name: string): string {
  return name
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/^./, (c) => c.toUpperCase());
}

function todayIso(): string {
  return new Date().toISOString().split("T")[0];
}

function oneYearFromNow(): string {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString().split("T")[0];
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function IssuePage() {
  // Schema
  const [schemas, setSchemas] = useState<string[]>([]);
  const [schemasLoading, setSchemasLoading] = useState(true);
  const [schemaId, setSchemaId] = useState("");
  const [schemaFields, setSchemaFields] = useState<SchemaField[]>([]);

  // Form
  const [subjectValues, setSubjectValues] = useState<Record<string, string>>({});
  const [validFrom, setValidFrom] = useState(todayIso);
  const [validUntil, setValidUntil] = useState(oneYearFromNow);
  const [selectedKeyId, setSelectedKeyId] = useState("");
  const [keys, setKeys] = useState<KeyMetadata[]>([]);

  // Result
  const [signing, setSigning] = useState(false);
  const [signedCredential, setSignedCredential] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // ------------------------------------------------------------------
  // Data loading
  // ------------------------------------------------------------------

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

  const loadSchemas = useCallback(async () => {
    try {
      const response = await window.opencred.listSchemas();
      setSchemas(response.schemas);
    } catch {
      // Schemas not available
    } finally {
      setSchemasLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadKeys();
    void loadSchemas();
  }, [loadKeys, loadSchemas]);

  // ------------------------------------------------------------------
  // Handlers
  // ------------------------------------------------------------------

  async function handleSchemaSelect(id: string) {
    setSchemaId(id);
    setSchemaFields([]);
    setSubjectValues({});
    setSignedCredential(null);
    setError(null);

    if (!id) return;

    try {
      const response = await window.opencred.getSchema({ schemaId: id });
      const fields = extractFields(response.schema);
      setSchemaFields(fields);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load schema.");
    }
  }

  async function handleBuildAndSign() {
    if (!schemaId || !selectedKeyId) {
      setError("Please select a schema and a signing key.");
      return;
    }

    setError(null);
    setSignedCredential(null);
    setSigning(true);

    try {
      // The issuer DID is derived from the selected key in the main process.
      // We pass the key ID and the main process resolves the DID.
      const selectedKey = keys.find((k) => k.id === selectedKeyId);
      const issuerDid = selectedKey?.id ?? selectedKeyId;

      const response = await window.opencred.buildAndSign({
        schemaId,
        issuerDid,
        credentialSubject: subjectValues,
        validFrom: new Date(validFrom).toISOString(),
        validUntil: validUntil ? new Date(validUntil).toISOString() : undefined,
        keyId: selectedKeyId,
        packageFormats: ["json-ld"],
      });

      if (response.success && response.signedCredential) {
        setSignedCredential(response.signedCredential);
      } else {
        setError(response.error ?? "Build and sign failed.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Build and sign failed.");
    } finally {
      setSigning(false);
    }
  }

  async function handleExportJson() {
    if (!signedCredential) return;
    try {
      await window.opencred.saveFile({
        defaultName: "credential.jsonld",
        content: JSON.stringify(JSON.parse(signedCredential), null, 2),
        filters: [{ name: "JSON-LD", extensions: ["jsonld", "json"] }],
      });
    } catch {
      // User may have cancelled
    }
  }

  async function handleExportPdf() {
    if (!signedCredential) return;
    try {
      const result = await window.opencred.packageCredential({
        credential: signedCredential,
        formats: ["pdf"],
      });
      if (result.success && result.outputs && result.outputs.length > 0) {
        const pdfOutput = result.outputs[0];
        await window.opencred.saveFile({
          defaultName: pdfOutput.suggestedFileName,
          content: pdfOutput.data,
          encoding: "base64",
          filters: [{ name: "PDF", extensions: ["pdf"] }],
        });
      }
    } catch {
      // User may have cancelled or packaging not available
    }
  }

  async function handleShowQr() {
    if (!signedCredential) return;
    try {
      const result = await window.opencred.packageCredential({
        credential: signedCredential,
        formats: ["qr-png"],
      });
      if (result.success && result.outputs && result.outputs.length > 0) {
        const qrOutput = result.outputs[0];
        // QR data is a data URL (data:image/png;base64,...) — extract the base64 payload
        const base64Data = qrOutput.data.includes(",")
          ? qrOutput.data.split(",")[1]
          : qrOutput.data;
        await window.opencred.saveFile({
          defaultName: qrOutput.suggestedFileName,
          content: base64Data,
          encoding: "base64",
          filters: [{ name: "PNG Image", extensions: ["png"] }],
        });
      }
    } catch {
      // User may have cancelled or packaging not available
    }
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  return (
    <div className="space-y-6">
      {/* Schema selection */}
      <Card className="space-y-3">
        <h2 className="text-sm font-medium text-gray-700">Credential Type</h2>
        <p className="text-xs text-gray-500">
          Select a credential schema to define the subject fields.
        </p>
        {schemasLoading ? (
          <p className="text-sm text-gray-400">Loading schemas...</p>
        ) : (
          <select
            value={schemaId}
            onChange={(e) => void handleSchemaSelect(e.target.value)}
            className="block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-700 shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="">Select a credential type...</option>
            {schemas.map((id) => (
              <option key={id} value={id}>
                {SCHEMA_LABELS[id] ?? id}
              </option>
            ))}
          </select>
        )}
      </Card>

      {/* Dynamic form fields */}
      <Card className="space-y-3">
        <h2 className="text-sm font-medium text-gray-700">Credential Details</h2>
        {schemaFields.length === 0 ? (
          <p className="text-sm text-gray-500">
            Select a credential type above to see the form fields.
          </p>
        ) : (
          <div className="space-y-3">
            {schemaFields.map((field) => (
              <div key={field.name}>
                <label
                  htmlFor={`field-${field.name}`}
                  className="block text-xs font-medium text-gray-600"
                >
                  {labelForField(field.name)}
                  {field.required && <span className="text-red-500 ml-0.5">*</span>}
                </label>
                <input
                  id={`field-${field.name}`}
                  type={inputTypeForField(field)}
                  value={subjectValues[field.name] ?? ""}
                  onChange={(e) =>
                    setSubjectValues((prev) => ({
                      ...prev,
                      [field.name]: e.target.value,
                    }))
                  }
                  required={field.required}
                  disabled={signing}
                  placeholder={`Enter ${labelForField(field.name).toLowerCase()}...`}
                  className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50 disabled:text-gray-400"
                />
              </div>
            ))}
          </div>
        )}
      </Card>

      {/* Issuance settings */}
      <Card className="space-y-3">
        <h2 className="text-sm font-medium text-gray-700">Issuance Settings</h2>

        {/* Key selector */}
        <div>
          <label
            htmlFor="issue-signing-key"
            className="block text-xs font-medium text-gray-600"
          >
            Signing Key <span className="text-red-500">*</span>
          </label>
          {keys.length === 0 ? (
            <p className="mt-1 text-xs text-gray-400 italic">
              No keys imported. Go to Settings to import or generate a key.
            </p>
          ) : (
            <select
              id="issue-signing-key"
              value={selectedKeyId}
              onChange={(e) => setSelectedKeyId(e.target.value)}
              disabled={signing}
              className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
            >
              {keys.map((key) => (
                <option key={key.id} value={key.id}>
                  {key.label ?? key.algorithm} -- {key.fingerprint.slice(0, 16)}...
                </option>
              ))}
            </select>
          )}
        </div>

        {/* Validity dates */}
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label
              htmlFor="issue-valid-from"
              className="block text-xs font-medium text-gray-600"
            >
              Valid From
            </label>
            <input
              id="issue-valid-from"
              type="date"
              value={validFrom}
              onChange={(e) => setValidFrom(e.target.value)}
              disabled={signing}
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
            />
          </div>
          <div>
            <label
              htmlFor="issue-valid-until"
              className="block text-xs font-medium text-gray-600"
            >
              Valid Until
            </label>
            <input
              id="issue-valid-until"
              type="date"
              value={validUntil}
              onChange={(e) => setValidUntil(e.target.value)}
              disabled={signing}
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
            />
          </div>
        </div>
      </Card>

      {/* Build & Sign */}
      <Card className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-medium text-gray-700">Build & Sign</h2>
            <p className="text-xs text-gray-500">
              Keys never leave this machine. Signing works offline.
            </p>
          </div>
          <Button
            onClick={() => void handleBuildAndSign()}
            disabled={signing || !schemaId || !selectedKeyId}
          >
            {signing ? "Signing..." : "Issue Credential"}
          </Button>
        </div>

        {error && <p className="text-sm text-red-600">{error}</p>}

        {signedCredential && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-green-700">
                Credential issued successfully
              </span>
              <div className="flex gap-2">
                <button
                  onClick={() => void handleExportJson()}
                  className="rounded-md bg-gray-100 px-3 py-1 text-xs text-gray-700 hover:bg-gray-200"
                >
                  Download JSON
                </button>
                <button
                  onClick={() => void handleExportPdf()}
                  className="rounded-md bg-gray-100 px-3 py-1 text-xs text-gray-700 hover:bg-gray-200"
                >
                  Download PDF
                </button>
                <button
                  onClick={() => void handleShowQr()}
                  className="rounded-md bg-gray-100 px-3 py-1 text-xs text-gray-700 hover:bg-gray-200"
                >
                  Show QR
                </button>
              </div>
            </div>
            <pre className="max-h-60 overflow-auto rounded-md bg-gray-50 border border-gray-200 p-3 font-mono text-xs text-gray-700">
              {JSON.stringify(JSON.parse(signedCredential), null, 2)}
            </pre>
          </div>
        )}
      </Card>
    </div>
  );
}
