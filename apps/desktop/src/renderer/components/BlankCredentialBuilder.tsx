/**
 * BlankCredentialBuilder — 3-mode schema input for blank credentials.
 *
 * Modes:
 *   1. Visual builder — add fields with name, type, and required toggle
 *   2. Import from URL — fetch a JSON Schema from a URL via IPC
 *   3. Paste / Upload — paste JSON (schema or sample) or upload a .json file
 *
 * All modes produce the same output: onSchemaReady(fields, schema, credentialName).
 */

import { useState, useCallback } from "react";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";
import type { FieldDefinition } from "../utils/schema-inference";
import {
  fieldsToJsonSchema,
  jsonToFields,
  jsonSchemaToFields,
  detectJsonType,
} from "../utils/schema-inference";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  format?: string;
}

interface Props {
  onSchemaReady: (
    fields: SchemaField[],
    schema: Record<string, unknown>,
    credentialName: string,
    sourceUrl?: string,
  ) => void;
}

type FieldType = FieldDefinition["type"];
type InputMode = "visual" | "url" | "paste";

const FIELD_TYPES: { value: FieldType; label: string }[] = [
  { value: "string", label: "Text" },
  { value: "number", label: "Number" },
  { value: "boolean", label: "Boolean" },
  { value: "integer", label: "Integer" },
  { value: "date", label: "Date" },
  { value: "datetime", label: "Date-Time" },
  { value: "email", label: "Email" },
  { value: "url", label: "URL" },
];

const TABS: { mode: InputMode; label: string }[] = [
  { mode: "visual", label: "Visual builder" },
  { mode: "url", label: "Import from URL" },
  { mode: "paste", label: "Paste / Upload" },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function BlankCredentialBuilder({ onSchemaReady }: Props) {
  const [credentialName, setCredentialName] = useState("");
  const [activeMode, setActiveMode] = useState<InputMode>("visual");
  const [fields, setFields] = useState<FieldDefinition[]>([
    { name: "", type: "string", required: true },
  ]);

  // URL mode state
  const [schemaUrl, setSchemaUrl] = useState("");
  const [urlFetching, setUrlFetching] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);
  // Paste mode state
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);
  // Save as reusable schema
  const [saveAsReusable, setSaveAsReusable] = useState(false);

  // ------------------------------------------------------------------
  // Shared: convert fields to SchemaFields and call onSchemaReady
  // ------------------------------------------------------------------

  const applyFields = useCallback(
    (defs: FieldDefinition[], name?: string, sourceUrl?: string) => {
      const validFields = defs.filter((f) => f.name.trim().length > 0);
      if (validFields.length === 0) return;

      const schema = fieldsToJsonSchema(validFields);

      const schemaFields: SchemaField[] = validFields.map((f) => ({
        name: f.name,
        type:
          f.type === "number"
            ? "number"
            : f.type === "integer"
              ? "integer"
              : f.type === "boolean"
                ? "boolean"
                : "string",
        required: f.required,
        format:
          f.type === "date"
            ? "date"
            : f.type === "datetime"
              ? "date-time"
              : f.type === "email"
                ? "email"
                : f.type === "url"
                  ? "uri"
                  : undefined,
      }));

      onSchemaReady(schemaFields, schema, name || credentialName || "Custom Credential", sourceUrl);

      if (saveAsReusable) {
        window.opencred.customSchemaSave({
          name: name || credentialName || "Custom Credential",
          schema,
        });
      }
    },
    [onSchemaReady, credentialName, saveAsReusable],
  );

  // ------------------------------------------------------------------
  // Visual builder handlers
  // ------------------------------------------------------------------

  function addField() {
    setFields((prev) => [...prev, { name: "", type: "string", required: false }]);
  }

  function removeField(index: number) {
    setFields((prev) => prev.filter((_, i) => i !== index));
  }

  function updateField(index: number, update: Partial<FieldDefinition>) {
    setFields((prev) => prev.map((f, i) => (i === index ? { ...f, ...update } : f)));
  }

  // ------------------------------------------------------------------
  // URL mode handlers
  // ------------------------------------------------------------------

  async function handleFetchUrl() {
    setUrlError(null);
    if (!schemaUrl.trim()) {
      setUrlError("Please enter a URL.");
      return;
    }

    setUrlFetching(true);
    try {
      const result = await window.opencred.schemaFetchUrl({ url: schemaUrl.trim() });
      if (!result.success) {
        setUrlError(result.error || "Failed to fetch schema.");
        return;
      }

      const fetched = result.schema!;
      const inferred = jsonSchemaToFields(fetched);
      setFields(inferred);
      setActiveMode("visual");

      if (result.title && !credentialName) {
        setCredentialName(result.title);
      }

      applyFields(inferred, result.title || credentialName, schemaUrl.trim());
    } catch (err) {
      setUrlError(err instanceof Error ? err.message : "Unexpected error");
    } finally {
      setUrlFetching(false);
    }
  }

  // ------------------------------------------------------------------
  // Paste / Upload mode handlers
  // ------------------------------------------------------------------

  function handleJsonParse() {
    setJsonError(null);
    try {
      const parsed = JSON.parse(jsonText);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setJsonError("Please paste a JSON object (not an array or primitive).");
        return;
      }

      const obj = parsed as Record<string, unknown>;
      const jsonType = detectJsonType(obj);
      let inferred: FieldDefinition[];
      let detectedName: string | undefined;

      if (jsonType === "schema") {
        inferred = jsonSchemaToFields(obj);
        if (typeof obj.title === "string") {
          detectedName = obj.title;
        }
      } else {
        inferred = jsonToFields(obj);
      }

      setFields(inferred);
      setActiveMode("visual");

      if (detectedName && !credentialName) {
        setCredentialName(detectedName);
      }

      applyFields(inferred, detectedName || credentialName);
    } catch {
      setJsonError("Invalid JSON. Please check your syntax.");
    }
  }

  async function handleFileUpload() {
    setJsonError(null);
    try {
      const result = await window.opencred.openFile({
        title: "Open JSON Schema or Sample",
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (result.content) {
        setJsonText(result.content);
      }
    } catch (err) {
      setJsonError(err instanceof Error ? err.message : "Failed to open file");
    }
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  const validFieldCount = fields.filter((f) => f.name.trim().length > 0).length;

  return (
    <Card className="space-y-4">
      {/* Credential name */}
      <div>
        <label htmlFor="blank-cred-name" className="block text-xs font-medium text-txt-secondary">
          Credential Name <span className="text-state-danger">*</span>
        </label>
        <input
          id="blank-cred-name"
          type="text"
          value={credentialName}
          onChange={(e) => setCredentialName(e.target.value)}
          placeholder="e.g. Energy Prosumer Certificate"
          className="mt-1 block w-full rounded-md border border-border px-3 py-2 text-sm shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500"
        />
      </div>

      {/* Mode tabs */}
      <div className="flex gap-1 border-b border-border-light">
        {TABS.map((tab) => (
          <button
            key={tab.mode}
            onClick={() => setActiveMode(tab.mode)}
            className={`px-3 py-1.5 text-xs font-medium transition-colors border-b-2 -mb-px ${
              activeMode === tab.mode
                ? "border-brand text-brand"
                : "border-transparent text-txt-muted hover:text-txt-secondary"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Mode 1: Visual builder */}
      {activeMode === "visual" && (
        <div className="space-y-2">
          <h2 className="oc-card-label">Define Fields</h2>
          {fields.map((field, index) => (
            <div key={index} className="oc-field-builder-row">
              <input
                type="text"
                value={field.name}
                onChange={(e) => updateField(index, { name: e.target.value })}
                placeholder="Field name"
                className="flex-1 min-w-0 rounded-md border border-border px-2 py-1.5 text-sm focus:border-brand focus:ring-1 focus:ring-blue-500"
              />
              <select
                value={field.type}
                onChange={(e) => updateField(index, { type: e.target.value as FieldType })}
                className="w-24 rounded-md border border-border bg-white px-2 py-1.5 text-xs focus:border-brand focus:ring-1 focus:ring-blue-500"
              >
                {FIELD_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>
                    {t.label}
                  </option>
                ))}
              </select>
              <label className="flex items-center gap-1 text-xs text-txt-muted whitespace-nowrap">
                <input
                  type="checkbox"
                  checked={field.required}
                  onChange={(e) => updateField(index, { required: e.target.checked })}
                  className="rounded border-border"
                />
                Req
              </label>
              <button
                onClick={() => removeField(index)}
                className="p-1 text-txt-muted hover:text-state-danger transition-colors"
                aria-label="Remove field"
              >
                <svg
                  width="14"
                  height="14"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth={2}
                >
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          ))}

          <div className="flex items-center gap-3 pt-1">
            <button
              onClick={addField}
              className="flex items-center gap-1 text-xs text-brand hover:text-brand transition-colors"
            >
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
              </svg>
              Add field
            </button>
            <label className="flex items-center gap-1.5 text-xs text-txt-muted">
              <input
                type="checkbox"
                checked={saveAsReusable}
                onChange={(e) => setSaveAsReusable(e.target.checked)}
                className="rounded border-border"
              />
              Save as reusable schema
            </label>
            {validFieldCount > 0 && (
              <Button size="sm" onClick={() => applyFields(fields)}>
                Apply ({validFieldCount} field{validFieldCount !== 1 ? "s" : ""})
              </Button>
            )}
          </div>
        </div>
      )}

      {/* Mode 2: Import from URL */}
      {activeMode === "url" && (
        <div className="space-y-3">
          <p className="text-xs text-txt-muted">
            Enter the URL of a JSON Schema. The schema will be fetched and loaded into the visual
            builder for review.
          </p>
          <div className="flex gap-2">
            <input
              type="url"
              value={schemaUrl}
              onChange={(e) => setSchemaUrl(e.target.value)}
              placeholder="https://example.com/schema.json"
              className="flex-1 rounded-md border border-border px-3 py-2 text-sm shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500"
              onKeyDown={(e) => {
                if (e.key === "Enter") handleFetchUrl();
              }}
            />
            <Button size="sm" onClick={handleFetchUrl} disabled={urlFetching}>
              {urlFetching ? "Fetching..." : "Fetch"}
            </Button>
          </div>
          {urlError && <p className="text-xs text-state-danger">{urlError}</p>}
        </div>
      )}

      {/* Mode 3: Paste / Upload */}
      {activeMode === "paste" && (
        <div className="space-y-3">
          <p className="text-xs text-txt-muted">
            Paste a JSON Schema or sample JSON object. The type is auto-detected: schemas are parsed
            directly, sample objects have their field types inferred.
          </p>
          <textarea
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
            placeholder={
              '{\n  "fullName": "Jane Doe",\n  "email": "jane@example.com",\n  "graduationDate": "2024-06-15"\n}'
            }
            rows={8}
            className="block w-full rounded-md border border-border px-3 py-2 text-sm font-mono shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500"
          />
          {jsonError && <p className="text-xs text-state-danger">{jsonError}</p>}
          <div className="flex items-center gap-3">
            <Button size="sm" onClick={handleJsonParse} disabled={!jsonText.trim()}>
              Infer Fields
            </Button>
            <button
              onClick={handleFileUpload}
              className="flex items-center gap-1 text-xs text-brand hover:text-brand transition-colors"
            >
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5"
                />
              </svg>
              Upload file
            </button>
          </div>
        </div>
      )}
    </Card>
  );
}
