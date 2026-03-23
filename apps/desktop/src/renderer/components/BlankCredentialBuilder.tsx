/**
 * BlankCredentialBuilder — visual field builder for blank credentials.
 *
 * Allows users to:
 *   - Add fields with name, type, and required toggle
 *   - Switch to JSON paste mode to define schema from a sample JSON object
 *   - Output: schema fields + JSON Schema for the buildAndSign flow
 */

import { useState, useCallback } from "react";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";
import type { FieldDefinition } from "../utils/schema-inference";
import { fieldsToJsonSchema, jsonToFields } from "../utils/schema-inference";

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
  onSchemaReady: (fields: SchemaField[], schema: Record<string, unknown>, credentialName: string) => void;
}

type FieldType = FieldDefinition["type"];

const FIELD_TYPES: { value: FieldType; label: string }[] = [
  { value: "string", label: "Text" },
  { value: "number", label: "Number" },
  { value: "date", label: "Date" },
  { value: "email", label: "Email" },
  { value: "url", label: "URL" },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function BlankCredentialBuilder({ onSchemaReady }: Props) {
  const [credentialName, setCredentialName] = useState("");
  const [fields, setFields] = useState<FieldDefinition[]>([
    { name: "", type: "string", required: true },
  ]);
  const [jsonMode, setJsonMode] = useState(false);
  const [jsonText, setJsonText] = useState("");
  const [jsonError, setJsonError] = useState<string | null>(null);

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
    setFields((prev) =>
      prev.map((f, i) => (i === index ? { ...f, ...update } : f)),
    );
  }

  const applyFields = useCallback(
    (defs: FieldDefinition[], name?: string) => {
      const validFields = defs.filter((f) => f.name.trim().length > 0);
      if (validFields.length === 0) return;

      const schema = fieldsToJsonSchema(validFields);

      const schemaFields: SchemaField[] = validFields.map((f) => ({
        name: f.name,
        type: f.type === "number" ? "number" : "string",
        required: f.required,
        format:
          f.type === "date"
            ? "date"
            : f.type === "email"
              ? "email"
              : f.type === "url"
                ? "uri"
                : undefined,
      }));

      onSchemaReady(schemaFields, schema, name || credentialName || "Custom Credential");
    },
    [onSchemaReady, credentialName],
  );

  // ------------------------------------------------------------------
  // JSON mode handlers
  // ------------------------------------------------------------------

  function handleJsonParse() {
    setJsonError(null);
    try {
      const parsed = JSON.parse(jsonText);
      if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
        setJsonError("Please paste a JSON object (not an array or primitive).");
        return;
      }
      const inferred = jsonToFields(parsed as Record<string, unknown>);
      setFields(inferred);
      setJsonMode(false);
      applyFields(inferred, credentialName);
    } catch {
      setJsonError("Invalid JSON. Please check your syntax.");
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
        <label htmlFor="blank-cred-name" className="block text-xs font-medium text-gray-600">
          Credential Name <span className="text-red-500">*</span>
        </label>
        <input
          id="blank-cred-name"
          type="text"
          value={credentialName}
          onChange={(e) => setCredentialName(e.target.value)}
          placeholder="e.g. Energy Prosumer Certificate"
          className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        />
      </div>

      <div className="flex items-center justify-between">
        <h2 className="oc-card-label">Define Fields</h2>
        <button
          onClick={() => setJsonMode(!jsonMode)}
          className="text-xs text-gray-500 hover:text-gray-700 transition-colors font-mono"
        >
          {jsonMode ? "Visual builder" : "Paste JSON"}
        </button>
      </div>

      {jsonMode ? (
        /* JSON paste mode */
        <div className="space-y-3">
          <p className="text-xs text-gray-500">
            Paste a sample JSON object. Field types will be inferred automatically.
          </p>
          <textarea
            value={jsonText}
            onChange={(e) => setJsonText(e.target.value)}
            placeholder={'{\n  "fullName": "Jane Doe",\n  "email": "jane@example.com",\n  "graduationDate": "2024-06-15"\n}'}
            rows={8}
            className="block w-full rounded-md border border-gray-300 px-3 py-2 text-sm font-mono shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
          {jsonError && <p className="text-xs text-red-600">{jsonError}</p>}
          <Button size="sm" onClick={handleJsonParse}>
            Infer Fields
          </Button>
        </div>
      ) : (
        /* Visual field builder */
        <div className="space-y-2">
          {fields.map((field, index) => (
            <div key={index} className="oc-field-builder-row">
              <input
                type="text"
                value={field.name}
                onChange={(e) => updateField(index, { name: e.target.value })}
                placeholder="Field name"
                className="flex-1 min-w-0 rounded-md border border-gray-300 px-2 py-1.5 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
              <select
                value={field.type}
                onChange={(e) => updateField(index, { type: e.target.value as FieldType })}
                className="w-24 rounded-md border border-gray-300 bg-white px-2 py-1.5 text-xs focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                {FIELD_TYPES.map((t) => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
              <label className="flex items-center gap-1 text-xs text-gray-500 whitespace-nowrap">
                <input
                  type="checkbox"
                  checked={field.required}
                  onChange={(e) => updateField(index, { required: e.target.checked })}
                  className="rounded border-gray-300"
                />
                Req
              </label>
              <button
                onClick={() => removeField(index)}
                className="p-1 text-gray-300 hover:text-red-500 transition-colors"
                aria-label="Remove field"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
          ))}

          <div className="flex items-center gap-3 pt-1">
            <button
              onClick={addField}
              className="flex items-center gap-1 text-xs text-blue-600 hover:text-blue-800 transition-colors"
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" />
              </svg>
              Add field
            </button>
            {validFieldCount > 0 && (
              <Button size="sm" onClick={() => applyFields(fields)}>
                Apply ({validFieldCount} field{validFieldCount !== 1 ? "s" : ""})
              </Button>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}
