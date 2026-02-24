/**
 * SchemaSelector — lists built-in schemas from @opencred/schema-engine
 * and allows the user to select one for credential issuance.
 *
 * Schemas are loaded from the main process via IPC (schema-engine runs
 * in the main process). The component communicates the selected schema
 * and its field definitions to parent components via callbacks.
 */

import { useState, useEffect, useCallback } from "react";

interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  format?: string;
}

interface Props {
  onSchemaSelect?: (schemaId: string, fields: SchemaField[]) => void;
  selectedSchema?: string;
}

/** Extract field information from a JSON Schema definition. */
function extractFields(schema: Record<string, unknown>): SchemaField[] {
  const properties = schema["properties"] as Record<string, Record<string, unknown>> | undefined;
  const required = (schema["required"] as string[]) ?? [];

  if (!properties) return [];

  return Object.entries(properties).map(([name, prop]) => ({
    name,
    type: String(prop["type"] ?? "string"),
    required: required.includes(name),
    format: prop["format"] as string | undefined,
  }));
}

/** Map schema IDs to user-friendly display labels. */
const SCHEMA_LABELS: Record<string, string> = {
  education: "Education Credential",
  employment: "Employment Credential",
  identity: "Identity Credential",
  health: "Health Credential",
  business: "Business Credential",
};

export function SchemaSelector({ onSchemaSelect, selectedSchema }: Props) {
  const [schemas, setSchemas] = useState<string[]>([]);
  const [selected, setSelected] = useState<string>(selectedSchema ?? "");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadSchemas = useCallback(async () => {
    try {
      const response = await window.opencred.listSchemas();
      setSchemas(response.schemas);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load schemas.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadSchemas();
  }, [loadSchemas]);

  async function handleSelect(schemaId: string) {
    setSelected(schemaId);
    setError(null);

    if (!schemaId) {
      return;
    }

    try {
      const response = await window.opencred.getSchema({ schemaId });
      const fields = extractFields(response.schema);
      onSchemaSelect?.(schemaId, fields);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load schema.");
    }
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4">
      <h2 className="text-sm font-medium text-gray-700">Credential Type</h2>
      <p className="mt-1 text-xs text-gray-500">
        Select a credential schema to define the subject fields.
      </p>

      {loading ? (
        <div className="mt-2 text-sm text-gray-400">Loading schemas...</div>
      ) : (
        <select
          value={selected}
          onChange={(e) => void handleSelect(e.target.value)}
          className="mt-2 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-700 shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        >
          <option value="">Select a credential type...</option>
          {schemas.map((schemaId) => (
            <option key={schemaId} value={schemaId}>
              {SCHEMA_LABELS[schemaId] ?? schemaId}
            </option>
          ))}
        </select>
      )}

      {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
    </div>
  );
}
