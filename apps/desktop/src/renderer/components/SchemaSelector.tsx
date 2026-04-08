/**
 * SchemaSelector — lists built-in schemas and custom schemas,
 * allowing the user to select one for credential issuance.
 *
 * Built-in schemas come from @opencred/schema-engine via IPC.
 * Custom schemas come from the local credential store (user-defined).
 */

import { useState, useEffect, useCallback } from "react";
import { formatSchemaLabel } from "../utils/schema-label.js";

interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  format?: string;
}

interface SchemaOption {
  id: string;
  label: string;
  isCustom: boolean;
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

export function SchemaSelector({ onSchemaSelect, selectedSchema }: Props) {
  const [schemaOptions, setSchemaOptions] = useState<SchemaOption[]>([]);
  const [selected, setSelected] = useState<string>(selectedSchema ?? "");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadSchemas = useCallback(async () => {
    try {
      const [builtInResponse, customResponse] = await Promise.all([
        window.opencred.listSchemas(),
        window.opencred.customSchemaList(),
      ]);

      const options: SchemaOption[] = [
        ...builtInResponse.schemas.map((id) => ({
          id,
          label: formatSchemaLabel(id),
          isCustom: false,
        })),
        ...customResponse.schemas.map((cs) => ({
          id: cs.id,
          label: cs.name,
          isCustom: true,
        })),
      ];

      setSchemaOptions(options);
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
      // Custom schemas are stored locally, built-in schemas come from the registry
      if (schemaId.startsWith("custom:")) {
        const customRes = await window.opencred.customSchemaList();
        const match = customRes.schemas.find((s) => s.id === schemaId);
        if (match) {
          const fields = extractFields(match.schema as Record<string, unknown>);
          onSchemaSelect?.(schemaId, fields);
        } else {
          setError("Custom schema not found.");
        }
      } else {
        const response = await window.opencred.getSchema({ schemaId });
        const fields = extractFields(response.schema);
        onSchemaSelect?.(schemaId, fields);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load schema.");
    }
  }

  const builtInOptions = schemaOptions.filter((o) => !o.isCustom);
  const customOptions = schemaOptions.filter((o) => o.isCustom);

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
          {builtInOptions.length > 0 && (
            <optgroup label="Built-in">
              {builtInOptions.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.label}
                </option>
              ))}
            </optgroup>
          )}
          {customOptions.length > 0 && (
            <optgroup label="Custom">
              {customOptions.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.label}
                </option>
              ))}
            </optgroup>
          )}
        </select>
      )}

      {error && <p className="mt-2 text-sm text-red-600">{error}</p>}
    </div>
  );
}
