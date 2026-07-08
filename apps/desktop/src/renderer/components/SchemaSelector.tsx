/**
 * SchemaSelector — lists built-in schemas and custom schemas,
 * allowing the user to select one for credential issuance.
 *
 * Built-in schemas come from @opencred/schema-engine via IPC.
 * Custom schemas come from the local credential store (user-defined).
 */

import { useState, useEffect, useCallback, useMemo } from "react";
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
  category?: string;
}

interface Props {
  onSchemaSelect?: (schemaId: string, fields: SchemaField[]) => void;
  selectedSchema?: string;
}

const CATEGORY_LABELS: Record<string, string> = {
  education: "Education",
  employment: "Employment",
  identity: "Identity",
  health: "Health",
  business: "Business",
  utility: "Utility",
  "supply-chain": "Supply Chain",
  other: "Other",
};

const CATEGORY_ORDER = [
  "education",
  "employment",
  "identity",
  "health",
  "business",
  "utility",
  "supply-chain",
  "other",
];

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
        ...builtInResponse.schemas.map((entry) => ({
          id: entry.id,
          label: formatSchemaLabel(entry.id),
          isCustom: false,
          category: entry.category,
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

  // Group built-in schemas by category
  const categorizedGroups = useMemo(() => {
    const groups: Record<string, SchemaOption[]> = {};
    for (const opt of builtInOptions) {
      const cat = opt.category ?? "other";
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(opt);
    }
    return CATEGORY_ORDER.filter((cat) => groups[cat] && groups[cat].length > 0).map((cat) => ({
      category: cat,
      label: CATEGORY_LABELS[cat] ?? cat,
      options: groups[cat],
    }));
  }, [builtInOptions]);

  return (
    <div className="rounded-lg border border-border-light bg-white p-4">
      <h2 className="text-sm font-medium text-txt-secondary">Credential Type</h2>
      <p className="mt-1 text-xs text-txt-muted">
        Select a credential schema to define the subject fields.
      </p>

      {loading ? (
        <div className="mt-2 text-sm text-txt-muted">Loading schemas...</div>
      ) : (
        <select
          value={selected}
          onChange={(e) => void handleSelect(e.target.value)}
          className="mt-2 block w-full rounded-md border border-border bg-white px-3 py-2 text-sm text-txt-secondary shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500"
        >
          <option value="">Select a credential type...</option>
          {categorizedGroups.map((group) => (
            <optgroup key={group.category} label={group.label}>
              {group.options.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.label}
                </option>
              ))}
            </optgroup>
          ))}
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

      {error && <p className="mt-2 text-sm text-state-danger">{error}</p>}
    </div>
  );
}
