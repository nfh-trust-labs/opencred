/**
 * CredentialForm — dynamic form fields based on selected schema.
 *
 * Renders input fields for each property defined in the credential schema.
 * Communicates the form values to parent components via callbacks.
 */

import { useState, useEffect } from "react";

interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  format?: string;
}

interface Props {
  fields: SchemaField[];
  values?: Record<string, string>;
  onChange?: (values: Record<string, string>) => void;
  disabled?: boolean;
}

/** Map field format hints to HTML input types. */
function inputTypeForField(field: SchemaField): string {
  if (field.format === "date") return "date";
  if (field.format === "date-time") return "datetime-local";
  if (field.format === "email") return "email";
  if (field.format === "uri") return "url";
  if (field.type === "number" || field.type === "integer") return "number";
  return "text";
}

/** Capitalize and split camelCase field names for display. */
function labelForField(name: string): string {
  return name.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, (c) => c.toUpperCase());
}

export function CredentialForm({ fields, values: externalValues, onChange, disabled }: Props) {
  const [values, setValues] = useState<Record<string, string>>(externalValues ?? {});

  useEffect(() => {
    if (externalValues) {
      setValues(externalValues);
    }
  }, [externalValues]);

  function handleChange(fieldName: string, value: string) {
    const updated = { ...values, [fieldName]: value };
    setValues(updated);
    onChange?.(updated);
  }

  if (fields.length === 0) {
    return (
      <div className="rounded-lg border border-border-light bg-white p-4">
        <h2 className="text-sm font-medium text-txt-secondary">Credential Details</h2>
        <p className="mt-1 text-sm text-txt-muted">
          Select a credential type above to see the form fields.
        </p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border-light bg-white p-4">
      <h2 className="text-sm font-medium text-txt-secondary mb-3">Credential Details</h2>
      <div className="space-y-3">
        {fields.map((field) => (
          <div key={field.name}>
            <label
              htmlFor={`field-${field.name}`}
              className="block text-xs font-medium text-txt-secondary"
            >
              {labelForField(field.name)}
              {field.required && <span className="text-state-danger ml-0.5">*</span>}
            </label>
            <input
              id={`field-${field.name}`}
              type={inputTypeForField(field)}
              value={values[field.name] ?? ""}
              onChange={(e) => handleChange(field.name, e.target.value)}
              required={field.required}
              disabled={disabled}
              placeholder={`Enter ${labelForField(field.name).toLowerCase()}...`}
              className="mt-1 block w-full rounded-md border border-border px-3 py-2 text-sm shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500 disabled:bg-surface-warm disabled:text-txt-muted"
            />
          </div>
        ))}
      </div>
    </div>
  );
}
