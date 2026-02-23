import type { CredentialSchema } from "../schemas";

interface Props {
  schema: CredentialSchema;
  values: Record<string, string>;
  onChange: (field: string, value: string) => void;
}

export function CredentialForm({ schema, values, onChange }: Props) {
  return (
    <fieldset className="space-y-3">
      <legend className="text-sm font-medium text-gray-700">{schema.title} — Subject Fields</legend>
      {schema.fields.map((field) => (
        <div key={field.name}>
          <label htmlFor={`field-${field.name}`} className="block text-sm text-gray-600">
            {field.label}
            {field.required && <span className="text-red-500 ml-0.5">*</span>}
          </label>
          <input
            id={`field-${field.name}`}
            type={field.format === "date" ? "date" : "text"}
            required={field.required}
            value={values[field.name] ?? ""}
            onChange={(e) => onChange(field.name, e.target.value)}
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
        </div>
      ))}
    </fieldset>
  );
}
