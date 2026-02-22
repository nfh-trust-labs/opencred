import { SCHEMAS } from "../schemas";

interface Props {
  value: string;
  onChange: (schemaId: string) => void;
}

export function SchemaSelector({ value, onChange }: Props) {
  return (
    <div>
      <label htmlFor="schema-select" className="block text-sm font-medium text-gray-700">
        Credential Type
      </label>
      <select
        id="schema-select"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
      >
        <option value="">Select a credential type...</option>
        {SCHEMAS.map((s) => (
          <option key={s.id} value={s.id}>
            {s.title}
          </option>
        ))}
      </select>
    </div>
  );
}
