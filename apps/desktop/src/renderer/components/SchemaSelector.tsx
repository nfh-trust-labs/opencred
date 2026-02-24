/**
 * SchemaSelector — placeholder for the desktop app.
 *
 * This mirrors the web app's SchemaSelector component. The full implementation
 * will be added in a follow-up issue when the desktop-specific schema
 * integration is built out.
 */
export function SchemaSelector() {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4">
      <h2 className="text-sm font-medium text-gray-700">Credential Type</h2>
      <p className="mt-1 text-sm text-gray-500">
        Schema selection will be available once the desktop credential workflow is implemented (see
        issue #37).
      </p>
      <select
        disabled
        className="mt-2 block w-full rounded-md border border-gray-300 bg-gray-50 px-3 py-2 text-sm text-gray-400"
      >
        <option>Select a credential type...</option>
      </select>
    </div>
  );
}
