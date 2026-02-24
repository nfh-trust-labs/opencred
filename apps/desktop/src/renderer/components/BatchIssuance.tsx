/**
 * BatchIssuance — placeholder for the desktop app.
 *
 * This mirrors the web app's BatchIssuance component. In the desktop app,
 * batch operations can run entirely offline using local signing. The full
 * implementation will be added in a follow-up issue.
 */
export function BatchIssuance() {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-3">
      <h2 className="text-sm font-medium text-gray-700">Batch Issuance</h2>
      <p className="mt-1 text-sm text-gray-500">
        Batch credential issuance allows you to issue multiple credentials at once from a CSV file.
        This feature will be fully implemented in a follow-up issue.
      </p>
      <button
        disabled
        className="rounded-md bg-gray-200 px-4 py-2 text-sm text-gray-400 cursor-not-allowed"
      >
        Upload CSV
      </button>
    </div>
  );
}
