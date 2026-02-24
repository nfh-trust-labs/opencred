/**
 * CredentialBuilder — placeholder for the desktop app.
 *
 * This mirrors the web app's CredentialBuilder component. In the desktop app,
 * credential building and signing happens locally in the main process via IPC.
 * The full implementation will be added in issue #37.
 */
export function CredentialBuilder() {
  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4">
      <h2 className="text-sm font-medium text-gray-700">Build & Sign</h2>
      <p className="mt-1 text-sm text-gray-500">
        Local credential building and signing will be available once the desktop signing workflow is
        implemented (see issue #37). Keys never leave this machine.
      </p>
      <button
        disabled
        className="mt-3 rounded-md bg-blue-600 px-4 py-2 text-sm text-white opacity-50 cursor-not-allowed"
      >
        Build & Sign Credential
      </button>
    </div>
  );
}
