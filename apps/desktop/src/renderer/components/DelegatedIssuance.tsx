/**
 * DelegatedIssuance — placeholder for the desktop app.
 *
 * This mirrors the web app's DelegatedIssuance component. Delegated signing
 * in the desktop app still communicates with the OpenCred API for delegation
 * certificate management. The full implementation will be added in a
 * follow-up issue.
 */
export function DelegatedIssuance() {
  return (
    <div className="rounded-lg border border-border-light bg-white p-4 space-y-3">
      <h2 className="text-sm font-medium text-txt-secondary">Delegated Issuance</h2>
      <p className="mt-1 text-sm text-txt-muted">
        Delegated issuance allows OpenCred to sign credentials on behalf of the issuer using a
        delegation certificate. This feature requires a network connection to the OpenCred API and
        will be fully implemented in a follow-up issue.
      </p>
    </div>
  );
}
