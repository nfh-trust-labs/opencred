import type { VerifyResponse } from "../api/client";

interface Props {
  result: VerifyResponse;
}

const STATUS_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  VALID: { bg: "bg-green-100", text: "text-green-800", label: "VALID" },
  REVOKED: { bg: "bg-red-100", text: "text-red-800", label: "REVOKED" },
  EXPIRED: { bg: "bg-yellow-100", text: "text-yellow-800", label: "EXPIRED" },
  INVALID: { bg: "bg-red-100", text: "text-red-800", label: "INVALID" },
  UNRESOLVABLE: { bg: "bg-gray-100", text: "text-gray-800", label: "UNRESOLVABLE" },
  DELEGATION_INVALID: {
    bg: "bg-orange-100",
    text: "text-orange-800",
    label: "DELEGATION INVALID",
  },
};

function CheckRow({ name, passed, detail }: { name: string; passed: boolean; detail?: string }) {
  return (
    <div className="flex items-start justify-between py-2 border-b border-gray-100 last:border-0">
      <div>
        <span className="text-sm font-medium text-gray-700 capitalize">{name}</span>
        {detail && <p className="text-xs text-gray-500 mt-0.5">{detail}</p>}
      </div>
      <span
        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
          passed ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"
        }`}
      >
        {passed ? "Pass" : "Fail"}
      </span>
    </div>
  );
}

export function VerificationResult({ result }: Props) {
  const style = STATUS_STYLES[result.status] ?? STATUS_STYLES.INVALID;

  return (
    <div className="space-y-4">
      <div className={`rounded-lg p-4 ${style.bg}`}>
        <p className={`text-lg font-semibold ${style.text}`} data-testid="verification-status">
          {style.label}
        </p>
      </div>
      <div className="rounded-lg border border-gray-200 bg-white p-4">
        <h3 className="text-sm font-medium text-gray-900 mb-2">Verification Checks</h3>
        <CheckRow name="signature" {...result.checks.signature} />
        <CheckRow name="expiry" {...result.checks.expiry} />
        <CheckRow name="revocation" {...result.checks.revocation} />
        {result.checks.dscChain && <CheckRow name="DSC chain" {...result.checks.dscChain} />}
        {result.checks.delegation && <CheckRow name="delegation" {...result.checks.delegation} />}
      </div>

      {result.delegationChain && result.delegationChain.length > 0 && (
        <div className="rounded-lg border border-gray-200 bg-white p-4">
          <h3 className="text-sm font-medium text-gray-900 mb-2">Delegation Chain</h3>
          <div className="space-y-3">
            {result.delegationChain.map((entry, idx) => (
              <div key={idx} className="rounded border border-gray-100 bg-gray-50 p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className="inline-flex items-center rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700">
                    Level {idx + 1}
                  </span>
                </div>
                <dl className="text-xs text-gray-600 space-y-1">
                  <div className="flex gap-2">
                    <dt className="font-medium text-gray-700 shrink-0">Delegation ID:</dt>
                    <dd className="font-mono truncate">{entry.delegationId}</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium text-gray-700 shrink-0">Issuer:</dt>
                    <dd className="font-mono truncate">{entry.issuer}</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium text-gray-700 shrink-0">Scope:</dt>
                    <dd>{entry.scope.join(", ")}</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium text-gray-700 shrink-0">Valid:</dt>
                    <dd>
                      {entry.validFrom} — {entry.validUntil}
                    </dd>
                  </div>
                </dl>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
