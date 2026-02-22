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
      </div>
    </div>
  );
}
