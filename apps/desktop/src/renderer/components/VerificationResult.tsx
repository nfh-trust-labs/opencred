/**
 * VerificationResult — placeholder for displaying verification outcomes.
 *
 * This mirrors the web app's VerificationResult component. It will be
 * populated with detailed verification output once the desktop verification
 * workflow is fully implemented.
 */

interface Props {
  valid: boolean;
  message: string;
}

export function VerificationResult({ valid, message }: Props) {
  return (
    <div
      className={`rounded-lg border p-4 ${
        valid
          ? "border-state-success-border bg-state-success-bg"
          : "border-state-danger-border bg-state-danger-bg"
      }`}
    >
      <h3 className={`text-sm font-medium ${valid ? "text-state-success" : "text-red-800"}`}>
        {valid ? "Valid Credential" : "Invalid Credential"}
      </h3>
      <p className={`mt-1 text-sm ${valid ? "text-state-success" : "text-state-danger"}`}>
        {message}
      </p>
    </div>
  );
}
