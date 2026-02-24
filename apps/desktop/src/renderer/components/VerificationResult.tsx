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
        valid ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"
      }`}
    >
      <h3 className={`text-sm font-medium ${valid ? "text-green-800" : "text-red-800"}`}>
        {valid ? "Valid Credential" : "Invalid Credential"}
      </h3>
      <p className={`mt-1 text-sm ${valid ? "text-green-700" : "text-red-700"}`}>{message}</p>
    </div>
  );
}
