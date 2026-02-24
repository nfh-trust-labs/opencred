import { useState } from "react";
import { SchemaSelector } from "./SchemaSelector";
import { CredentialForm } from "./CredentialForm";
import { getSchema } from "../schemas";
import { OpenCredClient } from "../api/client";

interface Props {
  apiUrl: string;
  token: string;
}

type Step = "setup" | "form" | "issuing" | "done";

export function DelegatedIssuance({ apiUrl, token }: Props) {
  const [step, setStep] = useState<Step>("setup");
  const [delegationId, setDelegationId] = useState("");
  const [schemaId, setSchemaId] = useState("");
  const [subjectValues, setSubjectValues] = useState<Record<string, string>>({});
  const [validFrom, setValidFrom] = useState(new Date().toISOString().split("T")[0]);
  const [validUntil, setValidUntil] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [credential, setCredential] = useState<Record<string, unknown> | null>(null);
  const [credentialHash, setCredentialHash] = useState<string | null>(null);

  const schema = schemaId ? getSchema(schemaId) : null;

  function handleSchemaChange(id: string) {
    setSchemaId(id);
    setSubjectValues({});
  }

  function handleFieldChange(field: string, value: string) {
    setSubjectValues((prev) => ({ ...prev, [field]: value }));
  }

  function handleProceedToForm() {
    if (!delegationId.trim()) return;
    setStep("form");
  }

  function isFormValid(): boolean {
    if (!schema || !delegationId.trim()) return false;
    return schema.fields
      .filter((f) => f.required)
      .every((f) => (subjectValues[f.name] ?? "").trim() !== "");
  }

  async function handleIssue() {
    if (!schema) return;

    setStep("issuing");
    setError(null);
    setCredential(null);

    try {
      const client = new OpenCredClient(apiUrl, token || undefined);
      const res = await client.issueDelegated(
        delegationId,
        schemaId,
        { ...subjectValues },
        validFrom ? new Date(validFrom).toISOString() : undefined,
        validUntil ? new Date(validUntil).toISOString() : undefined,
      );

      setCredential(res.credential);
      setCredentialHash(res.credentialHash);
      setStep("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delegated issuance failed");
      setStep("form");
    }
  }

  function handleDownload() {
    if (!credential) return;
    const blob = new Blob([JSON.stringify(credential, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "credential-delegated.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleReset() {
    setStep("setup");
    setDelegationId("");
    setSchemaId("");
    setSubjectValues({});
    setCredential(null);
    setCredentialHash(null);
    setError(null);
  }

  if (step === "done" && credential) {
    return (
      <div className="space-y-4">
        <div className="rounded-lg border border-green-200 bg-green-50 p-4">
          <p className="text-sm font-medium text-green-800">
            Credential issued via delegated signing
          </p>
          {credentialHash && <p className="mt-1 text-xs text-green-600">Hash: {credentialHash}</p>}
        </div>
        <pre className="max-h-96 overflow-auto rounded-lg border border-gray-200 bg-gray-900 p-4 text-xs text-gray-100">
          {JSON.stringify(credential, null, 2)}
        </pre>
        <div className="flex gap-3">
          <button
            type="button"
            onClick={handleDownload}
            className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
          >
            Download JSON
          </button>
          <button
            type="button"
            onClick={handleReset}
            className="rounded-md border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50"
          >
            Issue Another
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="rounded-lg border border-blue-100 bg-blue-50 p-4">
        <p className="text-sm text-blue-800">
          Delegated issuance uses an OpenCred-managed signing key. You need a delegation ID from the
          onboarding process.
        </p>
      </div>

      {step === "setup" && (
        <div className="space-y-4">
          <div>
            <label htmlFor="delegation-id" className="block text-sm font-medium text-gray-700">
              Delegation ID
            </label>
            <input
              id="delegation-id"
              type="text"
              value={delegationId}
              onChange={(e) => setDelegationId(e.target.value)}
              placeholder="Enter your delegation ID..."
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>
          <button
            type="button"
            onClick={handleProceedToForm}
            disabled={!delegationId.trim()}
            className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
          >
            Continue
          </button>
        </div>
      )}

      {(step === "form" || step === "issuing") && (
        <>
          <div className="rounded-lg border border-gray-200 bg-gray-50 p-3">
            <p className="text-xs text-gray-600">
              Delegation ID: <span className="font-mono">{delegationId}</span>
            </p>
          </div>

          <SchemaSelector value={schemaId} onChange={handleSchemaChange} />

          {schema && (
            <CredentialForm schema={schema} values={subjectValues} onChange={handleFieldChange} />
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label
                htmlFor="delegated-valid-from"
                className="block text-sm font-medium text-gray-700"
              >
                Valid From
              </label>
              <input
                id="delegated-valid-from"
                type="date"
                value={validFrom}
                onChange={(e) => setValidFrom(e.target.value)}
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div>
              <label
                htmlFor="delegated-valid-until"
                className="block text-sm font-medium text-gray-700"
              >
                Valid Until (optional)
              </label>
              <input
                id="delegated-valid-until"
                type="date"
                value={validUntil}
                onChange={(e) => setValidUntil(e.target.value)}
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
          </div>

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          <button
            type="button"
            onClick={handleIssue}
            disabled={!isFormValid() || step === "issuing"}
            className="w-full rounded-md bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
          >
            {step === "issuing" ? "Issuing..." : "Issue Credential (Delegated)"}
          </button>
        </>
      )}
    </div>
  );
}
