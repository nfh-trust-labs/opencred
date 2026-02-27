import { useState, useEffect, useCallback } from "react";
import { SchemaSelector } from "./SchemaSelector";
import { KeyImport } from "./KeyImport";
import { OpenCredClient } from "../api/client";
import type {
  BatchStatusResponse,
  BatchResultsResponse,
  BatchSignaturesResponse,
} from "../api/client";
import type { ImportedKey } from "./KeyImport";
import { signData, base64urlDecode, base64urlEncode } from "../crypto/webcrypto";

interface Props {
  apiUrl: string;
  token: string;
}

type Step = "upload" | "submitting" | "progress" | "signing" | "results";

export function BatchIssuance({ apiUrl, token }: Props) {
  const [step, setStep] = useState<Step>("upload");
  const [schemaId, setSchemaId] = useState("");
  const [signingFlow, setSigningFlow] = useState<"interface" | "delegated">("delegated");
  const [delegationId, setDelegationId] = useState("");
  const [importedKey, setImportedKey] = useState<ImportedKey | null>(null);
  const [csvFile, setCsvFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Job state
  const [jobId, setJobId] = useState<string | null>(null);
  const [jobStatus, setJobStatus] = useState<BatchStatusResponse | null>(null);
  const [jobResults, setJobResults] = useState<BatchResultsResponse | null>(null);
  const [signatureResults, setSignatureResults] = useState<BatchSignaturesResponse | null>(null);
  const [pollingActive, setPollingActive] = useState(false);

  const pollStatus = useCallback(async () => {
    if (!jobId) return;
    try {
      const client = new OpenCredClient(apiUrl, token || undefined);
      const status = await client.batchStatus(jobId);
      setJobStatus(status);

      if (status.status === "completed" || status.status === "failed") {
        setPollingActive(false);
        const results = await client.batchResults(jobId);
        setJobResults(results);
        setStep("results");
      } else if (status.status === "awaiting_signatures") {
        setPollingActive(false);
        const results = await client.batchResults(jobId);
        setJobResults(results);
        setStep("signing");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to poll job status");
      setPollingActive(false);
    }
  }, [jobId, apiUrl, token]);

  useEffect(() => {
    if (!pollingActive) return;
    const interval = setInterval(pollStatus, 2000);
    return () => clearInterval(interval);
  }, [pollingActive, pollStatus]);

  async function handleSubmit() {
    if (!csvFile || !schemaId) return;
    setStep("submitting");
    setError(null);

    try {
      const client = new OpenCredClient(apiUrl, token || undefined);
      const formData = new FormData();
      formData.append("file", csvFile);
      formData.append("schema", schemaId);
      formData.append("signingFlow", signingFlow);

      if (signingFlow === "delegated" && delegationId) {
        formData.append("delegationId", delegationId);
      }

      const res = await client.batchSubmitCsv(formData);
      setJobId(res.jobId);
      setStep("progress");
      setPollingActive(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Batch submission failed");
      setStep("upload");
    }
  }

  async function handleSignAll() {
    if (!jobId || !jobResults || !importedKey) return;
    setError(null);

    try {
      const cryptoKey = importedKey.signingKey;
      const itemsToSign = jobResults.results.filter((r) => r.status === "success" && r.dataToSign);

      const signatures: Array<{ index: number; signature: string }> = [];
      for (const item of itemsToSign) {
        const dataBytes = base64urlDecode(item.dataToSign!);
        const sig = await signData(cryptoKey, dataBytes);
        signatures.push({
          index: item.index,
          signature: base64urlEncode(sig),
        });
      }

      const client = new OpenCredClient(apiUrl, token || undefined);
      const res = await client.batchSignatures(jobId, signatures);
      setSignatureResults(res);
      setStep("results");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Batch signing failed");
    }
  }

  function handleDownloadResults() {
    const data = signatureResults ?? jobResults;
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `batch-results-${jobId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleReset() {
    setStep("upload");
    setSchemaId("");
    setCsvFile(null);
    setDelegationId("");
    setImportedKey(null);
    setJobId(null);
    setJobStatus(null);
    setJobResults(null);
    setSignatureResults(null);
    setError(null);
    setPollingActive(false);
  }

  function isUploadValid(): boolean {
    if (!csvFile || !schemaId) return false;
    if (signingFlow === "delegated" && !delegationId.trim()) return false;
    return true;
  }

  return (
    <div className="space-y-6">
      {step === "upload" && (
        <>
          <div className="rounded-lg border border-blue-100 bg-blue-50 p-4">
            <p className="text-sm text-blue-800">
              Upload a CSV file with credential subject data. Each row becomes a credential.
            </p>
          </div>

          <SchemaSelector value={schemaId} onChange={setSchemaId} />

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Signing Flow</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="radio"
                  name="signing-flow"
                  checked={signingFlow === "delegated"}
                  onChange={() => setSigningFlow("delegated")}
                  className="text-blue-600"
                />
                Delegated Signing
              </label>
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="radio"
                  name="signing-flow"
                  checked={signingFlow === "interface"}
                  onChange={() => setSigningFlow("interface")}
                  className="text-blue-600"
                />
                Interface Signing
              </label>
            </div>
          </div>

          {signingFlow === "delegated" && (
            <div>
              <label
                htmlFor="batch-delegation-id"
                className="block text-sm font-medium text-gray-700"
              >
                Delegation ID
              </label>
              <input
                id="batch-delegation-id"
                type="text"
                value={delegationId}
                onChange={(e) => setDelegationId(e.target.value)}
                placeholder="Enter your delegation ID..."
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
          )}

          {signingFlow === "interface" && <KeyImport onKeyImported={setImportedKey} />}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">CSV File</label>
            <label className="flex cursor-pointer items-center justify-center rounded-lg border-2 border-dashed border-gray-300 p-6 hover:border-gray-400">
              <div className="text-center">
                <p className="text-sm text-gray-600">
                  {csvFile ? csvFile.name : "Click to select CSV file"}
                </p>
                {csvFile && (
                  <p className="text-xs text-gray-400 mt-1">
                    {(csvFile.size / 1024).toFixed(1)} KB
                  </p>
                )}
              </div>
              <input
                type="file"
                accept=".csv"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) setCsvFile(file);
                }}
              />
            </label>
          </div>

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          <button
            type="button"
            onClick={handleSubmit}
            disabled={!isUploadValid()}
            className="w-full rounded-md bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
          >
            Submit Batch Job
          </button>
        </>
      )}

      {step === "submitting" && (
        <div className="text-center py-12">
          <p className="text-sm text-gray-600">Submitting batch job...</p>
        </div>
      )}

      {step === "progress" && jobStatus && (
        <div className="space-y-4">
          <div className="rounded-lg border border-blue-200 bg-blue-50 p-4">
            <p className="text-sm font-medium text-blue-800">
              Job {jobId} — {jobStatus.status}
            </p>
          </div>
          <div>
            <div className="flex justify-between text-xs text-gray-600 mb-1">
              <span>Progress</span>
              <span>
                {jobStatus.processedCredentials}/{jobStatus.totalCredentials}
              </span>
            </div>
            <div className="h-2 w-full rounded-full bg-gray-200">
              <div
                className="h-2 rounded-full bg-blue-600 transition-all"
                style={{ width: `${Math.round(jobStatus.progress * 100)}%` }}
              />
            </div>
          </div>
          <p className="text-xs text-gray-500">Polling for updates...</p>
        </div>
      )}

      {step === "signing" && jobResults && (
        <div className="space-y-4">
          <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-4">
            <p className="text-sm font-medium text-yellow-800">
              Awaiting signatures for {jobResults.results.filter((r) => r.dataToSign).length}{" "}
              credentials
            </p>
          </div>

          {!importedKey && <KeyImport onKeyImported={setImportedKey} />}

          {error && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3">
              <p className="text-sm text-red-700">{error}</p>
            </div>
          )}

          <button
            type="button"
            onClick={handleSignAll}
            disabled={!importedKey}
            className="w-full rounded-md bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
          >
            Sign All Credentials
          </button>
        </div>
      )}

      {step === "results" && (
        <div className="space-y-4">
          <div className="rounded-lg border border-green-200 bg-green-50 p-4">
            <p className="text-sm font-medium text-green-800">Batch job complete</p>
            {jobStatus && (
              <p className="text-xs text-green-600 mt-1">
                {jobStatus.processedCredentials - jobStatus.failedCredentials} succeeded,{" "}
                {jobStatus.failedCredentials} failed of {jobStatus.totalCredentials} total
              </p>
            )}
          </div>

          {(signatureResults ?? jobResults) && (
            <div className="max-h-64 overflow-auto rounded-lg border border-gray-200 bg-white">
              {(signatureResults?.results ?? jobResults?.results ?? []).map((result, idx) => (
                <div
                  key={idx}
                  className={`flex items-center justify-between px-4 py-2 border-b border-gray-100 last:border-0 ${
                    result.status === "success" ? "bg-green-50" : "bg-red-50"
                  }`}
                >
                  <span className="text-xs text-gray-700">Row {result.index + 1}</span>
                  <span
                    className={`text-xs font-medium ${
                      result.status === "success" ? "text-green-700" : "text-red-700"
                    }`}
                  >
                    {result.status === "success" ? "Success" : (result.error ?? "Failed")}
                  </span>
                </div>
              ))}
            </div>
          )}

          <div className="flex gap-3">
            <button
              type="button"
              onClick={handleDownloadResults}
              className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700"
            >
              Download Results
            </button>
            <button
              type="button"
              onClick={handleReset}
              className="rounded-md border border-gray-300 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50"
            >
              New Batch
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
