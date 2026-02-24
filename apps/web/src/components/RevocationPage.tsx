import { useState } from "react";
import { OpenCredClient } from "../api/client";

interface Props {
  apiUrl: string;
  token: string;
}

type Mode = "single" | "batch";

interface BatchResult {
  hash: string;
  revoked: boolean;
  error?: string;
}

export function RevocationPage({ apiUrl, token }: Props) {
  const [mode, setMode] = useState<Mode>("single");

  // Single revocation state
  const [revokeInput, setRevokeInput] = useState("");
  const [inputType, setInputType] = useState<"hash" | "credential">("hash");
  const [singleLoading, setSingleLoading] = useState(false);
  const [singleResult, setSingleResult] = useState<{ revoked: boolean; hash: string } | null>(null);
  const [singleError, setSingleError] = useState<string | null>(null);

  // Batch revocation state
  const [batchHashes, setBatchHashes] = useState("");
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchResults, setBatchResults] = useState<BatchResult[] | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);

  async function handleSingleRevoke() {
    setSingleResult(null);
    setSingleError(null);
    setSingleLoading(true);

    try {
      const client = new OpenCredClient(apiUrl, token || undefined);

      let hashOrCredential: string | Record<string, unknown>;
      if (inputType === "hash") {
        hashOrCredential = revokeInput.trim();
      } else {
        try {
          hashOrCredential = JSON.parse(revokeInput) as Record<string, unknown>;
        } catch {
          throw new Error("Invalid JSON — please paste a valid credential");
        }
      }

      const res = await client.revoke(hashOrCredential);
      setSingleResult(res);
    } catch (err) {
      setSingleError(err instanceof Error ? err.message : "Revocation failed");
    } finally {
      setSingleLoading(false);
    }
  }

  function handleBatchFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      setBatchHashes(reader.result as string);
      setBatchResults(null);
      setBatchError(null);
    };
    reader.readAsText(file);
  }

  async function handleBatchRevoke() {
    setBatchResults(null);
    setBatchError(null);
    setBatchLoading(true);

    try {
      const lines = batchHashes
        .split("\n")
        .map((line) => line.trim())
        .filter((line) => line.length > 0);

      if (lines.length === 0) {
        throw new Error("No hashes provided");
      }

      const client = new OpenCredClient(apiUrl, token || undefined);
      const res = await client.batchRevoke(lines);
      setBatchResults(res.results);
    } catch (err) {
      setBatchError(err instanceof Error ? err.message : "Batch revocation failed");
    } finally {
      setBatchLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex space-x-1 bg-gray-100 rounded-lg p-1">
        <button
          type="button"
          onClick={() => setMode("single")}
          className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
            mode === "single"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Single Revocation
        </button>
        <button
          type="button"
          onClick={() => setMode("batch")}
          className={`flex-1 rounded-md py-2 text-sm font-medium transition-colors ${
            mode === "batch"
              ? "bg-white text-gray-900 shadow-sm"
              : "text-gray-500 hover:text-gray-700"
          }`}
        >
          Batch Revocation
        </button>
      </div>

      {mode === "single" && (
        <div className="space-y-4">
          <div className="flex gap-4">
            <label className="flex items-center gap-2 text-sm text-gray-700">
              <input
                type="radio"
                name="input-type"
                checked={inputType === "hash"}
                onChange={() => setInputType("hash")}
                className="text-blue-600"
              />
              Credential Hash
            </label>
            <label className="flex items-center gap-2 text-sm text-gray-700">
              <input
                type="radio"
                name="input-type"
                checked={inputType === "credential"}
                onChange={() => setInputType("credential")}
                className="text-blue-600"
              />
              Credential JSON
            </label>
          </div>

          {inputType === "hash" ? (
            <div>
              <label htmlFor="revoke-hash" className="block text-sm font-medium text-gray-700">
                Credential Hash
              </label>
              <input
                id="revoke-hash"
                type="text"
                value={revokeInput}
                onChange={(e) => {
                  setRevokeInput(e.target.value);
                  setSingleResult(null);
                }}
                placeholder="Enter credential hash..."
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
          ) : (
            <div>
              <label htmlFor="revoke-json" className="block text-sm font-medium text-gray-700">
                Credential JSON
              </label>
              <textarea
                id="revoke-json"
                rows={8}
                value={revokeInput}
                onChange={(e) => {
                  setRevokeInput(e.target.value);
                  setSingleResult(null);
                }}
                placeholder="Paste credential JSON..."
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
          )}

          <button
            type="button"
            onClick={handleSingleRevoke}
            disabled={!revokeInput.trim() || singleLoading}
            className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-40"
          >
            {singleLoading ? "Revoking..." : "Revoke Credential"}
          </button>

          {singleError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3">
              <p className="text-sm text-red-700">{singleError}</p>
            </div>
          )}

          {singleResult && (
            <div
              className={`rounded-lg border p-4 ${
                singleResult.revoked ? "border-green-200 bg-green-50" : "border-red-200 bg-red-50"
              }`}
            >
              <p
                className={`text-sm font-medium ${
                  singleResult.revoked ? "text-green-800" : "text-red-800"
                }`}
              >
                {singleResult.revoked ? "Credential revoked successfully" : "Revocation failed"}
              </p>
              <p className="mt-1 text-xs text-gray-600">Hash: {singleResult.hash}</p>
            </div>
          )}
        </div>
      )}

      {mode === "batch" && (
        <div className="space-y-4">
          <div>
            <label htmlFor="batch-hashes" className="block text-sm font-medium text-gray-700">
              Credential Hashes (one per line)
            </label>
            <textarea
              id="batch-hashes"
              rows={8}
              value={batchHashes}
              onChange={(e) => {
                setBatchHashes(e.target.value);
                setBatchResults(null);
              }}
              placeholder="Enter one hash per line..."
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleBatchRevoke}
              disabled={!batchHashes.trim() || batchLoading}
              className="rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-40"
            >
              {batchLoading ? "Revoking..." : "Revoke All"}
            </button>
            <label className="cursor-pointer rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50">
              Upload File
              <input
                type="file"
                accept=".txt,.csv"
                className="hidden"
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) handleBatchFile(file);
                }}
              />
            </label>
          </div>

          {batchError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3">
              <p className="text-sm text-red-700">{batchError}</p>
            </div>
          )}

          {batchResults && (
            <div className="space-y-2">
              <h3 className="text-sm font-medium text-gray-900">
                Results ({batchResults.filter((r) => r.revoked).length}/{batchResults.length}{" "}
                revoked)
              </h3>
              <div className="max-h-64 overflow-auto rounded-lg border border-gray-200 bg-white">
                {batchResults.map((result, idx) => (
                  <div
                    key={idx}
                    className={`flex items-center justify-between px-4 py-2 border-b border-gray-100 last:border-0 ${
                      result.revoked ? "bg-green-50" : "bg-red-50"
                    }`}
                  >
                    <span className="font-mono text-xs text-gray-700 truncate max-w-[70%]">
                      {result.hash}
                    </span>
                    <span
                      className={`text-xs font-medium ${
                        result.revoked ? "text-green-700" : "text-red-700"
                      }`}
                    >
                      {result.revoked ? "Revoked" : (result.error ?? "Failed")}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
