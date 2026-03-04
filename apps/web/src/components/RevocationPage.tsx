import { useState } from "react";
import { OpenCredClient } from "../api/client";

interface Props {
  apiUrl: string;
  token: string;
}

type Mode = "single" | "batch";

interface BatchHashResult {
  hash: string;
  index: number;
}

export function RevocationPage({ apiUrl, token }: Props) {
  const [mode, setMode] = useState<Mode>("single");

  // Single hash state
  const [revokeInput, setRevokeInput] = useState("");
  const [inputType, setInputType] = useState<"hash" | "credential">("hash");
  const [singleLoading, setSingleLoading] = useState(false);
  const [singleResult, setSingleResult] = useState<string | null>(null);
  const [singleError, setSingleError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Batch hash state
  const [batchInput, setBatchInput] = useState("");
  const [batchLoading, setBatchLoading] = useState(false);
  const [batchResults, setBatchResults] = useState<BatchHashResult[] | null>(null);
  const [batchError, setBatchError] = useState<string | null>(null);
  const [batchCopied, setBatchCopied] = useState(false);

  async function handleSingleHash() {
    setSingleResult(null);
    setSingleError(null);
    setCopied(false);
    setSingleLoading(true);

    try {
      if (inputType === "hash") {
        // Already a hash — just display it
        setSingleResult(revokeInput.trim());
      } else {
        let credential: Record<string, unknown>;
        try {
          credential = JSON.parse(revokeInput) as Record<string, unknown>;
        } catch {
          throw new Error("Invalid JSON — please paste a valid credential");
        }

        const client = new OpenCredClient(apiUrl, token || undefined);
        const res = await client.computeRevocationHash(credential);
        setSingleResult(res.hash);
      }
    } catch (err) {
      setSingleError(err instanceof Error ? err.message : "Hash computation failed");
    } finally {
      setSingleLoading(false);
    }
  }

  function handleBatchFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      setBatchInput(reader.result as string);
      setBatchResults(null);
      setBatchError(null);
    };
    reader.readAsText(file);
  }

  async function handleBatchHash() {
    setBatchResults(null);
    setBatchError(null);
    setBatchCopied(false);
    setBatchLoading(true);

    try {
      const text = batchInput.trim();
      if (!text) {
        throw new Error("No credentials provided");
      }

      let credentials: Record<string, unknown>[];

      // Try parsing as JSON array first
      try {
        const parsed = JSON.parse(text);
        if (Array.isArray(parsed)) {
          credentials = parsed as Record<string, unknown>[];
        } else {
          // Single credential object
          credentials = [parsed as Record<string, unknown>];
        }
      } catch {
        // Try parsing as one credential JSON per line
        const lines = text.split("\n").filter((line) => line.trim().length > 0);
        credentials = lines.map((line, idx) => {
          try {
            return JSON.parse(line) as Record<string, unknown>;
          } catch {
            throw new Error(`Invalid JSON on line ${idx + 1}`);
          }
        });
      }

      if (credentials.length === 0) {
        throw new Error("No credentials provided");
      }

      const client = new OpenCredClient(apiUrl, token || undefined);
      const res = await client.computeRevocationHashBatch(credentials);
      setBatchResults(res.hashes);
    } catch (err) {
      setBatchError(err instanceof Error ? err.message : "Batch hash computation failed");
    } finally {
      setBatchLoading(false);
    }
  }

  async function copyToClipboard(text: string) {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function copyAllHashes() {
    if (!batchResults) return;
    const text = batchResults.map((r) => r.hash).join("\n");
    await navigator.clipboard.writeText(text);
    setBatchCopied(true);
    setTimeout(() => setBatchCopied(false), 2000);
  }

  function exportHashesToFile() {
    if (!batchResults) return;
    const text = batchResults.map((r) => r.hash).join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "revocation-hashes.txt";
    a.click();
    URL.revokeObjectURL(url);
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
          Single Hash
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
          Batch Hashes
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
            onClick={handleSingleHash}
            disabled={!revokeInput.trim() || singleLoading}
            className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
          >
            {singleLoading ? "Computing..." : "Compute Hash"}
          </button>

          {singleError && (
            <div className="rounded-lg border border-red-200 bg-red-50 p-3">
              <p className="text-sm text-red-700">{singleError}</p>
            </div>
          )}

          {singleResult && (
            <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 space-y-3">
              <div className="flex items-center justify-between gap-2">
                <p className="font-mono text-sm text-gray-800 break-all">{singleResult}</p>
                <button
                  type="button"
                  onClick={() => copyToClipboard(singleResult)}
                  className="shrink-0 rounded-md border border-gray-300 bg-white px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50"
                >
                  {copied ? "Copied!" : "Copy to Clipboard"}
                </button>
              </div>
              <p className="text-xs text-gray-600">
                Publish this hash to your DeDi revocation registry to revoke the credential.
              </p>
            </div>
          )}
        </div>
      )}

      {mode === "batch" && (
        <div className="space-y-4">
          <div>
            <label htmlFor="batch-credentials" className="block text-sm font-medium text-gray-700">
              Credential JSONs (one per line or JSON array)
            </label>
            <textarea
              id="batch-credentials"
              rows={8}
              value={batchInput}
              onChange={(e) => {
                setBatchInput(e.target.value);
                setBatchResults(null);
              }}
              placeholder="Paste credential JSONs (one per line or as a JSON array)..."
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={handleBatchHash}
              disabled={!batchInput.trim() || batchLoading}
              className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
            >
              {batchLoading ? "Computing..." : "Compute Hashes"}
            </button>
            <label className="cursor-pointer rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50">
              Upload File
              <input
                type="file"
                accept=".txt,.json"
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
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-medium text-gray-900">
                  Computed Hashes ({batchResults.length})
                </h3>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={copyAllHashes}
                    className="rounded-md border border-gray-300 bg-white px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50"
                  >
                    {batchCopied ? "Copied!" : "Copy All"}
                  </button>
                  <button
                    type="button"
                    onClick={exportHashesToFile}
                    className="rounded-md border border-gray-300 bg-white px-3 py-1 text-xs font-medium text-gray-700 hover:bg-gray-50"
                  >
                    Export to File
                  </button>
                </div>
              </div>
              <div className="max-h-64 overflow-auto rounded-lg border border-gray-200 bg-white">
                {batchResults.map((result) => (
                  <div
                    key={result.index}
                    className="flex items-center justify-between px-4 py-2 border-b border-gray-100 last:border-0"
                  >
                    <span className="font-mono text-xs text-gray-700 truncate max-w-[80%]">
                      {result.hash}
                    </span>
                    <span className="text-xs text-gray-500">#{result.index + 1}</span>
                  </div>
                ))}
              </div>
              <p className="text-xs text-gray-600">
                Publish these hashes to your DeDi revocation registry to revoke the credentials.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
