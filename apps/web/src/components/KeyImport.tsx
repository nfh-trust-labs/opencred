import { useState } from "react";
import {
  importJwkFile,
  importPemFile,
  importPfxFile,
  detectKeyFormat,
  type ImportedKeyResult,
  type CertificateInfo,
} from "../crypto/webcrypto";

export interface ImportedKey {
  signingKey: CryptoKey;
  publicKeyId: string;
  algorithm?: string;
  certificateChain?: string[];
  certificateInfo?: CertificateInfo;
}

interface Props {
  onKeyImported: (key: ImportedKey) => void;
}

export function KeyImport({ onKeyImported }: Props) {
  const [raw, setRaw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [imported, setImported] = useState(false);
  const [pfxPassword, setPfxPassword] = useState("");
  const [showPasswordInput, setShowPasswordInput] = useState(false);
  const [pendingPfxBuffer, setPendingPfxBuffer] = useState<ArrayBuffer | null>(null);
  const [certInfo, setCertInfo] = useState<CertificateInfo | null>(null);
  const [detectedFormat, setDetectedFormat] = useState<string | null>(null);

  function handleResult(result: ImportedKeyResult) {
    onKeyImported({
      signingKey: result.signingKey,
      publicKeyId: result.publicKeyId,
      algorithm: result.algorithm,
      certificateChain: result.certificateChain,
      certificateInfo: result.certificateInfo,
    });
    setImported(true);
    setCertInfo(result.certificateInfo ?? null);
  }

  async function handleImport() {
    setError(null);
    setImported(false);
    setCertInfo(null);
    try {
      const format = detectKeyFormat(raw);
      if (format === "pem") {
        handleResult(await importPemFile(raw));
      } else {
        handleResult(await importJwkFile(raw));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to import");
    }
  }

  async function handleFile(file: File) {
    setError(null);
    setImported(false);
    setCertInfo(null);

    const ext = file.name.toLowerCase().split(".").pop() ?? "";
    const isPfx = ext === "pfx" || ext === "p12";

    if (isPfx) {
      setDetectedFormat("pfx");
      const buffer = await file.arrayBuffer();
      setPendingPfxBuffer(buffer);
      setShowPasswordInput(true);
      return;
    }

    const reader = new FileReader();
    reader.onload = async () => {
      const text = reader.result as string;
      setRaw(text);
      const format = detectKeyFormat(text);
      setDetectedFormat(format === "unknown" ? null : format);
      try {
        if (format === "pem") {
          handleResult(await importPemFile(text));
        } else {
          handleResult(await importJwkFile(text));
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to import");
      }
    };
    reader.readAsText(file);
  }

  async function handlePfxDecrypt() {
    if (!pendingPfxBuffer) return;
    setError(null);
    try {
      handleResult(await importPfxFile(pendingPfxBuffer, pfxPassword));
      setShowPasswordInput(false);
      setPendingPfxBuffer(null);
      setPfxPassword("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to import PFX");
    }
  }

  return (
    <div className="space-y-2">
      <label htmlFor="key-input" className="block text-sm font-medium text-gray-700">
        Signing Key (EC P-256/P-384, RSA — JWK or PEM)
      </label>
      <textarea
        id="key-input"
        rows={6}
        value={raw}
        onChange={(e) => {
          setRaw(e.target.value);
          setImported(false);
          setCertInfo(null);
        }}
        placeholder="Paste a JWK or PEM, or upload a .pfx/.p12/.pem/.json file..."
        className="block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
      />
      <div className="flex items-center gap-3 flex-wrap">
        <button
          type="button"
          onClick={handleImport}
          disabled={!raw.trim()}
          className="rounded-md bg-gray-700 px-3 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
        >
          Import Key
        </button>
        <label className="cursor-pointer rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50">
          Upload file
          <input
            type="file"
            accept=".json,.jwk,.pem,.key,.pfx,.p12"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFile(file);
            }}
          />
        </label>
        {detectedFormat && (
          <span className="text-xs text-gray-500">Format: {detectedFormat.toUpperCase()}</span>
        )}
        {imported && <span className="text-sm text-green-600">Key imported</span>}
      </div>

      {showPasswordInput && (
        <div className="flex items-center gap-2 mt-2">
          <input
            type="password"
            value={pfxPassword}
            onChange={(e) => setPfxPassword(e.target.value)}
            placeholder="PFX password..."
            onKeyDown={(e) => e.key === "Enter" && handlePfxDecrypt()}
            className="rounded-md border border-gray-300 px-3 py-1.5 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
          <button
            type="button"
            onClick={handlePfxDecrypt}
            className="rounded-md bg-gray-700 px-3 py-1.5 text-sm text-white hover:bg-gray-800"
          >
            Decrypt
          </button>
        </div>
      )}

      {certInfo && (
        <div className="rounded-md border border-blue-200 bg-blue-50 p-3 text-xs space-y-1">
          <p className="font-medium text-blue-800">Certificate Info</p>
          <p><span className="text-gray-600">Subject:</span> {certInfo.subject}</p>
          <p><span className="text-gray-600">Issuer:</span> {certInfo.issuer}</p>
          <p><span className="text-gray-600">Valid:</span> {certInfo.validFrom} — {certInfo.validUntil}</p>
          <p><span className="text-gray-600">Algorithm:</span> {certInfo.algorithm}</p>
        </div>
      )}

      {error && <p className="text-sm text-red-600">{error}</p>}
    </div>
  );
}
