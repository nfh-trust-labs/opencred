import { useState } from "react";
import type { EcJwk } from "../crypto/webcrypto";
import { parseJwk } from "../crypto/webcrypto";

interface Props {
  onKeyParsed: (jwk: EcJwk) => void;
}

const SAMPLE_PLACEHOLDER = `{
  "kty": "EC",
  "crv": "P-256",
  "x": "...",
  "y": "...",
  "d": "..."
}`;

export function KeyImport({ onKeyParsed }: Props) {
  const [raw, setRaw] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [imported, setImported] = useState(false);

  function handleImport() {
    setError(null);
    setImported(false);
    try {
      const jwk = parseJwk(raw);
      onKeyParsed(jwk);
      setImported(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to parse key");
    }
  }

  function handleFile(file: File) {
    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result as string;
      setRaw(text);
      setError(null);
      setImported(false);
      try {
        const jwk = parseJwk(text);
        onKeyParsed(jwk);
        setImported(true);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to parse key");
      }
    };
    reader.readAsText(file);
  }

  return (
    <div className="space-y-2">
      <label htmlFor="key-input" className="block text-sm font-medium text-gray-700">
        Signing Key (ECDSA P-256 JWK — private key)
      </label>
      <textarea
        id="key-input"
        rows={6}
        value={raw}
        onChange={(e) => {
          setRaw(e.target.value);
          setImported(false);
        }}
        placeholder={SAMPLE_PLACEHOLDER}
        className="block w-full rounded-md border border-gray-300 px-3 py-2 font-mono text-xs shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
      />
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={handleImport}
          disabled={!raw.trim()}
          className="rounded-md bg-gray-700 px-3 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
        >
          Import Key
        </button>
        <label className="cursor-pointer rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50">
          Upload JWK file
          <input
            type="file"
            accept=".json,.jwk"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFile(file);
            }}
          />
        </label>
        {imported && <span className="text-sm text-green-600">Key imported</span>}
      </div>
      {error && <p className="text-sm text-red-600">{error}</p>}
    </div>
  );
}
