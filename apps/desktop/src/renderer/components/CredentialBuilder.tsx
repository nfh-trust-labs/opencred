/**
 * CredentialBuilder — full credential builder form for the desktop app.
 *
 * Handles issuer DID, subject fields, validity dates, and revocation URL.
 * Calls IPC to build + sign the credential using the local signing flow.
 * All signing happens in the main process -- the private key never reaches
 * the renderer.
 */

import { useState, useEffect, useCallback } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { SchemaSelector } from "./SchemaSelector";
import { CredentialForm } from "./CredentialForm";

interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  format?: string;
}

export function CredentialBuilder() {
  // State
  const [schemaId, setSchemaId] = useState<string>("");
  const [schemaFields, setSchemaFields] = useState<SchemaField[]>([]);
  const [subjectValues, setSubjectValues] = useState<Record<string, string>>({});
  const [issuerDid, setIssuerDid] = useState("");
  const [subjectDid, setSubjectDid] = useState("");
  const [validFrom, setValidFrom] = useState(new Date().toISOString().split("T")[0]);
  const [validUntil, setValidUntil] = useState("");
  const [revocationUrl, setRevocationUrl] = useState("");
  const [selectedKeyId, setSelectedKeyId] = useState("");
  const [keys, setKeys] = useState<KeyMetadata[]>([]);
  const [result, setResult] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [signing, setSigning] = useState(false);
  const [signedCredential, setSignedCredential] = useState<string | null>(null);

  const loadKeys = useCallback(async () => {
    try {
      const response = await window.opencred.listKeys();
      setKeys(response.keys);
      if (response.keys.length > 0 && !selectedKeyId) {
        setSelectedKeyId(response.keys[0].id);
      }
    } catch {
      // Keys may not be loaded yet
    }
  }, [selectedKeyId]);

  useEffect(() => {
    void loadKeys();
  }, [loadKeys]);

  function handleSchemaSelect(id: string, fields: SchemaField[]) {
    setSchemaId(id);
    setSchemaFields(fields);
    setSubjectValues({});
    setResult(null);
    setError(null);
    setSignedCredential(null);
  }

  async function handleBuildAndSign() {
    if (!schemaId || !issuerDid || !selectedKeyId) {
      setError("Please select a schema, enter an issuer DID, and import a key.");
      return;
    }

    setError(null);
    setResult(null);
    setSignedCredential(null);
    setSigning(true);

    try {
      const response = await window.opencred.buildAndSign({
        schemaId,
        issuerDid,
        credentialSubject: subjectValues,
        validFrom: new Date(validFrom + "T00:00:00").toISOString(),
        validUntil: validUntil ? new Date(validUntil + "T23:59:59").toISOString() : undefined,
        revocationRegistryUrl: revocationUrl || undefined,
        subjectDid: subjectDid || undefined,
        keyId: selectedKeyId,
        packageFormats: ["json-ld"],
      });

      if (response.success && response.signedCredential) {
        setSignedCredential(response.signedCredential);
        setResult("Credential built, signed, and packaged successfully.");
      } else {
        setError(response.error ?? "Build and sign failed.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Build and sign failed.");
    } finally {
      setSigning(false);
    }
  }

  async function handleExportJson() {
    if (!signedCredential) return;

    try {
      await window.opencred.saveFile({
        defaultName: "credential.jsonld",
        content: JSON.stringify(JSON.parse(signedCredential), null, 2),
        filters: [{ name: "JSON-LD", extensions: ["jsonld", "json"] }],
      });
    } catch {
      // User may have cancelled
    }
  }

  return (
    <div className="space-y-6">
      {/* Schema selection */}
      <SchemaSelector onSchemaSelect={handleSchemaSelect} selectedSchema={schemaId} />

      {/* Dynamic form fields */}
      <CredentialForm
        fields={schemaFields}
        values={subjectValues}
        onChange={setSubjectValues}
        disabled={signing}
      />

      {/* Issuer and subject configuration */}
      <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-3">
        <h2 className="text-sm font-medium text-gray-700">Issuance Settings</h2>

        <div>
          <label htmlFor="issuer-did" className="block text-xs font-medium text-gray-600">
            Issuer DID <span className="text-red-500">*</span>
          </label>
          <input
            id="issuer-did"
            type="text"
            value={issuerDid}
            onChange={(e) => setIssuerDid(e.target.value)}
            placeholder="did:web:example.com"
            disabled={signing}
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
          />
        </div>

        <div>
          <label htmlFor="subject-did" className="block text-xs font-medium text-gray-600">
            Subject DID (optional)
          </label>
          <input
            id="subject-did"
            type="text"
            value={subjectDid}
            onChange={(e) => setSubjectDid(e.target.value)}
            placeholder="did:example:holder123"
            disabled={signing}
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label htmlFor="valid-from" className="block text-xs font-medium text-gray-600">
              Valid From <span className="text-red-500">*</span>
            </label>
            <input
              id="valid-from"
              type="date"
              value={validFrom}
              onChange={(e) => setValidFrom(e.target.value)}
              disabled={signing}
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
            />
          </div>
          <div>
            <label htmlFor="valid-until" className="block text-xs font-medium text-gray-600">
              Valid Until (optional)
            </label>
            <input
              id="valid-until"
              type="date"
              value={validUntil}
              onChange={(e) => setValidUntil(e.target.value)}
              disabled={signing}
              className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
            />
          </div>
        </div>

        <div>
          <label htmlFor="revocation-url" className="block text-xs font-medium text-gray-600">
            Revocation Registry URL (optional)
          </label>
          <input
            id="revocation-url"
            type="url"
            value={revocationUrl}
            onChange={(e) => setRevocationUrl(e.target.value)}
            placeholder="https://dedi.example/revocations/..."
            disabled={signing}
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
          />
        </div>

        {/* Signing key selection */}
        <div>
          <label htmlFor="signing-key" className="block text-xs font-medium text-gray-600">
            Signing Key <span className="text-red-500">*</span>
          </label>
          {keys.length === 0 ? (
            <p className="mt-1 text-xs text-gray-400 italic">
              No keys imported. Go to Key Management to import a key.
            </p>
          ) : (
            <select
              id="signing-key"
              value={selectedKeyId}
              onChange={(e) => setSelectedKeyId(e.target.value)}
              disabled={signing}
              className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
            >
              {keys.map((key) => {
                const dateFormatted = (() => {
                  try {
                    return new Date(key.importedAt).toLocaleDateString("en-US", {
                      year: "numeric",
                      month: "short",
                      day: "numeric",
                    });
                  } catch {
                    return key.importedAt;
                  }
                })();
                return (
                  <option key={key.id} value={key.id} title={key.fingerprint}>
                    {key.label ?? key.algorithm} ({dateFormatted})
                  </option>
                );
              })}
            </select>
          )}
        </div>
      </div>

      {/* Build & Sign button */}
      <div className="rounded-lg border border-gray-200 bg-white p-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-sm font-medium text-gray-700">Build & Sign</h2>
            <p className="text-xs text-gray-500">
              Keys never leave this machine. Signing works offline.
            </p>
          </div>
          <button
            onClick={() => void handleBuildAndSign()}
            disabled={signing || !schemaId || !issuerDid || !selectedKeyId}
            className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {signing ? "Signing..." : "Build & Sign Credential"}
          </button>
        </div>

        {error && <p className="mt-3 text-sm text-red-600">{error}</p>}
        {result && <p className="mt-3 text-sm text-green-700">{result}</p>}

        {signedCredential && (
          <div className="mt-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-gray-600">Signed Credential</span>
              <button
                onClick={() => void handleExportJson()}
                className="rounded-md bg-gray-100 px-3 py-1 text-xs text-gray-700 hover:bg-gray-200"
              >
                Export JSON-LD
              </button>
            </div>
            <pre className="max-h-60 overflow-auto rounded-md bg-gray-50 border border-gray-200 p-3 font-mono text-xs text-gray-700">
              {JSON.stringify(JSON.parse(signedCredential), null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
