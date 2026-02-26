import { useState } from "react";
import { SchemaSelector } from "./SchemaSelector";
import { CredentialForm } from "./CredentialForm";
import { KeyImport } from "./KeyImport";
import type { ImportedKey } from "./KeyImport";
import { getSchema } from "../schemas";
import { OpenCredClient } from "../api/client";
import {
  signData,
  base64urlDecode,
  base64urlEncode,
} from "../crypto/webcrypto";

interface Props {
  apiUrl: string;
  token: string;
}

type Step = "form" | "signing" | "done";
type SigningMode = "interface" | "delegated";

export function CredentialBuilder({ apiUrl, token }: Props) {
  const [schemaId, setSchemaId] = useState("");
  const [subjectValues, setSubjectValues] = useState<Record<string, string>>({});
  const [issuerDid, setIssuerDid] = useState("");
  const [validFrom, setValidFrom] = useState(new Date().toISOString().split("T")[0]);
  const [validUntil, setValidUntil] = useState("");
  const [revocationUrl, setRevocationUrl] = useState("https://dedi.example.com/revocation/list/1");
  const [importedKey, setImportedKey] = useState<ImportedKey | null>(null);
  const [signingMode, setSigningMode] = useState<SigningMode>("interface");
  const [delegationId, setDelegationId] = useState("");
  const [step, setStep] = useState<Step>("form");
  const [error, setError] = useState<string | null>(null);
  const [credential, setCredential] = useState<Record<string, unknown> | null>(null);

  const schema = schemaId ? getSchema(schemaId) : null;

  function handleSchemaChange(id: string) {
    setSchemaId(id);
    setSubjectValues({});
  }

  function handleFieldChange(field: string, value: string) {
    setSubjectValues((prev) => ({ ...prev, [field]: value }));
  }

  function isFormValid(): boolean {
    if (!schema || !validFrom) return false;
    const requiredFieldsFilled = schema.fields
      .filter((f) => f.required)
      .every((f) => (subjectValues[f.name] ?? "").trim() !== "");
    if (!requiredFieldsFilled) return false;

    if (signingMode === "interface") {
      return !!issuerDid && !!revocationUrl && !!importedKey;
    } else {
      return !!delegationId.trim();
    }
  }

  async function handleBuildAndSign() {
    if (!schema) return;

    setStep("signing");
    setError(null);
    setCredential(null);

    try {
      const client = new OpenCredClient(apiUrl, token || undefined);

      if (signingMode === "delegated") {
        // Delegated signing — server signs
        const res = await client.issueDelegated(
          delegationId,
          schemaId,
          { ...subjectValues },
          validFrom ? new Date(validFrom).toISOString() : undefined,
          validUntil ? new Date(validUntil).toISOString() : undefined,
        );
        setCredential(res.credential);
        setStep("done");
        return;
      }

      // Interface signing — local key, never leaves browser
      if (!importedKey) return;

      // 1. Build — send to API, get back dataToSign
      const buildRes = await client.buildCredential({
        schema: schemaId,
        issuer: issuerDid,
        publicKey: importedKey.publicKeyId,
        credentialSubject: { ...subjectValues },
        validFrom: new Date(validFrom).toISOString(),
        validUntil: validUntil ? new Date(validUntil).toISOString() : undefined,
        revocationRegistryUrl: revocationUrl,
      });

      // 2. Sign locally with WebCrypto — private key never leaves the browser
      const dataBytes = base64urlDecode(buildRes.dataToSign);
      const signature = await signData(importedKey.signingKey, dataBytes);
      const signatureB64 = base64urlEncode(signature);

      // 3. Package — send signature to API, get back final credential
      const pkgRes = await client.packageCredential({
        sessionId: buildRes.sessionId,
        signature: signatureB64,
      });

      setCredential(pkgRes.credential);
      setStep("done");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Signing failed");
      setStep("form");
    }
  }

  function handleDownload() {
    if (!credential) return;
    const blob = new Blob([JSON.stringify(credential, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "credential.json";
    a.click();
    URL.revokeObjectURL(url);
  }

  function handleReset() {
    setStep("form");
    setCredential(null);
    setError(null);
  }

  return (
    <div className="space-y-6">
      {step === "done" && credential ? (
        <div className="space-y-4">
          <div className="rounded-lg border border-green-200 bg-green-50 p-4">
            <p className="text-sm font-medium text-green-800">Credential issued successfully</p>
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
      ) : (
        <>
          <SchemaSelector value={schemaId} onChange={handleSchemaChange} />

          {schema && (
            <CredentialForm schema={schema} values={subjectValues} onChange={handleFieldChange} />
          )}

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">Signing Mode</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="radio"
                  name="signing-mode"
                  checked={signingMode === "interface"}
                  onChange={() => setSigningMode("interface")}
                  className="text-blue-600"
                />
                Interface Signing (local key)
              </label>
              <label className="flex items-center gap-2 text-sm text-gray-700">
                <input
                  type="radio"
                  name="signing-mode"
                  checked={signingMode === "delegated"}
                  onChange={() => setSigningMode("delegated")}
                  className="text-blue-600"
                />
                Delegated Signing
              </label>
            </div>
          </div>

          {signingMode === "delegated" && (
            <div>
              <label
                htmlFor="builder-delegation-id"
                className="block text-sm font-medium text-gray-700"
              >
                Delegation ID
              </label>
              <input
                id="builder-delegation-id"
                type="text"
                value={delegationId}
                onChange={(e) => setDelegationId(e.target.value)}
                placeholder="Enter your delegation ID..."
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
          )}

          {signingMode === "interface" && (
            <>
              <div className="space-y-3">
                <div>
                  <label htmlFor="issuer-did" className="block text-sm font-medium text-gray-700">
                    Issuer DID
                  </label>
                  <input
                    id="issuer-did"
                    type="text"
                    value={issuerDid}
                    onChange={(e) => setIssuerDid(e.target.value)}
                    placeholder="did:key:z..."
                    className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label
                    htmlFor="revocation-url"
                    className="block text-sm font-medium text-gray-700"
                  >
                    Revocation Registry URL
                  </label>
                  <input
                    id="revocation-url"
                    type="url"
                    value={revocationUrl}
                    onChange={(e) => setRevocationUrl(e.target.value)}
                    className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              </div>

              <KeyImport onKeyImported={setImportedKey} />
            </>
          )}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="valid-from" className="block text-sm font-medium text-gray-700">
                Valid From
              </label>
              <input
                id="valid-from"
                type="date"
                value={validFrom}
                onChange={(e) => setValidFrom(e.target.value)}
                className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              />
            </div>
            <div>
              <label htmlFor="valid-until" className="block text-sm font-medium text-gray-700">
                Valid Until (optional)
              </label>
              <input
                id="valid-until"
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
            onClick={handleBuildAndSign}
            disabled={!isFormValid() || step === "signing"}
            className="w-full rounded-md bg-blue-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-blue-700 disabled:opacity-40"
          >
            {step === "signing"
              ? "Signing..."
              : signingMode === "delegated"
                ? "Issue Credential (Delegated)"
                : "Build & Sign Credential"}
          </button>
        </>
      )}
    </div>
  );
}
