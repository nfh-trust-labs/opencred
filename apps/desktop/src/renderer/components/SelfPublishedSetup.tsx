/**
 * SelfPublishedSetup — multi-step setup for the Self-Published Keys (did:web) workflow.
 *
 * Steps:
 *   1. Generate a fresh ECDSA P-256 key pair
 *   2. Enter the domain where the DID document will be hosted
 *   3. Export the DID document and save to disk
 *   4. (Optional) Verify publication via HTTPS fetch
 *   5. Complete — show profile summary
 *
 * SECURITY NOTE: Only the public key is embedded in the DID document.
 * The private key stays in the main process and is never exposed.
 */

import { useState } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";

type SelfPubStep = "generate" | "domain" | "export" | "verify" | "complete";

interface SelfPublishedSetupProps {
  onComplete: (result?: { key: KeyMetadata; domain: string; didDocument?: string }) => void;
}

export function SelfPublishedSetup({ onComplete }: SelfPublishedSetupProps) {
  const [step, setStep] = useState<SelfPubStep>("generate");
  const [generatedKey, setGeneratedKey] = useState<KeyMetadata | null>(null);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);

  const [domain, setDomain] = useState("");
  const [domainError, setDomainError] = useState<string | null>(null);

  const [exportedDoc, setExportedDoc] = useState<string | null>(null);
  const [exportedDid, setExportedDid] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{ accessible: boolean; error?: string } | null>(
    null,
  );

  // Export step: collapsible state
  const [showDidDoc, setShowDidDoc] = useState(false);
  const [showInstructions, setShowInstructions] = useState(false);
  const [showNoWebsite, setShowNoWebsite] = useState(false);

  // ------------------------------------------------------------------
  // Step 1: Generate key
  // ------------------------------------------------------------------

  async function handleGenerate() {
    setGenerating(true);
    setGenError(null);
    try {
      const result = await window.opencred.generateKey({});
      if (result.success && result.key) {
        setGeneratedKey(result.key);
        setStep("domain");
      } else {
        setGenError(result.error ?? "Key generation failed.");
      }
    } catch (err) {
      setGenError(err instanceof Error ? err.message : "Key generation failed.");
    } finally {
      setGenerating(false);
    }
  }

  // ------------------------------------------------------------------
  // Step 2: Domain entry — validation
  // ------------------------------------------------------------------

  function handleDomainSubmit() {
    const trimmed = domain.trim();
    if (!trimmed) {
      setDomainError("Please enter a domain.");
      return;
    }
    // Basic domain format check (allow letters, digits, dots, hyphens, optional port)
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\d+)?$/.test(trimmed)) {
      setDomainError("Invalid domain format. Example: university.example");
      return;
    }
    setDomainError(null);
    setStep("export");
  }

  // ------------------------------------------------------------------
  // Step 3: Export DID document
  // ------------------------------------------------------------------

  async function handleExport() {
    if (!generatedKey) return;
    setExporting(true);
    setExportError(null);
    setSaved(false);
    try {
      const result = await window.opencred.exportDidDocument({
        keyId: generatedKey.id,
        domain: domain.trim(),
      });
      if (result.success && result.didDocument) {
        setExportedDoc(result.didDocument);
        setExportedDid(result.did ?? null);
      } else {
        setExportError(result.error ?? "Export failed.");
      }
    } catch (err) {
      setExportError(err instanceof Error ? err.message : "Export failed.");
    } finally {
      setExporting(false);
    }
  }

  async function handleSaveToFile() {
    if (!exportedDoc) return;
    try {
      const result = await window.opencred.saveFile({
        defaultName: "did.json",
        content: exportedDoc,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (result.filePath) {
        setSaved(true);
      }
    } catch {
      // User cancelled — no action needed
    }
  }

  // ------------------------------------------------------------------
  // Step 4: Verify publication
  // ------------------------------------------------------------------

  async function handleVerify() {
    setVerifying(true);
    setVerifyResult(null);
    try {
      const result = await window.opencred.verifyDidWeb({ domain: domain.trim() });
      setVerifyResult({ accessible: result.accessible, error: result.error });
    } catch (err) {
      setVerifyResult({
        accessible: false,
        error: err instanceof Error ? err.message : "Verification failed.",
      });
    } finally {
      setVerifying(false);
    }
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  const didPreview = domain.trim() ? `did:web:${domain.trim().replace(/:/g, "%3A")}` : "";

  return (
    <>
      {/* ================================================================
          Step: Generate Key
          ================================================================ */}
      {step === "generate" && (
        <Card className="space-y-5">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              Self-Published Keys
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Generate a new key pair. Your public key will be published on your website as a DID
              document. Your private key never leaves this machine.
            </p>
          </div>

          {genError && <p className="text-sm text-red-600">{genError}</p>}

          <div className="pt-2 flex gap-3">
            <Button onClick={() => void handleGenerate()} disabled={generating}>
              {generating ? "Generating..." : "Generate Key Pair"}
            </Button>
          </div>
        </Card>
      )}

      {/* ================================================================
          Step: Enter Domain
          ================================================================ */}
      {step === "domain" && generatedKey && (
        <Card className="space-y-5">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              Enter Your Domain
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Enter the domain where you will host your DID document. The document will be served at{" "}
              <code className="text-[0.72rem] bg-surface-warm px-1 py-0.5 rounded">
                https://your-domain/.well-known/did.json
              </code>
            </p>
          </div>

          <div className="space-y-3">
            <div>
              <label className="oc-label block mb-1">Domain</label>
              <input
                type="text"
                value={domain}
                onChange={(e) => {
                  setDomain(e.target.value);
                  setDomainError(null);
                }}
                placeholder="university.example"
                className="w-full rounded-oc border border-border px-3 py-2 text-body-sm text-txt-primary placeholder:text-txt-muted focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue"
              />
              {domainError && <p className="text-[0.72rem] text-red-600 mt-1">{domainError}</p>}
            </div>

            {didPreview && (
              <div className="rounded-oc border border-border-light bg-surface-warm p-3">
                <p className="oc-label mb-1">DID Preview</p>
                <p className="font-mono text-[0.72rem] text-txt-primary break-all">{didPreview}</p>
              </div>
            )}

            <div className="rounded-oc border border-green-200 bg-green-50 p-3 space-y-1">
              <p className="text-[0.72rem] font-medium text-green-800">Key Generated</p>
              <p className="text-[0.68rem] text-green-700">Algorithm: {generatedKey.algorithm}</p>
              <p className="text-[0.68rem] text-green-700">
                Fingerprint: {generatedKey.fingerprint.slice(0, 32)}...
              </p>
            </div>
          </div>

          <div className="pt-2 flex gap-3">
            <Button onClick={handleDomainSubmit}>Continue</Button>
            <Button variant="secondary" onClick={() => setStep("generate")}>
              Back
            </Button>
          </div>
        </Card>
      )}

      {/* ================================================================
          Step: Export DID Document
          ================================================================ */}
      {step === "export" && (
        <Card className="space-y-5">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              Export DID Document
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Generate and save your DID document, then publish it to your website.
            </p>
          </div>

          {!exportedDoc && (
            <div className="space-y-3">
              <div className="rounded-oc border border-border-light bg-surface-warm p-3">
                <p className="oc-label mb-1">Your DID</p>
                <p className="font-mono text-[0.72rem] text-txt-primary break-all">{didPreview}</p>
              </div>

              {exportError && <p className="text-sm text-red-600">{exportError}</p>}

              <Button onClick={() => void handleExport()} disabled={exporting}>
                {exporting ? "Generating..." : "Generate DID Document"}
              </Button>
            </div>
          )}

          {exportedDoc && (
            <div className="space-y-4">
              {/* Simplified summary */}
              <div className="rounded-oc border border-green-200 bg-green-50 p-4 space-y-2">
                <p className="text-[0.82rem] font-medium text-green-800">
                  Your verification file is ready to publish
                </p>
                <p className="text-[0.72rem] text-green-700">
                  Domain: <span className="font-mono">{domain.trim()}</span>
                </p>
              </div>

              {/* Save button */}
              <div className="flex gap-3 items-center">
                <Button onClick={() => void handleSaveToFile()}>Save to File</Button>
                {saved && <span className="text-[0.78rem] text-green-700">Saved</span>}
              </div>

              {/* Collapsible: View DID Document (Advanced) */}
              <div>
                <button
                  onClick={() => setShowDidDoc(!showDidDoc)}
                  className="text-[0.78rem] text-brand-blue font-medium hover:underline focus:outline-none flex items-center gap-1"
                >
                  <svg
                    width="12"
                    height="12"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth={2}
                    className={`transition-transform duration-200 ${showDidDoc ? "rotate-180" : ""}`}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                  View DID Document (Advanced)
                </button>
                {showDidDoc && (
                  <div className="mt-2 rounded-oc border border-border bg-surface-warm p-3">
                    <pre className="text-[0.68rem] text-txt-secondary overflow-x-auto max-h-48 overflow-y-auto whitespace-pre-wrap">
                      {exportedDoc}
                    </pre>
                  </div>
                )}
              </div>

              {/* Collapsible: Publishing Instructions */}
              <div>
                <button
                  onClick={() => setShowInstructions(!showInstructions)}
                  className="text-[0.78rem] text-brand-blue font-medium hover:underline focus:outline-none flex items-center gap-1"
                >
                  <svg
                    width="12"
                    height="12"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth={2}
                    className={`transition-transform duration-200 ${showInstructions ? "rotate-180" : ""}`}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                  Publishing Instructions
                </button>
                {showInstructions && (
                  <div className="mt-2 rounded-oc border border-blue-200 bg-blue-50 p-3 space-y-2">
                    <p className="text-[0.72rem] text-blue-600 italic">
                      You will need access to your organization&apos;s website hosting. Your IT
                      administrator or web developer can help with this step.
                    </p>
                    <ol className="text-[0.72rem] text-blue-700 list-decimal list-inside space-y-0.5">
                      <li>
                        Save the DID document as{" "}
                        <code className="bg-blue-100 px-1 rounded">did.json</code>
                      </li>
                      <li>
                        Upload it to{" "}
                        <code className="bg-blue-100 px-1 rounded">
                          https://{domain.trim()}/.well-known/did.json
                        </code>
                      </li>
                      <li>
                        Ensure the file is served with{" "}
                        <code className="bg-blue-100 px-1 rounded">
                          Content-Type: application/json
                        </code>
                      </li>
                    </ol>
                  </div>
                )}
              </div>

              {/* "I don't have a website" link */}
              <div>
                <button
                  onClick={() => setShowNoWebsite(!showNoWebsite)}
                  className="text-[0.72rem] text-txt-muted hover:text-txt-secondary hover:underline focus:outline-none"
                >
                  I don&apos;t have a website
                </button>
                {showNoWebsite && (
                  <div className="mt-2 rounded-oc border border-border-light bg-surface-warm p-3">
                    <p className="text-[0.72rem] text-txt-secondary">
                      You can still issue credentials. Verifiers will need your public key shared
                      directly. You can also set up DeDi later from Settings to publish your key to
                      a public directory.
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="pt-2 flex gap-3">
            {exportedDoc && <Button onClick={() => setStep("verify")}>Continue</Button>}
            <Button variant="secondary" onClick={() => setStep("domain")}>
              Back
            </Button>
          </div>
        </Card>
      )}

      {/* ================================================================
          Step: Verify Publication (optional)
          ================================================================ */}
      {step === "verify" && (
        <Card className="space-y-5">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              Verify Publication
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Optionally verify that your DID document is accessible at the expected URL. You can
              skip this step and verify later.
            </p>
          </div>

          <div className="rounded-oc border border-border-light bg-surface-warm p-3">
            <p className="oc-label mb-1">Expected URL</p>
            <p className="font-mono text-[0.72rem] text-txt-primary break-all">
              https://{domain.trim()}/.well-known/did.json
            </p>
          </div>

          <div className="flex gap-3 items-center">
            <Button onClick={() => void handleVerify()} disabled={verifying}>
              {verifying ? "Checking..." : "Verify Now"}
            </Button>
            <Button variant="secondary" onClick={() => setStep("complete")}>
              Skip
            </Button>
          </div>

          {verifyResult && (
            <div
              className={`rounded-oc border p-3 ${
                verifyResult.accessible
                  ? "border-green-200 bg-green-50"
                  : "border-amber-200 bg-amber-50"
              }`}
            >
              {verifyResult.accessible ? (
                <p className="text-[0.78rem] text-green-800 font-medium">
                  DID document is accessible and valid.
                </p>
              ) : (
                <div className="space-y-1">
                  <p className="text-[0.78rem] text-amber-800 font-medium">
                    DID document not accessible yet.
                  </p>
                  {verifyResult.error && (
                    <p className="text-[0.72rem] text-amber-700">{verifyResult.error}</p>
                  )}
                  <p className="text-[0.72rem] text-amber-700">
                    Make sure you have published the file and that your web server is running.
                  </p>
                </div>
              )}
            </div>
          )}

          {verifyResult?.accessible && (
            <div className="pt-1">
              <Button onClick={() => setStep("complete")}>Continue</Button>
            </div>
          )}
        </Card>
      )}

      {/* ================================================================
          Step: Complete
          ================================================================ */}
      {step === "complete" && generatedKey && (
        <Card className="space-y-6">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              Self-Published Key Ready
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Your signing identity is set up. You can now issue and sign Verifiable Credentials.
            </p>
          </div>

          <div className="rounded-oc border border-green-200 bg-green-50 p-4 space-y-2">
            <h3 className="oc-card-label" style={{ color: "#2e7d32" }}>
              Profile Summary
            </h3>
            <dl className="text-[0.78rem] text-green-700 space-y-1.5">
              <div className="flex gap-2">
                <dt className="font-medium w-24 flex-shrink-0">DID:</dt>
                <dd className="font-mono text-[0.72rem] break-all">{exportedDid ?? didPreview}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="font-medium w-24 flex-shrink-0">Domain:</dt>
                <dd>{domain.trim()}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="font-medium w-24 flex-shrink-0">Algorithm:</dt>
                <dd>{generatedKey.algorithm}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="font-medium w-24 flex-shrink-0">Fingerprint:</dt>
                <dd className="font-mono text-[0.72rem]">{generatedKey.fingerprint}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="font-medium w-24 flex-shrink-0">Source:</dt>
                <dd>Self-Published (did:web)</dd>
              </div>
            </dl>
          </div>

          <div className="pt-2">
            <Button
              onClick={() =>
                onComplete({
                  key: generatedKey!,
                  domain: domain.trim(),
                  didDocument: exportedDoc ?? undefined,
                })
              }
            >
              Start Issuing Credentials
            </Button>
          </div>
        </Card>
      )}
    </>
  );
}
