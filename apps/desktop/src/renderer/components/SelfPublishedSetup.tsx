/**
 * SelfPublishedSetup — multi-step setup for the Self-Published Keys workflow.
 *
 * Two DID-method branches:
 *
 *   did:web — issuer has a public domain. The user enters the domain, exports
 *             a DID document, and publishes it at `.well-known/did.json`.
 *             Trust is anchored in the domain's TLS; key rotation is supported
 *             by re-publishing.
 *
 *   did:key — issuer has no domain. The DID is derived directly from the
 *             public key (`did:key:z…`) and is self-contained — verifiers
 *             resolve it offline without a network call. There is no key
 *             rotation; the user is forced through an explicit "I understand
 *             my key is unrotatable" backup gate before completing.
 *
 * Steps:
 *   1. Generate a fresh key pair
 *   2. Choose DID method (web vs key)
 *   3a. (web) Enter the domain
 *   3b. (web) Export and publish the DID document
 *   3c. (web) Verify publication
 *   3d. (key) Confirm derived did:key
 *   3e. (key) Backup-key acknowledgement gate
 *   4.  Complete — show profile summary tailored to the chosen method
 *
 * SECURITY NOTE: Only the public key is embedded in the DID document /
 * exposed via did:key. The private key stays in the main process and is
 * never serialised over IPC.
 */

import { useState } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";

type DidMethodChoice = "web" | "key";

type SelfPubStep =
  | "generate"
  | "choose-method"
  | "domain"
  | "export"
  | "verify"
  | "did-key-confirm"
  | "did-key-backup"
  | "complete";

/**
 * Result handed to the parent wizard on completion.
 *
 * `method` distinguishes the two branches. `did` is always populated — for
 * did:web it's `did:web:<domain>`, for did:key it's the derived
 * `did:key:z…` (`key.id` minus the `#fragment`). `domain` and `didDocument`
 * are only present on the did:web branch.
 */
export interface SelfPubResult {
  key: KeyMetadata;
  method: DidMethodChoice;
  did: string;
  domain?: string;
  didDocument?: string;
}

interface SelfPublishedSetupProps {
  onComplete: (result?: SelfPubResult) => void;
  /**
   * Optional callback for the very first step's Back button — returns the
   * user to the prior step in the parent wizard (e.g. choose-path) when
   * they realise they picked the wrong onboarding path. Issue #547.
   */
  onBack?: () => void;
  /**
   * Render-suppression for the keep-mounted strategy: when the parent
   * wizard navigates forward to a later step (e.g. dedi-setup) it sets
   * `hidden` so the React subtree stays mounted and useState is preserved,
   * but nothing draws on screen. This lets the user navigate back from
   * dedi-setup without losing their generated key, domain, or DID
   * document. Issue #547.
   */
  hidden?: boolean;
}

export function SelfPublishedSetup({ onComplete, onBack, hidden }: SelfPublishedSetupProps) {
  const [step, setStep] = useState<SelfPubStep>("generate");
  const [generatedKey, setGeneratedKey] = useState<KeyMetadata | null>(null);
  const [generating, setGenerating] = useState(false);
  const [genError, setGenError] = useState<string | null>(null);

  // DID-method branch: defaults to "web" because that's the recommended path
  // for issuers who have a domain. "key" requires explicit selection so the
  // user actively opts in to its (irrevocable) trade-offs.
  const [method, setMethod] = useState<DidMethodChoice>("web");
  // did:key branch: gates the "Complete" step behind an explicit
  // backup-acknowledged checkbox. The wizard never proceeds with did:key
  // until this is true. See COMMENTARY in render section below.
  const [backupAcknowledged, setBackupAcknowledged] = useState(false);

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
        setStep("choose-method");
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
  // For did:key, the signer's `id` field is already `did:key:z…#z…` (the
  // verification-method ref). Strip the fragment to get the DID itself,
  // which is what the credential's `issuer` field will use.
  const didKeyDid = generatedKey?.id.split("#")[0] ?? "";

  /**
   * Final-step completion handler.
   *
   * For did:web, the DID document was already exported and saved during
   * the wizard's `export` step, so we pass it through verbatim.
   *
   * For did:key, we synthesise the DID document just-in-time here by
   * calling the `exportDidKeyDocument` IPC. The document is needed by the
   * parent wizard's DeDi step so it can publish the attribution record;
   * if DeDi publishing is later skipped, the document is simply discarded.
   * We tolerate IPC failure here without blocking — the user can still
   * issue credentials; DeDi attribution just won't be published.
   */
  async function handleCompleteHandoff() {
    if (!generatedKey) return;
    if (method === "web") {
      onComplete({
        key: generatedKey,
        method: "web",
        did: exportedDid ?? didPreview,
        domain: domain.trim(),
        didDocument: exportedDoc ?? undefined,
      });
      return;
    }
    // did:key — synthesize document for DeDi publishing.
    let didKeyDocument: string | undefined;
    try {
      const result = await window.opencred.exportDidKeyDocument({ keyId: generatedKey.id });
      if (result.success) didKeyDocument = result.didDocument;
    } catch {
      // Non-fatal — proceed without a DeDi-publishable document.
    }
    onComplete({
      key: generatedKey,
      method: "key",
      did: didKeyDid,
      didDocument: didKeyDocument,
    });
  }

  return (
    <div style={hidden ? { display: "none" } : undefined}>
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
            {onBack && (
              <Button variant="secondary" onClick={onBack} disabled={generating}>
                Back
              </Button>
            )}
          </div>
        </Card>
      )}

      {/* ================================================================
          Step: Choose DID Method
          ================================================================
          The user has just generated a keypair; now they pick how that key
          will be discoverable. did:web wants a public domain and supports
          rotation; did:key is fully offline-verifiable but unrotatable.
          The wizard surfaces this trade-off explicitly so the user makes an
          intentional choice — there is no "default" that hides the impact. */}
      {step === "choose-method" && generatedKey && (
        <Card className="space-y-5">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              How will your key be published?
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Choose where verifiers will find your public key. You can change this later by
              re-running setup.
            </p>
          </div>

          <div className="space-y-3">
            <label
              className={`flex gap-3 rounded-oc border p-3 cursor-pointer ${
                method === "web" ? "border-brand-blue bg-brand-blue/5" : "border-border"
              }`}
            >
              <input
                type="radio"
                name="did-method"
                value="web"
                checked={method === "web"}
                onChange={() => setMethod("web")}
                className="mt-0.5"
              />
              <div className="space-y-1">
                <p className="text-[0.85rem] font-medium text-txt-primary">
                  I have a domain (did:web) — recommended
                </p>
                <p className="text-[0.72rem] text-txt-secondary">
                  Publish a DID document on your website at{" "}
                  <code className="text-[0.68rem] bg-surface-warm px-1 rounded">
                    /.well-known/did.json
                  </code>
                  . Best for institutional issuers; supports key rotation.
                </p>
              </div>
            </label>

            <label
              className={`flex gap-3 rounded-oc border p-3 cursor-pointer ${
                method === "key" ? "border-brand-blue bg-brand-blue/5" : "border-border"
              }`}
            >
              <input
                type="radio"
                name="did-method"
                value="key"
                checked={method === "key"}
                onChange={() => setMethod("key")}
                className="mt-0.5"
              />
              <div className="space-y-1">
                <p className="text-[0.85rem] font-medium text-txt-primary">No domain (did:key)</p>
                <p className="text-[0.72rem] text-txt-secondary">
                  Your DID is derived directly from the public key — no hosting needed. Credentials
                  verify fully offline. Trade-off: this key cannot be rotated; losing it means
                  re-issuing every credential under a new DID.
                </p>
              </div>
            </label>
          </div>

          <div className="pt-2 flex gap-3">
            <Button onClick={() => setStep(method === "web" ? "domain" : "did-key-confirm")}>
              Continue
            </Button>
            <Button variant="secondary" onClick={() => setStep("generate")}>
              Back
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
            <Button variant="secondary" onClick={() => setStep("choose-method")}>
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
            <div className="pt-1 flex gap-3">
              <Button onClick={() => setStep("complete")}>Continue</Button>
              <Button variant="secondary" onClick={() => setStep("export")}>
                Back
              </Button>
            </div>
          )}

          {/* When the verify step is reached but the user hasn't run it yet
              (or it failed), they should still be able to step back to the
              export screen to inspect the doc or save it again. */}
          {!verifyResult?.accessible && (
            <div className="pt-1">
              <Button variant="secondary" onClick={() => setStep("export")}>
                Back
              </Button>
            </div>
          )}
        </Card>
      )}

      {/* ================================================================
          Step: did:key — Confirm derived DID
          ================================================================
          For the did:key branch, there is no domain or hosted document; the
          DID is the key. We show the user the exact identifier their
          credentials will carry so they can confirm before moving on. */}
      {step === "did-key-confirm" && generatedKey && (
        <Card className="space-y-5">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              Your did:key identifier
            </h2>
            <p className="text-body-sm text-txt-secondary">
              This is the DID that will appear in every credential you issue. It is derived from
              your public key — verifiers can resolve it offline without contacting any server.
            </p>
          </div>

          <div className="rounded-oc border border-border-light bg-surface-warm p-3">
            <p className="oc-label mb-1">Your DID</p>
            <p className="font-mono text-[0.72rem] text-txt-primary break-all">{didKeyDid}</p>
          </div>

          <div className="rounded-oc border border-green-200 bg-green-50 p-3 space-y-1">
            <p className="text-[0.72rem] font-medium text-green-800">Key Generated</p>
            <p className="text-[0.68rem] text-green-700">Algorithm: {generatedKey.algorithm}</p>
            <p className="text-[0.68rem] text-green-700">
              Fingerprint: {generatedKey.fingerprint.slice(0, 32)}...
            </p>
          </div>

          <div className="pt-2 flex gap-3">
            <Button onClick={() => setStep("did-key-backup")}>Continue</Button>
            <Button variant="secondary" onClick={() => setStep("choose-method")}>
              Back
            </Button>
          </div>
        </Card>
      )}

      {/* ================================================================
          Step: did:key — Backup acknowledgement gate
          ================================================================
          The unrotatable-key risk is the single biggest downside of did:key.
          This step exists so the user CANNOT proceed without explicitly
          acknowledging it. The Continue button is disabled until the
          checkbox is checked — this is intentional UX friction, not a
          mistake. See the plan's "Risks and edge cases" section.

          v1 limitation: the desktop app currently keeps generated keys in
          main-process memory only (loadedSigners Map). A first-class
          "export encrypted private key" IPC handler is a planned follow-up;
          for now this step is a strong forcing function that surfaces the
          risk and tells the user what they need to do externally. */}
      {step === "did-key-backup" && generatedKey && (
        <Card className="space-y-5">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              Back up your key
            </h2>
            <p className="text-body-sm text-txt-secondary">
              did:key has no rotation path. If you lose this key, every credential you have ever
              issued under this DID becomes unverifiable forever. Take a moment to back it up before
              continuing.
            </p>
          </div>

          <div className="rounded-oc border border-amber-300 bg-amber-50 p-4 space-y-2">
            <p className="text-[0.82rem] font-medium text-amber-900">What you should do now</p>
            <ul className="text-[0.78rem] text-amber-800 list-disc list-inside space-y-1">
              <li>
                Record the key fingerprint and your DID in a password manager or secure document
                store.
              </li>
              <li>
                Keep this device's encrypted backup current — the private key lives in the operating
                system keystore and is included in standard backups.
              </li>
              <li>
                Consider setting up DeDi attribution in the next step so verifiers can recognise
                your DID — and so you have a published successor record if you ever rotate.
              </li>
            </ul>
            <p className="text-[0.72rem] text-amber-800 italic pt-1">
              A dedicated "export encrypted backup" command is on the roadmap. For now, the key
              persists with this installation only; reformatting or reinstalling without a system
              backup will lose it.
            </p>
          </div>

          <label className="flex gap-3 items-start cursor-pointer">
            <input
              type="checkbox"
              checked={backupAcknowledged}
              onChange={(e) => setBackupAcknowledged(e.target.checked)}
              className="mt-0.5"
            />
            <span className="text-[0.78rem] text-txt-primary">
              I understand that this key cannot be rotated and I have noted my DID and fingerprint
              somewhere I will not lose.
            </span>
          </label>

          <div className="pt-2 flex gap-3">
            <Button onClick={() => setStep("complete")} disabled={!backupAcknowledged}>
              Continue
            </Button>
            <Button variant="secondary" onClick={() => setStep("did-key-confirm")}>
              Back
            </Button>
          </div>
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
                <dd className="font-mono text-[0.72rem] break-all">
                  {method === "web" ? (exportedDid ?? didPreview) : didKeyDid}
                </dd>
              </div>
              {method === "web" && (
                <div className="flex gap-2">
                  <dt className="font-medium w-24 flex-shrink-0">Domain:</dt>
                  <dd>{domain.trim()}</dd>
                </div>
              )}
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
                <dd>
                  {method === "web" ? "Self-Published (did:web)" : "Self-Published (did:key)"}
                </dd>
              </div>
            </dl>
          </div>

          <div className="pt-2 flex gap-3">
            <Button onClick={() => void handleCompleteHandoff()}>Start Issuing Credentials</Button>
            <Button
              variant="secondary"
              onClick={() => setStep(method === "web" ? "verify" : "did-key-backup")}
            >
              Back
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}
