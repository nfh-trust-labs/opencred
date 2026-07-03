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
 *   2. Choose DID method (web vs key) — skipped when `initialMethod` is preset
 *      by the wizard's situation screen (web / key / directory)
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

import { useEffect, useState } from "react";
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
   * user to the prior step in the parent wizard (e.g. choose-anchor) when
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
  /**
   * The identity anchor the user chose on the wizard's situation screen.
   * When set, the in-flow "how will your key be published?" picker is
   * skipped — the user already answered that question. `"directory"` is a
   * did:web identity hosted in a public directory (DeDi) rather than on the
   * issuer's own domain; the DID is still `did:web:<namespace>`.
   */
  initialMethod?: "web" | "key" | "directory";
  /**
   * Reports the current sub-step to the parent wizard so its progress
   * indicator can place each phase under the right visible step ("Your key"
   * vs "Publish"). Called whenever the internal step changes.
   */
  onPhaseChange?: (phase: SelfPubStep) => void;
}

export function SelfPublishedSetup({
  onComplete,
  onBack,
  hidden,
  initialMethod,
  onPhaseChange,
}: SelfPublishedSetupProps) {
  const [step, setStep] = useState<SelfPubStep>("generate");
  // `directory` is the public-directory anchor: a did:web identity whose home
  // is a shared directory (DeDi) instead of the issuer's own domain. It reuses
  // the did:web machinery (the DID is `did:web:<namespace>`), so internally it
  // runs as `method === "web"` with directory-specific copy and DeDi as the
  // publish destination.
  const directory = initialMethod === "directory";
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

  // Keep the parent wizard's progress indicator in sync with our sub-step so
  // it can place each phase under the right visible step ("Your key" vs
  // "Publish"). Idempotent — re-emitting the same phase is a no-op upstream.
  useEffect(() => {
    onPhaseChange?.(step);
  }, [step, onPhaseChange]);

  // Directory anchor: auto-generate the identity document the first time the
  // export step is shown. For the website path the user clicks "Generate
  // identity document" themselves, but for the directory anchor DeDi is the
  // publish — there's nothing to save or upload here, so the manual Generate +
  // Continue round-trip is pure friction. The `!exportError` guard is load-
  // bearing: on a failed export, `exporting` flips back to false and
  // `exportedDoc` stays null, so without it the effect would re-fire forever.
  // On failure we stop and surface the error + the manual "Generate" button so
  // the user retries deliberately (clicking it clears exportError).
  useEffect(() => {
    if (step === "export" && directory && !exportedDoc && !exporting && !exportError) {
      void handleExport();
    }
    // handleExport reads `generatedKey`/`domain` from closure but is stable
    // enough for our one-shot guard; intentionally not in the dep list to
    // avoid re-firing on unrelated re-renders. (No eslint-disable directive
    // here: the project's ESLint config doesn't load eslint-plugin-react-hooks,
    // so referencing react-hooks/exhaustive-deps is a hard "rule not found"
    // error — see #716 regression.)
  }, [step, directory, exportedDoc, exporting, exportError]);

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
        // When an anchor was preset on the wizard's situation screen, skip the
        // in-flow method picker and jump straight to that anchor's first step.
        if (initialMethod === "key") {
          setMethod("key");
          setStep("did-key-confirm");
        } else if (initialMethod === "web" || initialMethod === "directory") {
          setMethod("web");
          setStep("domain");
        } else {
          setStep("choose-method");
        }
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
      setDomainError(directory ? "Please enter a namespace." : "Please enter a domain.");
      return;
    }
    // Website: a hostname with an optional numeric port. Directory: a
    // colon-delimited namespace whose segments become the did:web path
    // (`did.cord.network:acme` -> `did:web:did.cord.network:acme`), so path
    // colons are allowed.
    const valid = directory
      ? /^[a-zA-Z0-9.-]+(:[a-zA-Z0-9.-]+)*$/.test(trimmed)
      : /^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?(:\d+)?$/.test(trimmed);
    if (!valid) {
      setDomainError(
        directory
          ? "Invalid namespace. Example: acme or did.cord.network:acme"
          : "Invalid domain format. Example: university.example",
      );
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

  // For the public-directory anchor the value is a colon-delimited namespace
  // (e.g. `acme` or `did.cord.network:acme`) whose path colons must NOT be
  // percent-encoded; only a website's host:port colon is. The authoritative
  // DID still comes from the main process (`exportDidDocument`); this preview
  // is cosmetic.
  const didPreview = domain.trim()
    ? directory
      ? `did:web:${domain.trim()}`
      : `did:web:${domain.trim().replace(/:/g, "%3A")}`
    : "";
  // With an anchor preset the in-flow method picker is skipped, so "Back" from
  // the domain / did:key-confirm steps returns to key generation rather than
  // the never-shown picker.
  const backToMethodChoice = () => setStep(initialMethod ? "generate" : "choose-method");
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
              Create your signing key
            </h2>
            <p className="text-body-sm text-txt-secondary">
              {directory
                ? "Create your signing key. You'll publish its public half to your own DeDi namespace so verifiers can find you. Your private key never leaves this machine."
                : initialMethod === "key"
                  ? "Create your signing key. Its public half becomes your identity — no hosting needed. Your private key never leaves this machine."
                  : "Create your signing key. You'll publish its public half on your website so verifiers can find you. Your private key never leaves this machine."}
            </p>
          </div>

          {genError && <p className="text-sm text-state-danger">{genError}</p>}

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
                <p className="text-body-sm font-medium text-txt-primary">
                  I have a domain (did:web) — recommended
                </p>
                <p className="text-body-2xs text-txt-secondary">
                  Publish a DID document on your website at{" "}
                  <code className="text-body-2xs bg-surface-warm px-1 rounded">
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
                <p className="text-body-sm font-medium text-txt-primary">No domain (did:key)</p>
                <p className="text-body-2xs text-txt-secondary">
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
              {directory ? "Enter your DeDi namespace" : "Enter your domain"}
            </h2>
            {directory ? (
              <p className="text-body-sm text-txt-secondary">
                Your DeDi namespace becomes your issuer identity, and you publish your key to it in
                the next step. Don&apos;t have one yet? You&apos;ll create a DeDi account and
                namespace in the next step.
              </p>
            ) : (
              <p className="text-body-sm text-txt-secondary">
                Enter the domain where you will host your identity file. It will be served at{" "}
                <code className="text-body-2xs bg-surface-warm px-1 py-0.5 rounded">
                  https://your-domain/.well-known/did.json
                </code>
              </p>
            )}
          </div>

          <div className="space-y-3">
            <div>
              <label className="oc-label block mb-1">
                {directory ? "DeDi namespace" : "Domain"}
              </label>
              <input
                type="text"
                value={domain}
                onChange={(e) => {
                  setDomain(e.target.value);
                  setDomainError(null);
                  // Editing the domain/namespace invalidates any document we
                  // already generated for the old value. Clear it so the export
                  // step regenerates (auto for directory; the manual Generate
                  // button reappears for the website path) instead of leaving a
                  // stale doc the user can't refresh.
                  if (exportedDoc) {
                    setExportedDoc(null);
                    setExportedDid(null);
                    setVerifyResult(null);
                    setSaved(false);
                  }
                }}
                placeholder={directory ? "acme" : "university.example"}
                className="w-full rounded-oc border border-border px-3 py-2 text-body-sm text-txt-primary placeholder:text-txt-muted focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue"
              />
              {domainError && <p className="text-body-2xs text-state-danger mt-1">{domainError}</p>}
            </div>

            {didPreview && (
              <div className="rounded-oc border border-border-light bg-surface-warm p-3">
                <p className="oc-label mb-1">DID Preview</p>
                <p className="font-mono text-body-2xs text-txt-primary break-all">{didPreview}</p>
              </div>
            )}

            <div className="rounded-oc border border-state-success-border bg-state-success-bg p-3 space-y-1">
              <p className="text-body-2xs font-medium text-state-success">Key Generated</p>
              <p className="text-body-2xs text-state-success">
                Algorithm: {generatedKey.algorithm}
              </p>
              <p className="text-body-2xs text-state-success">
                Fingerprint: {generatedKey.fingerprint.slice(0, 32)}...
              </p>
            </div>
          </div>

          <div className="pt-2 flex gap-3">
            <Button onClick={handleDomainSubmit}>Continue</Button>
            <Button variant="secondary" onClick={backToMethodChoice}>
              Back
            </Button>
          </div>
        </Card>
      )}

      {/* ================================================================
          Step: Publish identity (host on your site / publish to your DeDi account)
          ================================================================ */}
      {step === "export" && (
        <Card className="space-y-5">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              {directory
                ? "Publish your identity to your DeDi account"
                : "Publish your identity to your site"}
            </h2>
            <p className="text-body-sm text-txt-secondary">
              {directory
                ? "Generate your identity document — you'll publish it to your own DeDi namespace in the final step."
                : "Generate your identity file, then publish it on your own website so verifiers can find your key."}
            </p>
          </div>

          {!exportedDoc && (
            <div className="space-y-3">
              <div className="rounded-oc border border-border-light bg-surface-warm p-3">
                <p className="oc-label mb-1">Your DID</p>
                <p className="font-mono text-body-2xs text-txt-primary break-all">{didPreview}</p>
              </div>

              {exportError && <p className="text-sm text-state-danger">{exportError}</p>}

              <Button onClick={() => void handleExport()} disabled={exporting}>
                {exporting ? "Generating..." : "Generate identity document"}
              </Button>
            </div>
          )}

          {exportedDoc && (
            <div className="space-y-4">
              {/* Simplified summary */}
              <div className="rounded-oc border border-state-success-border bg-state-success-bg p-4 space-y-2">
                <p className="text-body-xs font-medium text-state-success">
                  {directory
                    ? "Your identity is ready to publish"
                    : "Your identity file is ready to publish"}
                </p>
                <p className="text-body-2xs text-state-success">
                  {directory ? "Namespace: " : "Domain: "}
                  <span className="font-mono">{domain.trim()}</span>
                </p>
              </div>

              {/* Save button — website only; DeDi hosts the file for the directory anchor */}
              {!directory && (
                <div className="flex gap-3 items-center">
                  <Button onClick={() => void handleSaveToFile()}>Save to File</Button>
                  {saved && <span className="text-body-xs text-state-success">Saved</span>}
                </div>
              )}

              {/* Collapsible: View DID Document (Advanced) */}
              <div>
                <button
                  onClick={() => setShowDidDoc(!showDidDoc)}
                  className="text-body-xs text-brand-blue font-medium hover:underline focus:outline-none flex items-center gap-1"
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
                    <pre className="text-body-2xs text-txt-secondary overflow-x-auto max-h-48 overflow-y-auto whitespace-pre-wrap">
                      {exportedDoc}
                    </pre>
                  </div>
                )}
              </div>

              {directory && (
                <div className="rounded-oc border border-blue-200 bg-brand-light p-3">
                  <p className="text-body-2xs text-brand">
                    DeDi hosts this file when you publish — no web server needed. You&apos;ll
                    connect your DeDi namespace (or create one) in the next step.
                  </p>
                </div>
              )}

              {/* Collapsible: Publishing Instructions + no-website link (website only) */}
              {!directory && (
                <>
                  <div>
                    <button
                      onClick={() => setShowInstructions(!showInstructions)}
                      className="text-body-xs text-brand-blue font-medium hover:underline focus:outline-none flex items-center gap-1"
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
                      <div className="mt-2 rounded-oc border border-blue-200 bg-brand-light p-3 space-y-2">
                        <p className="text-body-2xs text-brand italic">
                          You will need access to your organization&apos;s website hosting. Your IT
                          administrator or web developer can help with this step.
                        </p>
                        <ol className="text-body-2xs text-brand list-decimal list-inside space-y-0.5">
                          <li>
                            Save the DID document as{" "}
                            <code className="bg-brand-light px-1 rounded">did.json</code>
                          </li>
                          <li>
                            Upload it to{" "}
                            <code className="bg-brand-light px-1 rounded">
                              https://{domain.trim()}/.well-known/did.json
                            </code>
                          </li>
                          <li>
                            Ensure the file is served with{" "}
                            <code className="bg-brand-light px-1 rounded">
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
                      className="text-body-2xs text-txt-muted hover:text-txt-secondary hover:underline focus:outline-none"
                    >
                      I don&apos;t have a website
                    </button>
                    {showNoWebsite && (
                      <div className="mt-2 rounded-oc border border-border-light bg-surface-warm p-3">
                        <p className="text-body-2xs text-txt-secondary">
                          You can still issue credentials. Verifiers will need your public key
                          shared directly. You can also set up DeDi later from Settings to publish
                          your key to a public directory.
                        </p>
                      </div>
                    )}
                  </div>
                </>
              )}
            </div>
          )}

          <div className="pt-2 flex gap-3">
            {exportedDoc && (
              <Button onClick={() => setStep(directory ? "complete" : "verify")}>Continue</Button>
            )}
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
              Check your site is serving it
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Optionally verify that your DID document is accessible at the expected URL. You can
              skip this step and verify later.
            </p>
          </div>

          <div className="rounded-oc border border-border-light bg-surface-warm p-3">
            <p className="oc-label mb-1">Expected URL</p>
            <p className="font-mono text-body-2xs text-txt-primary break-all">
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
                  ? "border-state-success-border bg-state-success-bg"
                  : "border-state-warning-border bg-state-warning-bg"
              }`}
            >
              {verifyResult.accessible ? (
                <p className="text-body-xs text-state-success font-medium">
                  DID document is accessible and valid.
                </p>
              ) : (
                <div className="space-y-1">
                  <p className="text-body-xs text-state-warning font-medium">
                    DID document not accessible yet.
                  </p>
                  {verifyResult.error && (
                    <p className="text-body-2xs text-state-warning">{verifyResult.error}</p>
                  )}
                  <p className="text-body-2xs text-state-warning">
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
            <p className="font-mono text-body-2xs text-txt-primary break-all">{didKeyDid}</p>
          </div>

          <div className="rounded-oc border border-state-success-border bg-state-success-bg p-3 space-y-1">
            <p className="text-body-2xs font-medium text-state-success">Key Generated</p>
            <p className="text-body-2xs text-state-success">Algorithm: {generatedKey.algorithm}</p>
            <p className="text-body-2xs text-state-success">
              Fingerprint: {generatedKey.fingerprint.slice(0, 32)}...
            </p>
          </div>

          <div className="pt-2 flex gap-3">
            <Button onClick={() => setStep("did-key-backup")}>Continue</Button>
            <Button variant="secondary" onClick={backToMethodChoice}>
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

          <div className="rounded-oc border border-amber-300 bg-state-warning-bg p-4 space-y-2">
            <p className="text-body-xs font-medium text-amber-900">What you should do now</p>
            <ul className="text-body-xs text-state-warning list-disc list-inside space-y-1">
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
            <p className="text-body-2xs text-state-warning italic pt-1">
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
            <span className="text-body-xs text-txt-primary">
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
              Your issuer identity is ready
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Your signing identity is set up. You can now issue and sign Verifiable Credentials.
            </p>
          </div>

          <div className="rounded-oc border border-state-success-border bg-state-success-bg p-4 space-y-2">
            <h3 className="oc-card-label" style={{ color: "#2e7d32" }}>
              Profile Summary
            </h3>
            <dl className="text-body-xs text-state-success space-y-1.5">
              <div className="flex gap-2">
                <dt className="font-medium w-24 flex-shrink-0">DID:</dt>
                <dd className="font-mono text-body-2xs break-all">
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
                <dd className="font-mono text-body-2xs">{generatedKey.fingerprint}</dd>
              </div>
              <div className="flex gap-2">
                <dt className="font-medium w-24 flex-shrink-0">Source:</dt>
                <dd>
                  {directory
                    ? "Public directory (DeDi)"
                    : method === "web"
                      ? "Your website"
                      : "Self-contained key"}
                </dd>
              </div>
            </dl>
          </div>

          <div className="pt-2 flex gap-3">
            <Button onClick={() => void handleCompleteHandoff()}>Start Issuing Credentials</Button>
            <Button
              variant="secondary"
              onClick={() =>
                // Directory skips the .well-known verify step (DeDi hosts the
                // doc), so Back from "complete" must return to "export", not to
                // a verify screen the directory user never saw.
                setStep(directory ? "export" : method === "web" ? "verify" : "did-key-backup")
              }
            >
              Back
            </Button>
          </div>
        </Card>
      )}
    </div>
  );
}
