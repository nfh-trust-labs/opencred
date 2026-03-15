/**
 * OnboardingWizard — multi-step first-run setup for new users.
 *
 * Presents 3 onboarding paths:
 *   1. "I have a DSC" → choose source (Upload File, Hardware Token, OS Cert Store) → Profile
 *   2. "I want to get a DSC" → Coming Soon (connect to CAs)
 *   3. "Get started without a DSC" → Coming Soon (OpenCred-Attested)
 *
 * On completion the wizard calls `onComplete` so the parent can
 * switch to the main sidebar interface.
 *
 * SECURITY NOTE: Private keys are never exposed to the renderer.
 * The file path is sent to the main process via IPC and only key
 * metadata (ID, fingerprint, algorithm) is returned.
 */

import { useState } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { KeyImport } from "./KeyImport";
import { HardwareToken } from "./HardwareToken";
import { OsCertStore } from "./OsCertStore";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Step =
  | "welcome"
  | "choose-path"
  | "dsc-source"
  | "dsc-upload"
  | "dsc-hardware"
  | "dsc-os-cert"
  | "profile"
  | "get-dsc-soon"
  | "attested-soon";

interface OnboardingWizardProps {
  onComplete: () => void;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function OnboardingWizard({ onComplete }: OnboardingWizardProps) {
  const [step, setStep] = useState<Step>("welcome");
  const [importedKey, setImportedKey] = useState<KeyMetadata | null>(null);

  // ------------------------------------------------------------------
  // Key connected handler (shared by all DSC sources)
  // ------------------------------------------------------------------

  function handleKeyReady(key: KeyMetadata) {
    setImportedKey(key);
    setStep("profile");
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-surface-bg flex flex-col font-body">
      <div className="oc-titlebar">
        <span style={{ flex: 1, textAlign: "center" }}>OpenCred</span>
      </div>

      <main className="flex-1 flex items-start justify-center pt-12 px-4">
        <div className="w-full max-w-xl">

          {/* ============================================================
              Step: Welcome
              ============================================================ */}
          {step === "welcome" && (
            <Card className="space-y-6 text-center">
              <div className="space-y-3">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  Welcome to OpenCred
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  Let&apos;s set up your signing identity. This will allow you to issue
                  and sign Verifiable Credentials from your desktop.
                </p>
              </div>
              <p className="oc-label">
                Your private keys never leave this machine. All signing happens locally.
              </p>
              <div className="pt-2">
                <Button onClick={() => setStep("choose-path")}>Get Started</Button>
              </div>
            </Card>
          )}

          {/* ============================================================
              Step: Choose Path (3 options)
              ============================================================ */}
          {step === "choose-path" && (
            <Card variant="neutral" className="space-y-6">
              <div className="space-y-2">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  How would you like to get started?
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  Choose how to set up your signing identity.
                </p>
              </div>

              <div className="space-y-3">
                {/* Option 1: I have a DSC */}
                <button
                  onClick={() => setStep("dsc-source")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <span className="block text-body-sm font-semibold text-txt-primary">
                    I have a Document Signer Certificate
                  </span>
                  <span className="block text-[0.78rem] text-txt-muted mt-1">
                    Sign credentials using your existing DSC from a certificate authority
                  </span>
                </button>

                {/* Option 2: I want to get a DSC */}
                <button
                  onClick={() => setStep("get-dsc-soon")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-border-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="block text-body-sm font-semibold text-txt-primary">
                        I want to get a DSC
                      </span>
                      <span className="block text-[0.78rem] text-txt-muted mt-1">
                        Connect to a Certificate Authority to obtain your DSC
                      </span>
                    </div>
                    <span className="inline-flex items-center rounded-oc bg-amber-50 border border-amber-200/60 px-2 py-0.5 font-mono text-[0.6rem] uppercase tracking-wider text-amber-700 flex-shrink-0 ml-3 mt-0.5">
                      Coming Soon
                    </span>
                  </div>
                </button>

                {/* Option 3: Get started without a DSC */}
                <button
                  onClick={() => setStep("attested-soon")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-border-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="block text-body-sm font-semibold text-txt-primary">
                        Get started without a DSC
                      </span>
                      <span className="block text-[0.78rem] text-txt-muted mt-1">
                        Generate a key and get OpenCred-attested to start issuing credentials
                      </span>
                    </div>
                    <span className="inline-flex items-center rounded-oc bg-amber-50 border border-amber-200/60 px-2 py-0.5 font-mono text-[0.6rem] uppercase tracking-wider text-amber-700 flex-shrink-0 ml-3 mt-0.5">
                      Coming Soon
                    </span>
                  </div>
                </button>
              </div>

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep("welcome")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* ============================================================
              Step: DSC Source (3 sub-options)
              ============================================================ */}
          {step === "dsc-source" && (
            <Card variant="neutral" className="space-y-6">
              <div className="space-y-2">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  How is your DSC stored?
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  Choose where your Document Signer Certificate is located.
                  Your private key never leaves your machine.
                </p>
              </div>

              <div className="space-y-3">
                {/* Upload file */}
                <button
                  onClick={() => setStep("dsc-upload")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <span className="block text-body-sm font-semibold text-txt-primary">
                    Certificate File
                  </span>
                  <span className="block text-[0.78rem] text-txt-muted mt-1">
                    Import a PFX (.pfx, .p12) or PEM (.pem, .crt) file from your computer
                  </span>
                </button>

                {/* Hardware token */}
                <button
                  onClick={() => setStep("dsc-hardware")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <span className="block text-body-sm font-semibold text-txt-primary">
                    Hardware Token
                  </span>
                  <span className="block text-[0.78rem] text-txt-muted mt-1">
                    Connect a PKCS#11 device (YubiKey, smart card, HSM)
                  </span>
                </button>

                {/* OS certificate store */}
                <button
                  onClick={() => setStep("dsc-os-cert")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <span className="block text-body-sm font-semibold text-txt-primary">
                    OS Certificate Store
                  </span>
                  <span className="block text-[0.78rem] text-txt-muted mt-1">
                    Use a certificate from macOS Keychain or Windows Certificate Store
                  </span>
                </button>
              </div>

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep("choose-path")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* ============================================================
              DSC: Upload File
              ============================================================ */}
          {step === "dsc-upload" && (
            <Card className="space-y-5">
              <div className="space-y-2">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  Import Certificate File
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  Select a PFX, PEM, JWK, or PKCS#8 DER file from your computer.
                  Only ECDSA P-256 keys are accepted. Your private key never leaves this machine.
                </p>
              </div>
              <KeyImport
                onKeyImported={() => {
                  void window.opencred.listKeys().then((response) => {
                    if (response.keys.length > 0) {
                      handleKeyReady(response.keys[response.keys.length - 1]);
                    }
                  });
                }}
              />
              <div className="pt-1">
                <Button variant="secondary" onClick={() => setStep("dsc-source")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* ============================================================
              DSC: Hardware Token
              ============================================================ */}
          {step === "dsc-hardware" && (
            <Card className="space-y-5">
              <div className="space-y-2">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  Connect Hardware Token
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  Connect a PKCS#11 device such as a YubiKey, smart card, or HSM
                  to use your DSC for signing.
                </p>
              </div>
              <HardwareToken
                onKeyConnected={() => {
                  void window.opencred.listKeys().then((response) => {
                    if (response.keys.length > 0) {
                      handleKeyReady(response.keys[response.keys.length - 1]);
                    }
                  });
                }}
              />
              <div className="pt-1">
                <Button variant="secondary" onClick={() => setStep("dsc-source")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* ============================================================
              DSC: OS Certificate Store
              ============================================================ */}
          {step === "dsc-os-cert" && (
            <Card className="space-y-5">
              <div className="space-y-2">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  OS Certificate Store
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  Browse certificates from macOS Keychain or Windows Certificate Store.
                  Your private key stays in the OS — signing is handled natively.
                </p>
              </div>
              <OsCertStore
                onKeyConnected={() => {
                  void window.opencred.listKeys().then((response) => {
                    if (response.keys.length > 0) {
                      handleKeyReady(response.keys[response.keys.length - 1]);
                    }
                  });
                }}
              />
              <div className="pt-1">
                <Button variant="secondary" onClick={() => setStep("dsc-source")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* ============================================================
              Profile Summary (after any DSC source)
              ============================================================ */}
          {step === "profile" && importedKey && (
            <Card className="space-y-6">
              <div className="space-y-2">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  Signing Identity Ready
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  Your signing key has been connected successfully.
                </p>
              </div>

              <div className="rounded-oc border border-green-200 bg-green-50 p-4 space-y-2">
                <h3 className="oc-card-label" style={{ color: "#2e7d32" }}>Key Details</h3>
                <dl className="text-[0.78rem] text-green-700 space-y-1.5">
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">DID:</dt>
                    <dd className="font-mono text-[0.72rem] break-all">{importedKey.id}</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">Algorithm:</dt>
                    <dd>{importedKey.algorithm}</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">Fingerprint:</dt>
                    <dd className="font-mono text-[0.72rem]">{importedKey.fingerprint}</dd>
                  </div>
                  {importedKey.source && (
                    <div className="flex gap-2">
                      <dt className="font-medium w-24 flex-shrink-0">Source:</dt>
                      <dd>{importedKey.source}</dd>
                    </div>
                  )}
                </dl>
              </div>

              <div className="pt-2">
                <Button onClick={onComplete}>Continue to OpenCred</Button>
              </div>
            </Card>
          )}

          {/* ============================================================
              Coming Soon: Get a DSC
              ============================================================ */}
          {step === "get-dsc-soon" && (
            <Card variant="neutral" className="space-y-6">
              <div className="space-y-2">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  Get a Document Signer Certificate
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  OpenCred will connect you to trusted Certificate Authorities to
                  obtain your own DSC. This feature is under development.
                </p>
              </div>

              <div className="rounded-oc border border-amber-200 bg-amber-50 p-4">
                <p className="text-[0.82rem] text-amber-800 font-medium mb-1">Coming Soon</p>
                <p className="text-[0.78rem] text-amber-700">
                  CA integration is being built as part of Phase 3. In the meantime,
                  if you already have a DSC from a certificate authority, choose
                  &ldquo;I have a DSC&rdquo; to import it.
                </p>
              </div>

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep("choose-path")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* ============================================================
              Coming Soon: OpenCred Attested
              ============================================================ */}
          {step === "attested-soon" && (
            <Card variant="neutral" className="space-y-6">
              <div className="space-y-2">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  OpenCred-Attested Issuance
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  Generate a signing key and have OpenCred attest your identity
                  through domain and business verification. No DSC required.
                </p>
              </div>

              <div className="rounded-oc border border-amber-200 bg-amber-50 p-4">
                <p className="text-[0.82rem] text-amber-800 font-medium mb-1">Coming Soon</p>
                <p className="text-[0.78rem] text-amber-700">
                  OpenCred-attested issuance will generate a key, verify your
                  organization through domain ownership and business credentials,
                  then attest your public key with OpenCred&apos;s DSC. This creates
                  a trust chain without requiring your own certificate authority.
                </p>
              </div>

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep("choose-path")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

        </div>
      </main>
    </div>
  );
}
