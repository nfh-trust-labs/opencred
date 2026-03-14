/**
 * OnboardingWizard — multi-step first-run setup for new users.
 *
 * Supports two workflows:
 *   Workflow 1 (DSC): Welcome → DSC check → Import DSC → Profile summary
 *   Workflow 3 (Quick Start): Welcome → DSC check → Generate Key →
 *     Organization Info → Domain Verification → Attestation Result
 *
 * On completion the wizard calls `onComplete` so the parent can
 * switch to the main tabbed interface.
 *
 * SECURITY NOTE: Private keys are never exposed to the renderer.
 * The file path is sent to the main process via IPC and only key
 * metadata (ID, fingerprint, algorithm) is returned.
 */

import { useState } from "react";
import type { KeyMetadata } from "../../shared/ipc-types";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { KeyGenerationStep } from "./KeyGenerationStep";
import { OrganizationInfoStep } from "./OrganizationInfoStep";
import { DomainVerificationStep } from "./DomainVerificationStep";
import { AttestationResultStep } from "./AttestationResultStep";

type Workflow = "dsc" | "quick-start";

// DSC workflow steps
type DscStep = "welcome" | "dsc-check" | "import-dsc" | "profile";
// Quick Start workflow steps
type QuickStartStep = "welcome" | "dsc-check" | "key-gen" | "org-info" | "domain-verify" | "attestation-result";

type Step = DscStep | QuickStartStep;

interface OnboardingWizardProps {
  onComplete: () => void;
}

export function OnboardingWizard({ onComplete }: OnboardingWizardProps) {
  const [workflow, setWorkflow] = useState<Workflow | null>(null);
  const [step, setStep] = useState<Step>("welcome");

  // DSC workflow state
  const [password, setPassword] = useState("");
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importedKey, setImportedKey] = useState<KeyMetadata | null>(null);

  // Quick Start workflow state
  const [generatedKey, setGeneratedKey] = useState<{ id: string; fingerprint: string; algorithm: string } | null>(null);
  const [orgInfo, setOrgInfo] = useState<{ organizationName: string; domain: string } | null>(null);
  const [attestationCredential, setAttestationCredential] = useState<Record<string, unknown> | null>(null);

  // Step counts for progress indicator
  const dscSteps: DscStep[] = ["welcome", "dsc-check", "import-dsc", "profile"];
  const quickStartSteps: QuickStartStep[] = ["welcome", "dsc-check", "key-gen", "org-info", "domain-verify", "attestation-result"];
  const currentSteps = workflow === "quick-start" ? quickStartSteps : dscSteps;
  const stepIndex = currentSteps.indexOf(step as never);

  // ------------------------------------------------------------------
  // DSC import handler
  // ------------------------------------------------------------------

  async function handleImportDsc() {
    setImportError(null);
    setImporting(true);

    try {
      const fileResult = await window.opencred.openFile({
        title: "Select Document Signer Certificate",
        filters: [
          { name: "Certificate Files", extensions: ["pfx", "p12", "pem", "crt", "key"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (!fileResult.filePath) {
        setImporting(false);
        return;
      }

      const importResult = await window.opencred.importKey({
        filePath: fileResult.filePath,
        label: undefined,
        password: password || undefined,
      });

      if (importResult.success && importResult.key) {
        setImportedKey(importResult.key);
        setPassword("");
        setStep("profile");
      } else {
        setImportError(importResult.error ?? "Import failed. Please check the file format.");
      }
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "Import failed.");
    } finally {
      setImporting(false);
    }
  }

  // ------------------------------------------------------------------
  // Step indicator
  // ------------------------------------------------------------------

  function StepIndicator() {
    return (
      <div className="flex items-center justify-center gap-2 mb-8">
        {currentSteps.map((s, i) => (
          <div
            key={s}
            className={`h-2.5 w-2.5 rounded-full transition-colors ${
              i === stepIndex
                ? "bg-blue-600"
                : i < stepIndex
                  ? "bg-blue-300"
                  : "bg-gray-200"
            }`}
            aria-label={`Step ${i + 1}${i === stepIndex ? " (current)" : ""}`}
          />
        ))}
      </div>
    );
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <div className="oc-titlebar">
        <span style={{ flex: 1, textAlign: "center" }}>OpenCred</span>
      </div>

      <main className="flex-1 flex items-start justify-center pt-16 px-4">
        <div className="w-full max-w-lg">
          <StepIndicator />

          {/* Step: Welcome */}
          {step === "welcome" && (
            <Card className="space-y-6 text-center">
              <div className="space-y-2">
                <h2 className="text-xl font-semibold text-gray-900">
                  Welcome to OpenCred
                </h2>
                <p className="text-sm text-gray-600">
                  Let&apos;s set up your signing identity. This will allow you to issue
                  and sign Verifiable Credentials from your desktop.
                </p>
              </div>
              <p className="text-xs text-gray-500">
                Your private keys never leave this machine. All signing happens locally.
              </p>
              <div className="pt-2">
                <Button onClick={() => setStep("dsc-check")}>Get Started</Button>
              </div>
            </Card>
          )}

          {/* Step: DSC check */}
          {step === "dsc-check" && (
            <Card className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-lg font-semibold text-gray-900">
                  How would you like to get started?
                </h2>
                <p className="text-sm text-gray-600">
                  Choose how to set up your signing identity.
                </p>
              </div>

              <div className="space-y-3">
                <button
                  onClick={() => {
                    setWorkflow("dsc");
                    setStep("import-dsc");
                  }}
                  className="w-full rounded-lg border-2 border-gray-200 p-4 text-left transition-colors hover:border-blue-500 hover:bg-blue-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <span className="block text-sm font-medium text-gray-900">
                    I have a DSC
                  </span>
                  <span className="block text-xs text-gray-500 mt-1">
                    Import your PFX or PEM certificate file
                  </span>
                </button>

                <button
                  onClick={() => {
                    setWorkflow("quick-start");
                    setStep("key-gen");
                  }}
                  className="w-full rounded-lg border-2 border-gray-200 p-4 text-left transition-colors hover:border-blue-500 hover:bg-blue-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <span className="block text-sm font-medium text-gray-900">
                    Quick Start
                  </span>
                  <span className="block text-xs text-gray-500 mt-1">
                    Generate a key and verify your domain for attestation
                  </span>
                </button>
              </div>

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep("welcome")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* DSC Workflow: Import DSC */}
          {step === "import-dsc" && (
            <Card className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-lg font-semibold text-gray-900">
                  Import your Document Signer Certificate
                </h2>
                <p className="text-sm text-gray-600">
                  Select a PFX (.pfx, .p12) or PEM (.pem, .crt) file from your computer.
                  The private key stays on this machine and is never transmitted.
                </p>
              </div>

              <div>
                <label htmlFor="pfx-password" className="block text-xs font-medium text-gray-600">
                  Certificate Password (if PFX/P12)
                </label>
                <input
                  id="pfx-password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Leave blank if not password-protected"
                  disabled={importing}
                  className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
                />
              </div>

              <Button onClick={() => void handleImportDsc()} disabled={importing}>
                {importing ? "Importing..." : "Choose File & Import"}
              </Button>

              {importError && (
                <div className="rounded-md border border-red-200 bg-red-50 p-3">
                  <p className="text-sm text-red-700">{importError}</p>
                </div>
              )}

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep("dsc-check")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* DSC Workflow: Profile summary */}
          {step === "profile" && importedKey && (
            <Card className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-lg font-semibold text-gray-900">Signing Identity Ready</h2>
                <p className="text-sm text-gray-600">
                  Your signing key has been imported successfully.
                </p>
              </div>

              <div className="rounded-lg border border-green-200 bg-green-50 p-4 space-y-2">
                <h3 className="text-sm font-medium text-green-800">Key Details</h3>
                <dl className="text-xs text-green-700 space-y-1">
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">DID:</dt>
                    <dd className="font-mono break-all">{importedKey.id}</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">Algorithm:</dt>
                    <dd>{importedKey.algorithm}</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">Fingerprint:</dt>
                    <dd className="font-mono">{importedKey.fingerprint}</dd>
                  </div>
                </dl>
              </div>

              <div className="pt-2">
                <Button onClick={onComplete}>Continue to OpenCred</Button>
              </div>
            </Card>
          )}

          {/* Quick Start: Generate Key */}
          {step === "key-gen" && (
            <KeyGenerationStep
              onKeyGenerated={(keyMeta) => {
                setGeneratedKey(keyMeta);
                setStep("org-info");
              }}
              onBack={() => setStep("dsc-check")}
            />
          )}

          {/* Quick Start: Organization Info */}
          {step === "org-info" && (
            <OrganizationInfoStep
              onSubmit={(info) => {
                setOrgInfo(info);
                setStep("domain-verify");
              }}
              onBack={() => setStep("key-gen")}
            />
          )}

          {/* Quick Start: Domain Verification */}
          {step === "domain-verify" && orgInfo && generatedKey && (
            <DomainVerificationStep
              domain={orgInfo.domain}
              keyId={generatedKey.id}
              organizationName={orgInfo.organizationName}
              onVerified={(credential) => {
                setAttestationCredential(credential);
                setStep("attestation-result");
              }}
              onBack={() => setStep("org-info")}
            />
          )}

          {/* Quick Start: Attestation Result */}
          {step === "attestation-result" && attestationCredential && generatedKey && orgInfo && (
            <AttestationResultStep
              attestationCredential={attestationCredential}
              keyId={generatedKey.id}
              organizationName={orgInfo.organizationName}
              domain={orgInfo.domain}
              onComplete={onComplete}
            />
          )}
        </div>
      </main>
    </div>
  );
}
