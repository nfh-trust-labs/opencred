/**
 * OnboardingWizard — multi-step first-run setup for new users.
 *
 * Steps:
 *  1. Welcome — introduction to OpenCred
 *  2. DSC check — "Do you have a Document Signer Certificate?"
 *  3. Import DSC — file picker for PFX/PEM import
 *  4. Profile summary — show imported key metadata
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

type Step = 1 | 2 | 3 | 4;

interface OnboardingWizardProps {
  onComplete: () => void;
}

export function OnboardingWizard({ onComplete }: OnboardingWizardProps) {
  const [step, setStep] = useState<Step>(1);
  const [hasDsc, setHasDsc] = useState<boolean | null>(null);
  const [password, setPassword] = useState("");
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importedKey, setImportedKey] = useState<KeyMetadata | null>(null);

  // ------------------------------------------------------------------
  // Step 3: DSC import
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
        return; // User cancelled.
      }

      const importResult = await window.opencred.importKey({
        filePath: fileResult.filePath,
        label: password ? undefined : undefined,
      });

      if (importResult.success && importResult.key) {
        setImportedKey(importResult.key);
        setPassword("");
        setStep(4);
      } else {
        setImportError(importResult.error ?? "Import failed. Please check the file format.");
      }
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "Import failed.");
    } finally {
      setImporting(false);
    }
  }

  async function handleGenerateTestKey() {
    setImportError(null);
    setImporting(true);

    try {
      const result = await window.opencred.generateKey({
        label: "Test Signing Key",
      });

      if (result.success && result.key) {
        setImportedKey(result.key);
        setStep(4);
      } else {
        setImportError(result.error ?? "Key generation failed.");
      }
    } catch (err) {
      setImportError(err instanceof Error ? err.message : "Key generation failed.");
    } finally {
      setImporting(false);
    }
  }

  // ------------------------------------------------------------------
  // Step indicator
  // ------------------------------------------------------------------

  function StepIndicator() {
    const steps: Step[] = [1, 2, 3, 4];
    return (
      <div className="flex items-center justify-center gap-2 mb-8">
        {steps.map((s) => (
          <div
            key={s}
            className={`h-2.5 w-2.5 rounded-full transition-colors ${
              s === step
                ? "bg-blue-600"
                : s < step
                  ? "bg-blue-300"
                  : "bg-gray-200"
            }`}
            aria-label={`Step ${s}${s === step ? " (current)" : ""}`}
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
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="mx-auto max-w-2xl px-4 py-4">
          <h1 className="text-lg font-semibold text-gray-900">OpenCred</h1>
        </div>
      </header>

      {/* Wizard content */}
      <main className="flex-1 flex items-start justify-center pt-16 px-4">
        <div className="w-full max-w-lg">
          <StepIndicator />

          {/* Step 1: Welcome */}
          {step === 1 && (
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
                <Button onClick={() => setStep(2)}>Get Started</Button>
              </div>
            </Card>
          )}

          {/* Step 2: DSC check */}
          {step === 2 && (
            <Card className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-lg font-semibold text-gray-900">
                  Do you have a Document Signer Certificate (DSC)?
                </h2>
                <p className="text-sm text-gray-600">
                  A DSC is issued by a Certificate Authority and binds your signing key
                  to your organization&apos;s identity. If you have one, we can import it now.
                </p>
              </div>

              <div className="space-y-3">
                <button
                  onClick={() => {
                    setHasDsc(true);
                    setStep(3);
                  }}
                  className="w-full rounded-lg border-2 border-gray-200 p-4 text-left transition-colors hover:border-blue-500 hover:bg-blue-50 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <span className="block text-sm font-medium text-gray-900">
                    Yes, I have a DSC
                  </span>
                  <span className="block text-xs text-gray-500 mt-1">
                    Import your PFX or PEM certificate file
                  </span>
                </button>

                <button
                  onClick={() => {
                    setHasDsc(false);
                  }}
                  className="w-full rounded-lg border-2 border-gray-200 p-4 text-left transition-colors hover:border-gray-400 hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-gray-400"
                >
                  <span className="block text-sm font-medium text-gray-900">
                    No, I don&apos;t have one
                  </span>
                  <span className="block text-xs text-gray-500 mt-1">
                    You can generate a test key or set up attestation later
                  </span>
                </button>
              </div>

              {hasDsc === false && (
                <div className="rounded-lg border border-blue-200 bg-blue-50 p-4 space-y-3">
                  <p className="text-sm text-blue-800">
                    Key Attestation flow coming soon. You can also generate a key pair
                    for testing.
                  </p>
                  <Button
                    onClick={() => void handleGenerateTestKey()}
                    disabled={importing}
                  >
                    {importing ? "Generating..." : "Generate Test Key"}
                  </Button>
                  {importError && (
                    <p className="text-sm text-red-600">{importError}</p>
                  )}
                </div>
              )}

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep(1)}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* Step 3: Import DSC */}
          {step === 3 && (
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

              {/* Password field for PFX files */}
              <div>
                <label
                  htmlFor="pfx-password"
                  className="block text-xs font-medium text-gray-600"
                >
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

              <div className="flex items-center gap-3">
                <Button
                  onClick={() => void handleImportDsc()}
                  disabled={importing}
                >
                  {importing ? "Importing..." : "Choose File & Import"}
                </Button>
              </div>

              {importError && (
                <div className="rounded-md border border-red-200 bg-red-50 p-3">
                  <p className="text-sm text-red-700">{importError}</p>
                </div>
              )}

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep(2)}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* Step 4: Profile summary */}
          {step === 4 && importedKey && (
            <Card className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-lg font-semibold text-gray-900">
                  Signing Identity Ready
                </h2>
                <p className="text-sm text-gray-600">
                  Your signing key has been imported successfully. You can now issue and
                  sign Verifiable Credentials.
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
                  {importedKey.format && (
                    <div className="flex gap-2">
                      <dt className="font-medium w-24 flex-shrink-0">Format:</dt>
                      <dd>{importedKey.format}</dd>
                    </div>
                  )}
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">Fingerprint:</dt>
                    <dd className="font-mono">{importedKey.fingerprint}</dd>
                  </div>
                  {importedKey.source && (
                    <div className="flex gap-2">
                      <dt className="font-medium w-24 flex-shrink-0">Source:</dt>
                      <dd>{importedKey.source}</dd>
                    </div>
                  )}
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">Imported:</dt>
                    <dd>{new Date(importedKey.importedAt).toLocaleString()}</dd>
                  </div>
                </dl>
              </div>

              <div className="pt-2">
                <Button onClick={onComplete}>Continue to OpenCred</Button>
              </div>
            </Card>
          )}
        </div>
      </main>
    </div>
  );
}
