/**
 * OnboardingWizard — multi-step first-run setup for new users.
 *
 * Presents 3 onboarding paths:
 *   1. "I have a DSC" → choose source (Upload File, Hardware Token, OS Cert Store) → Profile
 *   2. "I want to get a DSC" → Coming Soon (connect to CAs)
 *   3. "Self-Published Keys" → Generate key, enter domain, export DID doc → Profile
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
import { Badge } from "./ui/Badge";
import { KeyImport } from "./KeyImport";
import { HardwareToken } from "./HardwareToken";
import { OsCertStore } from "./OsCertStore";
import { SelfPublishedSetup } from "./SelfPublishedSetup";
import { DeDiSetup } from "./DeDiSetup";
import { DISPLAY_STEPS, getDisplayStepIndex, type Step } from "./onboarding-steps";
import logoSrc from "../assets/logo.svg";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface OnboardingWizardProps {
  onComplete: () => void;
}

// ---------------------------------------------------------------------------
// Progress Indicator — maps internal steps to the visible DISPLAY_STEPS
// (mapping + step model live in ./onboarding-steps for unit testing).
// ---------------------------------------------------------------------------

function StepIndicator({ step, selfPubPhase }: { step: Step; selfPubPhase: string | null }) {
  const currentIndex = getDisplayStepIndex(step, selfPubPhase);

  return (
    <div className="w-full max-w-xl mb-8">
      <div className="flex items-center justify-between relative">
        {/* Background line */}
        <div className="absolute top-3 left-0 right-0 h-0.5 bg-gray-200" />
        {/* Progress line */}
        <div
          className="absolute top-3 left-0 h-0.5 bg-brand-blue transition-all duration-300"
          style={{ width: `${(currentIndex / (DISPLAY_STEPS.length - 1)) * 100}%` }}
        />

        {DISPLAY_STEPS.map((label, i) => {
          const isActive = i === currentIndex;
          const isCompleted = i < currentIndex;
          return (
            <div key={label} className="flex flex-col items-center relative z-10">
              <div
                className={`w-6 h-6 rounded-full flex items-center justify-center text-body-2xs font-semibold transition-colors ${
                  isActive
                    ? "bg-brand-blue text-white"
                    : isCompleted
                      ? "bg-brand-blue text-white"
                      : "bg-gray-200 text-txt-muted"
                }`}
              >
                {isCompleted ? "\u2713" : i + 1}
              </div>
              <span
                className={`mt-1.5 text-body-2xs font-medium whitespace-nowrap ${
                  isActive
                    ? "text-brand-blue"
                    : isCompleted
                      ? "text-txt-secondary"
                      : "text-txt-muted"
                }`}
              >
                {label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// "Which should I choose?" guidance
// ---------------------------------------------------------------------------

function PathGuidance() {
  const [open, setOpen] = useState(false);

  return (
    <div className="pt-1">
      <button
        onClick={() => setOpen(!open)}
        className="text-body-xs text-brand-blue font-medium hover:underline focus:outline-none flex items-center gap-1"
      >
        <svg
          width="12"
          height="12"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          className={`transition-transform duration-200 ${open ? "rotate-180" : ""}`}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
        Which should I choose?
      </button>
      {open && (
        <div className="mt-3 rounded-oc border border-border-light bg-surface-warm p-4 space-y-3 text-body-xs text-txt-secondary">
          <p>
            <span className="font-semibold text-txt-primary">My organisation has a website</span>:
            best if you control a domain (e.g. acme.org). Your website becomes your identity, and you
            can replace your key later if needed.
          </p>
          <p>
            <span className="font-semibold text-txt-primary">Publish to a DeDi directory</span>:
            choose this if you use DeDi. It is not a managed service — you create your own DeDi
            account and namespace; OpenCred then publishes your key there (with key replacement and
            revocation) so verifiers can resolve it. We&apos;ll point you to DeDi if you don&apos;t
            have a namespace yet.
          </p>
          <p>
            <span className="font-semibold text-txt-primary">I have an official certificate</span>:
            choose this if you already have a government-issued signing certificate.
          </p>
          <p>
            <span className="font-semibold text-txt-primary">Just get started</span>: the simplest
            option — a self-contained key that works offline. Trade-off: it can&apos;t be replaced
            later.
          </p>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function OnboardingWizard({ onComplete }: OnboardingWizardProps) {
  const [step, setStep] = useState<Step>("welcome");
  const [importedKey, setImportedKey] = useState<KeyMetadata | null>(null);
  const [selfPubDomain, setSelfPubDomain] = useState<string | null>(null);
  const [selfPubDidDoc, setSelfPubDidDoc] = useState<string | null>(null);
  // Which DID method the user picked in SelfPublishedSetup. `null` means the
  // self-pub flow hasn't completed (or the user never entered it). Used by
  // DeDiSetup to render attribution-only mode for did:key (no DID document
  // to publish) and by the Back logic to distinguish "user finished
  // self-pub" from "user completed DSC and selfPubFlowEntered is stale".
  const [selfPubMethod, setSelfPubMethod] = useState<"web" | "key" | null>(null);
  // The canonical (fragment-less) issuer DID that the user committed to in
  // the self-pub flow — `did:web:<domain>` for the did:web branch, or
  // `did:key:z…` (the signer's id minus its `#fragment`) for the did:key
  // branch. Threaded into DeDiSetup so the DeDi record name matches the
  // `issuer` field a verifier later resolves; using `importedKey.id` (the
  // full verification-method ref `did:key:z…#z…`) would publish under the
  // wrong record name and silently break cross-surface attribution lookup.
  const [selfPubDid, setSelfPubDid] = useState<string | null>(null);
  // Track which DSC source the user came from so the `profile` Back button
  // can return to that specific source instead of the generic `dsc-source`
  // picker. Set in `handleKeyReady`. Issue #547.
  const [dscSourceStep, setDscSourceStep] = useState<
    "dsc-upload" | "dsc-hardware" | "dsc-os-cert" | null
  >(null);
  // `selfPubFlowEntered` flips the moment the user steps into the self-pub
  // sub-flow and stays true for the rest of the wizard. It lets us keep
  // `<SelfPublishedSetup />` mounted (hidden via CSS) once entered, so
  // navigating back from `dedi-setup` preserves the user's generated key,
  // domain, exported doc, etc. that would otherwise live only in
  // SelfPublishedSetup's local useState. Issue #547.
  const [selfPubFlowEntered, setSelfPubFlowEntered] = useState(false);
  // The self-pub sub-flow reports its current phase so the step indicator can
  // tell "Your key" phases apart from "Publish" phases (fixes the skipped-step
  // bug). `null` until the self-pub flow mounts and emits its first phase.
  const [selfPubPhase, setSelfPubPhase] = useState<string | null>(null);
  // The identity anchor the user picked on the Step-2 situation screen. Drives
  // the preset method handed to SelfPublishedSetup so the in-flow method picker
  // is skipped — the user already answered "where should your identity live?".
  const [anchorMethod, setAnchorMethod] = useState<"web" | "key" | "directory" | null>(null);

  // ------------------------------------------------------------------
  // Key connected handler (shared by all DSC sources)
  // ------------------------------------------------------------------

  function handleKeyReady(key: KeyMetadata) {
    setImportedKey(key);
    setStep("profile");
  }

  function handleDscSourceClick(target: "dsc-upload" | "dsc-hardware" | "dsc-os-cert") {
    setDscSourceStep(target);
    setStep(target);
  }

  // Enter the self-published flow with the anchor the user picked on the
  // Step-2 situation screen. The preset method skips the in-flow method
  // picker — the user already chose where their identity should live.
  function enterSelfPub(method: "web" | "key" | "directory") {
    setAnchorMethod(method);
    setSelfPubPhase("generate");
    setSelfPubFlowEntered(true);
    setStep("self-pub-setup");
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-surface-bg flex flex-col font-body">
      <div className="oc-titlebar">
        <span
          style={{
            flex: 1,
            textAlign: "center",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: 6,
          }}
        >
          <img src={logoSrc} alt="" width={16} height={16} />
          OpenCred
        </span>
      </div>

      <main className="flex-1 flex flex-col items-center justify-center px-4">
        {/* Step indicator — shown on all steps */}
        <StepIndicator step={step} selfPubPhase={selfPubPhase} />

        <div className="w-full max-w-xl">
          {/* ============================================================
              Step: Welcome
              ============================================================ */}
          {step === "welcome" && (
            <Card className="space-y-6 text-center py-10 px-8">
              <div className="space-y-4">
                <img src={logoSrc} alt="OpenCred logo" width={64} height={64} className="mx-auto" />
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  Welcome to OpenCred
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  Let&apos;s set up your signing identity. This will allow you to issue and sign
                  Verifiable Credentials from your desktop.
                </p>
                <p className="text-body-sm text-txt-primary font-medium">
                  Issue tamper-proof digital certificates that anyone can verify — from your
                  desktop.
                </p>
              </div>
              <p className="oc-label">
                Your private keys never leave this machine. All signing happens locally.
              </p>
              <div className="pt-2 space-y-3">
                <Button onClick={() => setStep("choose-anchor")}>Get Started</Button>
                <p className="text-body-2xs text-txt-muted">Setup takes about 5 minutes</p>
              </div>
            </Card>
          )}

          {/* ============================================================
              Step: Identity anchor — "where should your identity live?"
              Situation-based choices; the protocol (did:web / did:key / DSC)
              is intentionally not surfaced here — see PathGuidance for the
              plain-language "which should I choose?" help.
              ============================================================ */}
          {step === "choose-anchor" && (
            <Card variant="neutral" className="space-y-6">
              <div className="space-y-2">
                <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
                  Where should your issuer identity live?
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  This is how people will trust the credentials you issue. Pick what fits you.
                </p>
              </div>

              <div className="space-y-3">
                {/* Anchor 1: own website (did:web) */}
                <button
                  onClick={() => enterSelfPub("web")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="block text-body-sm font-semibold text-txt-primary">
                        My organisation has a website
                      </span>
                      <span className="block text-body-xs text-txt-muted mt-1">
                        Use your domain (e.g. acme.org) as your identity. You stay in control.
                      </span>
                    </div>
                    <Badge variant="info" className="flex-shrink-0 ml-3 mt-0.5">
                      Recommended
                    </Badge>
                  </div>
                </button>

                {/* Anchor 2: public directory (did:web via a DeDi namespace) */}
                <button
                  onClick={() => enterSelfPub("directory")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="block text-body-sm font-semibold text-txt-primary">
                        Publish to a DeDi directory
                      </span>
                      <span className="block text-body-xs text-txt-muted mt-1">
                        Connect your own DeDi namespace so verifiers can resolve your key. You bring
                        the DeDi account; we set up the registries.
                      </span>
                    </div>
                    <Badge variant="neutral" className="flex-shrink-0 ml-3 mt-0.5">
                      Powered by DeDi
                    </Badge>
                  </div>
                </button>

                {/* Anchor 3: official certificate (DSC) */}
                <button
                  onClick={() => setStep("dsc-source")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <span className="block text-body-sm font-semibold text-txt-primary">
                    I have an official certificate
                  </span>
                  <span className="block text-body-xs text-txt-muted mt-1">
                    Use a government-issued signing certificate. For regulated issuers.
                  </span>
                </button>

                {/* Anchor 4: self-contained key (did:key) */}
                <button
                  onClick={() => enterSelfPub("key")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <span className="block text-body-sm font-semibold text-txt-primary">
                    Just get started
                  </span>
                  <span className="block text-body-xs text-txt-muted mt-1">
                    A self-contained key. Works offline, simplest to set up — but can&apos;t be
                    replaced later.
                  </span>
                </button>
              </div>

              {/* "Which should I choose?" collapsible guidance */}
              <PathGuidance />

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
                  Choose where your Digital Signature Certificate is located. Your private key never
                  leaves your machine.
                </p>
              </div>

              <div className="space-y-3">
                {/* Upload file */}
                <button
                  onClick={() => handleDscSourceClick("dsc-upload")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <span className="block text-body-sm font-semibold text-txt-primary">
                    Certificate File
                  </span>
                  <span className="block text-body-xs text-txt-muted mt-1">
                    Import a PFX (.pfx, .p12) or PEM (.pem, .crt) file from your computer
                  </span>
                </button>

                {/* Hardware token */}
                <button
                  onClick={() => handleDscSourceClick("dsc-hardware")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <span className="block text-body-sm font-semibold text-txt-primary">
                    Hardware Token
                  </span>
                  <span className="block text-body-xs text-txt-muted mt-1">
                    Connect a PKCS#11 device (YubiKey, smart card, HSM)
                  </span>
                </button>

                {/* OS certificate store */}
                <button
                  onClick={() => handleDscSourceClick("dsc-os-cert")}
                  className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
                >
                  <span className="block text-body-sm font-semibold text-txt-primary">
                    OS Certificate Store
                  </span>
                  <span className="block text-body-xs text-txt-muted mt-1">
                    Use a certificate from macOS Keychain or Windows Certificate Store
                  </span>
                </button>
              </div>

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep("choose-anchor")}>
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
                  Select a PFX, PEM, JWK, or PKCS#8 DER file from your computer. Only ECDSA P-256
                  keys are accepted. Your private key never leaves this machine.
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
                  Connect a PKCS#11 device such as a YubiKey, smart card, or HSM to use your DSC for
                  signing.
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
                  Browse certificates from macOS Keychain or Windows Certificate Store. Your private
                  key stays in the OS — signing is handled natively.
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

              <div className="rounded-oc border border-state-success-border bg-state-success-bg p-4 space-y-2">
                <h3 className="oc-card-label" style={{ color: "#2e7d32" }}>
                  Key Details
                </h3>
                <dl className="text-body-xs text-state-success space-y-1.5">
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">DID:</dt>
                    <dd className="font-mono text-body-2xs break-all">{importedKey.id}</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">Algorithm:</dt>
                    <dd>{importedKey.algorithm}</dd>
                  </div>
                  <div className="flex gap-2">
                    <dt className="font-medium w-24 flex-shrink-0">Fingerprint:</dt>
                    <dd className="font-mono text-body-2xs">{importedKey.fingerprint}</dd>
                  </div>
                  {importedKey.source && (
                    <div className="flex gap-2">
                      <dt className="font-medium w-24 flex-shrink-0">Source:</dt>
                      <dd>{importedKey.source}</dd>
                    </div>
                  )}
                </dl>
              </div>

              <div className="pt-2 flex gap-3">
                <Button onClick={() => setStep("dedi-setup")}>Continue</Button>
                <Button variant="secondary" onClick={() => setStep(dscSourceStep ?? "dsc-source")}>
                  Back
                </Button>
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
                  Get a Digital Signature Certificate
                </h2>
                <p className="text-body-sm text-txt-secondary">
                  OpenCred will connect you to trusted Certificate Authorities to obtain your own
                  DSC. This feature is under development.
                </p>
              </div>

              <div className="rounded-oc border border-state-warning-border bg-state-warning-bg p-4">
                <p className="text-body-xs text-state-warning font-medium mb-1">Coming Soon</p>
                <p className="text-body-xs text-state-warning">
                  CA integration is being built as part of Phase 3. In the meantime, if you already
                  have a DSC from a certificate authority, choose &ldquo;I have a DSC&rdquo; to
                  import it.
                </p>
              </div>

              <div className="pt-2">
                <Button variant="secondary" onClick={() => setStep("choose-anchor")}>
                  Back
                </Button>
              </div>
            </Card>
          )}

          {/* ============================================================
              Self-Published Keys Setup
              ============================================================
              Mounted once the user enters the self-pub flow and kept
              mounted thereafter (visibility toggled via `hidden`) so that
              navigating back from `dedi-setup` preserves SelfPub's local
              state (generated key, domain, exported DID document) which
              otherwise lives entirely in SelfPublishedSetup's useState.
              Issue #547. */}
          {selfPubFlowEntered && (
            <SelfPublishedSetup
              // Re-key on the anchor so switching identity choice on the Step-2
              // screen remounts the sub-flow fresh, while back-from-dedi (same
              // anchor) keeps it mounted and preserves the user's progress.
              key={anchorMethod ?? "none"}
              hidden={step !== "self-pub-setup"}
              initialMethod={anchorMethod ?? undefined}
              onPhaseChange={setSelfPubPhase}
              onBack={() => setStep("choose-anchor")}
              onComplete={(result) => {
                if (result) {
                  setImportedKey(result.key);
                  setSelfPubMethod(result.method);
                  // did:web branch carries domain + DID document for the
                  // "publish to your web server" instructions in DeDiSetup.
                  // did:key branch leaves these undefined; DeDiSetup detects
                  // the absence and shifts into attribution-only mode.
                  setSelfPubDomain(result.domain ?? null);
                  setSelfPubDidDoc(result.didDocument ?? null);
                  // Capture the canonical issuer DID — see the field's
                  // declaration comment for why we must not fall back to
                  // `importedKey.id` (full VM ref with #fragment) here.
                  setSelfPubDid(result.did);
                }
                setStep("dedi-setup");
              }}
            />
          )}

          {/* ============================================================
              DeDi Setup (optional)
              ============================================================ */}
          {step === "dedi-setup" && !importedKey && (
            <Card className="space-y-4 text-center">
              <p className="text-body-sm text-txt-muted">Something went wrong during key setup.</p>
              <Button onClick={() => setStep("choose-anchor")}>Go Back</Button>
            </Card>
          )}
          {step === "dedi-setup" && importedKey && (
            <DeDiSetup
              // Prefer the canonical issuer DID computed by the self-pub
              // wizard (`did:web:<domain>` or fragment-less `did:key:z…`).
              // Falls back to `importedKey.id` only on the DSC paths,
              // where the wizard never sets `selfPubDid` — those keys are
              // DSC-backed signers, not self-published, and DeDi publish
              // there is meaningful as a "this DSC is associated with our
              // namespace" attribution rather than a did-document mirror.
              did={selfPubDid ?? importedKey.id}
              signerKeyId={importedKey.id}
              didDocument={selfPubDidDoc ?? undefined}
              domain={selfPubDomain ?? undefined}
              // For the public-directory anchor, DeDi is THE publish step, not
              // an optional mirror — surface it as such (and warn on "finish
              // later"). Website / did:key / DSC keep it optional.
              directoryAnchor={anchorMethod === "directory"}
              onBack={() =>
                // Key the Back destination off which sub-flow actually
                // produced `importedKey`, not off `selfPubFlowEntered`.
                // The latter sticks once true even if the user backs out
                // of self-pub and picks the DSC path instead, leaving
                // the hidden SelfPublishedSetup subtree mounted; we
                // don't want Back from dedi-setup to land them there
                // when they finished onboarding via DSC. `selfPubMethod`
                // is only set when SelfPublishedSetup's `onComplete` ran,
                // so it accurately reflects the completed path. It works
                // for both did:web and did:key (whereas `selfPubDomain`
                // alone would mis-route did:key users to "profile").
                setStep(selfPubMethod ? "self-pub-setup" : "profile")
              }
              onComplete={onComplete}
            />
          )}
        </div>
      </main>
    </div>
  );
}
