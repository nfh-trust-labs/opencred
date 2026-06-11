/**
 * DeDiSetup — optional onboarding step for configuring DeDi integration.
 *
 * Internal states: choice → configure → connecting → success
 *
 * On "Yes, I have a DeDi account":
 *   1. User enters namespace + API key
 *   2. Calls dediSetConfig() → stores config + creates 3 registries
 *   3. If self-pub path, fire-and-forget dediPublishKey()
 *   4. Shows success screen
 *
 * SECURITY NOTE: API key input uses type="password" and is never logged.
 * The API key is encrypted via safeStorage in the main process.
 */

import { useState } from "react";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";

type DeDiSetupState = "choice" | "not-yet" | "configure" | "connecting" | "success";

interface DeDiSetupProps {
  did: string;
  /**
   * The local in-memory signer id whose public key should be published to
   * DeDi. Used to resolve the public JWK + algorithm in the main process —
   * private key material never crosses the IPC boundary.
   */
  signerKeyId: string;
  didDocument?: string;
  domain?: string;
  onComplete: () => void;
  /**
   * Optional callback for the initial step's Back button — returns the
   * user to the prior wizard step (profile for the DSC path, or
   * self-pub-setup for the self-pub path) when they want to revisit an
   * earlier decision. Issue #547.
   */
  onBack?: () => void;
}

const DEDI_BASE_URL = "https://api.dedi.global";

export function DeDiSetup({
  did,
  signerKeyId,
  didDocument,
  domain,
  onComplete,
  onBack,
}: DeDiSetupProps) {
  const [state, setState] = useState<DeDiSetupState>("choice");
  const [namespace, setNamespace] = useState(domain ?? "");
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [didPublishFailed, setDidPublishFailed] = useState(false);
  const [registriesFailed, setRegistriesFailed] = useState(false);
  const [retryingRegistries, setRetryingRegistries] = useState(false);
  // Tracks the (namespace, apiKey) tuple that just failed. Used to gate
  // Connect-on-error: the IPC handler is *not* idempotent on the DeDi side
  // (every POST without an Idempotency-Key risks creating a duplicate
  // namespace), so we disable the button until the user edits a field
  // and explicitly retries with a different input. See issue #546.
  const [lastFailedKey, setLastFailedKey] = useState<string | null>(null);

  const currentKey = `${namespace.trim()}::${apiKey}`;
  const isResubmitOfFailedAttempt =
    lastFailedKey !== null && lastFailedKey === currentKey && error !== null;

  async function handleConnect() {
    if (!namespace.trim()) {
      setError("Please enter a namespace.");
      return;
    }
    if (!apiKey) {
      setError("Please enter your API key.");
      return;
    }

    setError(null);
    setState("connecting");

    try {
      const result = await window.opencred.dediSetConfig({
        baseUrl: DEDI_BASE_URL,
        namespace: namespace.trim(),
        credentials: { type: "api-key", apiKey },
      });

      if (!result.success) {
        setError(result.error ?? "Failed to configure DeDi.");
        setLastFailedKey(currentKey);
        setState("configure");
        return;
      }

      if (result.registriesReady === false) {
        setRegistriesFailed(true);
      }

      // Fire-and-forget key publish if we have a DID document (self-pub path).
      // Also stores the did:web document in DeDi via hostDidDocument.
      if (didDocument) {
        try {
          const pubResult = await window.opencred.dediPublishKey({
            signerKeyId,
            did,
            document: JSON.parse(didDocument),
            hostDidDocument: true,
          });
          // didDocumentStored === false means the key record made it into
          // the registry but the hosted did.json refresh failed — verifiers
          // resolving via DeDi would see a stale key set. Surface it the
          // same way as a failed publish so the user retries.
          if (!pubResult.success || pubResult.didDocumentStored === false) {
            setDidPublishFailed(true);
          }
        } catch {
          setDidPublishFailed(true);
        }
      }

      setState("success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to configure DeDi.");
      setLastFailedKey(currentKey);
      setState("configure");
    }
  }

  async function handleRetryRegistries() {
    setRetryingRegistries(true);
    try {
      const result = await window.opencred.dediEnsureRegistries();
      if (result.success) {
        setRegistriesFailed(false);
      }
    } catch {
      // Keep registriesFailed true
    } finally {
      setRetryingRegistries(false);
    }
  }

  return (
    <>
      {/* ================================================================
          Choice: 3 options
          ================================================================ */}
      {state === "choice" && (
        <Card variant="neutral" className="space-y-6">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              Public Directory
            </h2>
            <p className="text-body-sm text-txt-secondary">
              DeDi is a public directory where you can publish your DID, schemas, and revocation
              lists so verifiers can discover them.
            </p>
          </div>

          <div className="space-y-3">
            {/* Option 1: Yes */}
            <button
              onClick={() => setState("configure")}
              className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-brand-blue hover:bg-brand-blue-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
            >
              <span className="block text-body-sm font-semibold text-txt-primary">
                Yes, I have a DeDi account
              </span>
              <span className="block text-body-xs text-txt-muted mt-1">
                Connect your DeDi namespace to publish your DID and manage registries
              </span>
            </button>

            {/* Option 2: Not yet */}
            <button
              onClick={() => setState("not-yet")}
              className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-border-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
            >
              <span className="block text-body-sm font-semibold text-txt-primary">Not yet</span>
              <span className="block text-body-xs text-txt-muted mt-1">
                Learn about DeDi and create an account
              </span>
            </button>

            {/* Option 3: Skip */}
            <button
              onClick={onComplete}
              className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-border-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
            >
              <span className="block text-body-sm font-semibold text-txt-primary">Skip</span>
              <span className="block text-body-xs text-txt-muted mt-1">
                You can configure DeDi later from Settings
              </span>
            </button>
          </div>

          {onBack && (
            <div className="pt-2">
              <Button variant="secondary" onClick={onBack}>
                Back
              </Button>
            </div>
          )}
        </Card>
      )}

      {/* ================================================================
          Not Yet: Info card
          ================================================================ */}
      {state === "not-yet" && (
        <Card variant="neutral" className="space-y-6">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              About DeDi
            </h2>
            <p className="text-body-sm text-txt-secondary">
              DeDi (Decentralised Directory) is a public registry service where issuers publish
              their public keys, schemas, and revocation lists.
            </p>
          </div>

          <div className="rounded-oc border border-blue-200 bg-brand-light p-4 space-y-2">
            <p className="text-body-xs font-medium text-brand">Create an account at DeDi</p>
            <p className="text-body-2xs text-brand">
              Visit{" "}
              <a
                href="https://publish.dedi.global"
                target="_blank"
                rel="noopener noreferrer"
                className="underline font-medium"
              >
                publish.dedi.global
              </a>{" "}
              to create your namespace and get an API key. You can configure DeDi in OpenCred at any
              time from Settings.
            </p>
          </div>

          <div className="pt-2 flex gap-3">
            <Button onClick={onComplete}>Skip for now</Button>
            <Button variant="secondary" onClick={() => setState("choice")}>
              Back
            </Button>
          </div>
        </Card>
      )}

      {/* ================================================================
          Configure: namespace + API key form
          ================================================================ */}
      {(state === "configure" || state === "connecting") && (
        <Card className="space-y-5">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              Connect to DeDi
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Enter your DeDi namespace and API key. OpenCred will create the required registries
              automatically.
            </p>
          </div>

          <div className="space-y-3">
            <div>
              <label className="oc-label block mb-1">Namespace</label>
              <input
                type="text"
                value={namespace}
                onChange={(e) => {
                  setNamespace(e.target.value);
                  setError(null);
                  setLastFailedKey(null);
                }}
                placeholder="your-domain.example"
                disabled={state === "connecting"}
                className="w-full rounded-oc border border-border px-3 py-2 text-body-sm text-txt-primary placeholder:text-txt-muted focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue disabled:opacity-50"
              />
            </div>

            <div>
              <label className="oc-label block mb-1">API Key</label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => {
                  setApiKey(e.target.value);
                  setError(null);
                  setLastFailedKey(null);
                }}
                placeholder="Enter your DeDi API key"
                disabled={state === "connecting"}
                className="w-full rounded-oc border border-border px-3 py-2 text-body-sm text-txt-primary placeholder:text-txt-muted focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue disabled:opacity-50"
              />
            </div>
          </div>

          {error && (
            <div className="space-y-1">
              <p className="text-sm text-state-danger">{error}</p>
              {isResubmitOfFailedAttempt && (
                <p className="text-body-2xs text-txt-muted">
                  Edit the namespace or API key and try again. Re-submitting the same values could
                  create a duplicate namespace on DeDi.
                </p>
              )}
            </div>
          )}

          <div className="pt-2 flex gap-3">
            <Button
              onClick={() => void handleConnect()}
              disabled={state === "connecting" || isResubmitOfFailedAttempt}
            >
              {state === "connecting" ? "Connecting..." : "Connect to DeDi"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setState("choice");
                setError(null);
              }}
              disabled={state === "connecting"}
            >
              Back
            </Button>
          </div>
        </Card>
      )}

      {/* ================================================================
          Success
          ================================================================ */}
      {state === "success" && (
        <Card className="space-y-6">
          <div className="space-y-2">
            <h2 className="oc-page-title" style={{ marginBottom: 0 }}>
              DeDi Connected
            </h2>
            <p className="text-body-sm text-txt-secondary">
              Your DeDi integration is configured and ready to use.
            </p>
          </div>

          <div className="rounded-oc border border-state-success-border bg-state-success-bg p-4 space-y-2">
            <h3 className="oc-card-label" style={{ color: "#2e7d32" }}>
              Configuration
            </h3>
            <dl className="text-body-xs text-state-success space-y-1.5">
              <div className="flex gap-2">
                <dt className="font-medium w-28 flex-shrink-0">Namespace:</dt>
                <dd>{namespace.trim()}</dd>
              </div>
              {!registriesFailed && (
                <div className="flex gap-2">
                  <dt className="font-medium w-28 flex-shrink-0">Registries:</dt>
                  <dd>3 registries created</dd>
                </div>
              )}
              {didDocument && (
                <div className="flex gap-2">
                  <dt className="font-medium w-28 flex-shrink-0">DID:</dt>
                  <dd className="font-mono text-body-2xs break-all">
                    {didPublishFailed ? "Publish pending" : "Published"}
                  </dd>
                </div>
              )}
            </dl>
          </div>

          {registriesFailed && (
            <div className="rounded-oc border border-state-warning-border bg-state-warning-bg p-3 space-y-2">
              <p className="text-body-xs text-state-warning font-medium">
                Registries could not be created
              </p>
              <p className="text-body-2xs text-state-warning">
                Config saved but registries could not be created. Check your API key and network
                connection.
              </p>
              <button
                onClick={() => void handleRetryRegistries()}
                disabled={retryingRegistries}
                className="text-body-xs font-medium text-state-warning underline hover:text-amber-900 disabled:opacity-50"
              >
                {retryingRegistries ? "Retrying..." : "Retry"}
              </button>
            </div>
          )}

          {didPublishFailed && (
            <div className="rounded-oc border border-state-warning-border bg-state-warning-bg p-3">
              <p className="text-body-xs text-state-warning font-medium">
                DID could not be published
              </p>
              <p className="text-body-2xs text-state-warning">
                Your DeDi configuration was saved, but the DID document could not be published. You
                can retry from Settings.
              </p>
            </div>
          )}

          <div className="pt-2">
            <Button onClick={onComplete}>Start Issuing Credentials</Button>
          </div>
        </Card>
      )}
    </>
  );
}
