/**
 * DeDiSetup — optional onboarding step for configuring DeDi integration.
 *
 * Internal states: choice → configure → connecting → success
 *
 * On "Yes, I have a DeDi account":
 *   1. User enters namespace + API key
 *   2. Calls dediSetConfig() → stores config + creates 3 registries
 *   3. If self-pub path, fire-and-forget dediPublishDID()
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
  didDocument?: string;
  domain?: string;
  onComplete: () => void;
}

const DEDI_BASE_URL = "https://api-production-dc6c.up.railway.app";

export function DeDiSetup({ did, didDocument, domain, onComplete }: DeDiSetupProps) {
  const [state, setState] = useState<DeDiSetupState>("choice");
  const [namespace, setNamespace] = useState(domain ?? "");
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [didPublishFailed, setDidPublishFailed] = useState(false);
  const [registriesFailed, setRegistriesFailed] = useState(false);
  const [retryingRegistries, setRetryingRegistries] = useState(false);

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
        setState("configure");
        return;
      }

      if (result.registriesReady === false) {
        setRegistriesFailed(true);
      }

      // Fire-and-forget DID publish if we have a DID document (self-pub path)
      if (didDocument) {
        try {
          const pubResult = await window.opencred.dediPublishDID({
            did,
            document: JSON.parse(didDocument),
          });
          if (!pubResult.success) {
            setDidPublishFailed(true);
          }
        } catch {
          setDidPublishFailed(true);
        }
      }

      setState("success");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to configure DeDi.");
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
              DeDi is a public directory where you can publish your DID, schemas, and
              revocation lists so verifiers can discover them.
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
              <span className="block text-[0.78rem] text-txt-muted mt-1">
                Connect your DeDi namespace to publish your DID and manage registries
              </span>
            </button>

            {/* Option 2: Not yet */}
            <button
              onClick={() => setState("not-yet")}
              className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-border-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
            >
              <span className="block text-body-sm font-semibold text-txt-primary">
                Not yet
              </span>
              <span className="block text-[0.78rem] text-txt-muted mt-1">
                Learn about DeDi and create an account
              </span>
            </button>

            {/* Option 3: Skip */}
            <button
              onClick={onComplete}
              className="w-full rounded-oc border border-border p-4 text-left transition-colors hover:border-border-light focus:outline-none focus:ring-2 focus:ring-brand-blue"
            >
              <span className="block text-body-sm font-semibold text-txt-primary">
                Skip
              </span>
              <span className="block text-[0.78rem] text-txt-muted mt-1">
                You can configure DeDi later from Settings
              </span>
            </button>
          </div>
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
              DeDi (Decentralised Directory) is a public registry service where issuers
              publish their public keys, schemas, and revocation lists.
            </p>
          </div>

          <div className="rounded-oc border border-blue-200 bg-blue-50 p-4 space-y-2">
            <p className="text-[0.78rem] font-medium text-blue-800">
              Create an account at DeDi
            </p>
            <p className="text-[0.72rem] text-blue-700">
              Visit{" "}
              <a
                href="https://publish.dedi.global"
                target="_blank"
                rel="noopener noreferrer"
                className="underline font-medium"
              >
                publish.dedi.global
              </a>{" "}
              to create your namespace and get an API key. You can configure DeDi
              in OpenCred at any time from Settings.
            </p>
          </div>

          <div className="pt-2">
            <Button onClick={onComplete}>Skip for now</Button>
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
              Enter your DeDi namespace and API key. OpenCred will create the
              required registries automatically.
            </p>
          </div>

          <div className="space-y-3">
            <div>
              <label className="oc-label block mb-1">Namespace</label>
              <input
                type="text"
                value={namespace}
                onChange={(e) => { setNamespace(e.target.value); setError(null); }}
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
                onChange={(e) => { setApiKey(e.target.value); setError(null); }}
                placeholder="Enter your DeDi API key"
                disabled={state === "connecting"}
                className="w-full rounded-oc border border-border px-3 py-2 text-body-sm text-txt-primary placeholder:text-txt-muted focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue disabled:opacity-50"
              />
            </div>
          </div>

          {error && (
            <p className="text-sm text-red-600">{error}</p>
          )}

          <div className="pt-2 flex gap-3">
            <Button
              onClick={() => void handleConnect()}
              disabled={state === "connecting"}
            >
              {state === "connecting" ? "Connecting..." : "Connect to DeDi"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => { setState("choice"); setError(null); }}
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

          <div className="rounded-oc border border-green-200 bg-green-50 p-4 space-y-2">
            <h3 className="oc-card-label" style={{ color: "#2e7d32" }}>Configuration</h3>
            <dl className="text-[0.78rem] text-green-700 space-y-1.5">
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
                  <dd className="font-mono text-[0.72rem] break-all">
                    {didPublishFailed ? "Publish pending" : "Published"}
                  </dd>
                </div>
              )}
            </dl>
          </div>

          {registriesFailed && (
            <div className="rounded-oc border border-amber-200 bg-amber-50 p-3 space-y-2">
              <p className="text-[0.78rem] text-amber-800 font-medium">
                Registries could not be created
              </p>
              <p className="text-[0.72rem] text-amber-700">
                Config saved but registries could not be created. Check your API key
                and network connection.
              </p>
              <button
                onClick={() => void handleRetryRegistries()}
                disabled={retryingRegistries}
                className="text-[0.78rem] font-medium text-amber-800 underline hover:text-amber-900 disabled:opacity-50"
              >
                {retryingRegistries ? "Retrying..." : "Retry"}
              </button>
            </div>
          )}

          {didPublishFailed && (
            <div className="rounded-oc border border-amber-200 bg-amber-50 p-3">
              <p className="text-[0.78rem] text-amber-800 font-medium">
                DID could not be published
              </p>
              <p className="text-[0.72rem] text-amber-700">
                Your DeDi configuration was saved, but the DID document could not be
                published. You can retry from Settings.
              </p>
            </div>
          )}

          <div className="pt-2">
            <Button onClick={onComplete}>Continue to OpenCred</Button>
          </div>
        </Card>
      )}
    </>
  );
}
