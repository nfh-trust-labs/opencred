import { useState, useEffect } from "react";
import { detectExtension } from "./crypto/extension-client";
import { CredentialBuilder } from "./components/CredentialBuilder";
import { CredentialVerifier } from "./components/CredentialVerifier";
import { DelegatedIssuance } from "./components/DelegatedIssuance";
import { BatchIssuance } from "./components/BatchIssuance";
import { RevocationPage } from "./components/RevocationPage";
import { OnboardingPage } from "./components/OnboardingPage";
import { Navigation } from "./components/Navigation";

type Tab = "builder" | "delegated" | "batch" | "verifier" | "revocation" | "onboarding";

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("builder");
  const [apiUrl, setApiUrl] = useState("/api");
  const [token, setToken] = useState("");
  const [showSettings, setShowSettings] = useState(false);
  const [extensionAvailable, setExtensionAvailable] = useState(false);

  useEffect(() => {
    detectExtension().then((result) => {
      setExtensionAvailable(result.available);
    });
  }, []);

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white border-b border-gray-200">
        <div className="mx-auto max-w-4xl px-4 py-4 flex items-center justify-between">
          <h1 className="text-xl font-semibold text-gray-900">OpenCred</h1>
          <button
            type="button"
            onClick={() => setShowSettings(!showSettings)}
            className="text-sm text-gray-500 hover:text-gray-700"
          >
            Settings
          </button>
        </div>
        {showSettings && (
          <div className="mx-auto max-w-4xl px-4 pb-4 space-y-2">
            <div>
              <label htmlFor="api-url" className="block text-xs font-medium text-gray-600">
                API Base URL
              </label>
              <input
                id="api-url"
                type="text"
                value={apiUrl}
                onChange={(e) => setApiUrl(e.target.value)}
                className="mt-1 block w-full rounded border border-gray-300 px-2 py-1 text-sm"
              />
            </div>
            <div>
              <label htmlFor="api-token" className="block text-xs font-medium text-gray-600">
                Bearer Token
              </label>
              <input
                id="api-token"
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="Optional — required if API auth is enabled"
                className="mt-1 block w-full rounded border border-gray-300 px-2 py-1 text-sm"
              />
            </div>
          </div>
        )}
      </header>

      <nav className="mx-auto max-w-4xl px-4 mt-6">
        <Navigation activeTab={activeTab} onChange={(tab) => setActiveTab(tab as Tab)} />
      </nav>

      <main className="mx-auto max-w-4xl px-4 py-6">
        {activeTab === "builder" && <CredentialBuilder apiUrl={apiUrl} token={token} extensionAvailable={extensionAvailable} />}
        {activeTab === "delegated" && <DelegatedIssuance apiUrl={apiUrl} token={token} />}
        {activeTab === "batch" && <BatchIssuance apiUrl={apiUrl} token={token} />}
        {activeTab === "verifier" && <CredentialVerifier apiUrl={apiUrl} token={token} />}
        {activeTab === "revocation" && <RevocationPage apiUrl={apiUrl} token={token} />}
        {activeTab === "onboarding" && <OnboardingPage apiUrl={apiUrl} token={token} />}
      </main>
    </div>
  );
}
