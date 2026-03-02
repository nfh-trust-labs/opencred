import { useState, useEffect, useCallback } from "react";
import { Navigation } from "./components/Navigation";
import { OfflineIndicator } from "./components/OfflineIndicator";
import { CredentialBuilder } from "./components/CredentialBuilder";
import { CredentialVerifier } from "./components/CredentialVerifier";
import { KeyManagement } from "./components/KeyManagement";
import { BatchIssuance } from "./components/BatchIssuance";
import { DelegatedIssuance } from "./components/DelegatedIssuance";

export type Tab = "builder" | "verifier" | "keys" | "batch" | "delegated";

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("builder");
  const [isOffline, setIsOffline] = useState(false);

  const checkOfflineStatus = useCallback(async () => {
    try {
      const offline = await window.opencred.getOfflineStatus();
      setIsOffline(offline);
    } catch {
      // If the IPC call itself fails, assume offline.
      setIsOffline(true);
    }
  }, []);

  useEffect(() => {
    void checkOfflineStatus();

    // Re-check connectivity periodically.
    const interval = setInterval(() => void checkOfflineStatus(), 30_000);
    return () => clearInterval(interval);
  }, [checkOfflineStatus]);

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Title bar area */}
      <header className="bg-white border-b border-gray-200">
        <div className="mx-auto max-w-5xl px-4 py-3 flex items-center justify-between">
          <h1 className="text-lg font-semibold text-gray-900">OpenCred Desktop</h1>
          <OfflineIndicator isOffline={isOffline} />
        </div>
      </header>

      {/* Navigation */}
      <nav className="mx-auto max-w-5xl w-full px-4 mt-4">
        <Navigation activeTab={activeTab} onChange={setActiveTab} />
      </nav>

      {/* Main content */}
      <main className="mx-auto max-w-5xl w-full px-4 py-6 flex-1">
        {activeTab === "builder" && <CredentialBuilder />}
        {activeTab === "verifier" && <CredentialVerifier />}
        {activeTab === "keys" && <KeyManagement />}
        {activeTab === "batch" && <BatchIssuance />}
        {activeTab === "delegated" && <DelegatedIssuance />}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 py-2 text-center text-xs text-gray-400">
        OpenCred Desktop v0.1.0
      </footer>
    </div>
  );
}
