/**
 * App — root component for the OpenCred desktop renderer.
 *
 * On first launch (no keys imported) shows the OnboardingWizard.
 * After onboarding, displays a tabbed interface:
 *   - Issue: credential issuance form
 *   - Verify: credential verification
 *   - Batch: bulk issuance from CSV
 *   - Settings: key management and app settings
 */

import { useState, useEffect, useCallback } from "react";
import { OnboardingWizard } from "./components/OnboardingWizard";
import { IssuePage } from "./components/IssuePage";
import { VerifyPage } from "./components/VerifyPage";
import { BatchIssuance } from "./components/BatchIssuance";
import { SettingsPage } from "./components/SettingsPage";
import { UpdateNotification } from "./components/UpdateNotification";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Tab = "issue" | "verify" | "batch" | "settings";

const TABS: Array<{ id: Tab; label: string }> = [
  { id: "issue", label: "Issue" },
  { id: "verify", label: "Verify" },
  { id: "batch", label: "Batch" },
  { id: "settings", label: "Settings" },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("issue");
  const [isOffline, setIsOffline] = useState(false);
  const [showOnboarding, setShowOnboarding] = useState<boolean | null>(null);

  // ------------------------------------------------------------------
  // Check for first launch (no keys imported)
  // ------------------------------------------------------------------

  const checkFirstLaunch = useCallback(async () => {
    try {
      const response = await window.opencred.listKeys();
      setShowOnboarding(response.keys.length === 0);
    } catch {
      // If the IPC call fails, show onboarding as a safe default.
      setShowOnboarding(true);
    }
  }, []);

  const checkOfflineStatus = useCallback(async () => {
    try {
      const offline = await window.opencred.getOfflineStatus();
      setIsOffline(offline);
    } catch {
      setIsOffline(true);
    }
  }, []);

  useEffect(() => {
    void checkFirstLaunch();
    void checkOfflineStatus();

    const interval = setInterval(() => void checkOfflineStatus(), 30_000);
    return () => clearInterval(interval);
  }, [checkFirstLaunch, checkOfflineStatus]);

  // ------------------------------------------------------------------
  // Loading state
  // ------------------------------------------------------------------

  if (showOnboarding === null) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <p className="text-sm text-gray-400">Loading...</p>
      </div>
    );
  }

  // ------------------------------------------------------------------
  // Onboarding wizard
  // ------------------------------------------------------------------

  if (showOnboarding) {
    return (
      <OnboardingWizard
        onComplete={() => setShowOnboarding(false)}
      />
    );
  }

  // ------------------------------------------------------------------
  // Main tabbed interface
  // ------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      {/* Header */}
      <header className="bg-white border-b border-gray-200">
        <div className="mx-auto max-w-5xl px-4 py-3 flex items-center justify-between">
          <h1 className="text-lg font-semibold text-gray-900">OpenCred</h1>
          <div className="flex items-center gap-3">
            <span
              className={`inline-flex items-center gap-1.5 text-xs ${
                isOffline ? "text-amber-600" : "text-green-600"
              }`}
            >
              <span
                className={`h-2 w-2 rounded-full ${
                  isOffline ? "bg-amber-500" : "bg-green-500"
                }`}
                aria-hidden="true"
              />
              {isOffline ? "Offline" : "Online"}
            </span>
          </div>
        </div>
      </header>

      {/* Tab navigation */}
      <nav className="bg-white border-b border-gray-100">
        <div className="mx-auto max-w-5xl px-4">
          <div className="flex gap-1" role="tablist">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                role="tab"
                aria-selected={activeTab === tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                  activeTab === tab.id
                    ? "border-blue-600 text-blue-600"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="mx-auto max-w-5xl w-full px-4 py-6 flex-1">
        {activeTab === "issue" && <IssuePage />}
        {activeTab === "verify" && <VerifyPage />}
        {activeTab === "batch" && <BatchIssuance />}
        {activeTab === "settings" && <SettingsPage />}
      </main>

      {/* Footer */}
      <footer className="bg-white border-t border-gray-200 py-2 text-center text-xs text-gray-400">
        OpenCred Desktop v0.1.0
      </footer>

      {/* Update notification toast */}
      <UpdateNotification />
    </div>
  );
}
