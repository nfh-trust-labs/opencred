/**
 * App — root component for the OpenCred desktop renderer.
 *
 * Editorial Refined layout: sidebar navigation + content area.
 *
 * On first launch (no keys imported) shows the OnboardingWizard.
 * After onboarding, displays a sidebar-driven interface:
 *   - Issue: credential issuance form
 *   - Verify: credential verification
 *   - Batch: bulk issuance from CSV
 *   - Settings: key management and app settings
 */

import { useState, useEffect, useCallback } from "react";
import { OnboardingWizard } from "./components/OnboardingWizard";
import { Navigation } from "./components/Navigation";
import { IssuePage } from "./components/IssuePage";
import { VerifyPage } from "./components/VerifyPage";
import { BatchIssuance } from "./components/BatchIssuance";
import { SettingsPage } from "./components/SettingsPage";
import { UpdateNotification } from "./components/UpdateNotification";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type Tab = "issue" | "verify" | "batch" | "settings";

const PAGE_META: Record<Tab, { eyebrow: string; title: string; subtitle: string }> = {
  issue: {
    eyebrow: "Credential Issuance",
    title: "Issue Credential",
    subtitle: "Create and sign a new verifiable credential locally",
  },
  verify: {
    eyebrow: "Verification",
    title: "Verify Credential",
    subtitle: "Validate the authenticity and integrity of a verifiable credential",
  },
  batch: {
    eyebrow: "Bulk Operations",
    title: "Batch Issuance",
    subtitle: "Issue multiple credentials from a CSV data source",
  },
  settings: {
    eyebrow: "Management",
    title: "Settings",
    subtitle: "Manage signing keys, attestations, and application preferences",
  },
};

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
      <div className="min-h-screen bg-surface-bg flex items-center justify-center">
        <p className="text-body-sm text-txt-muted font-body">Loading...</p>
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
  // Main sidebar layout
  // ------------------------------------------------------------------

  const meta = PAGE_META[activeTab];

  return (
    <div className="min-h-screen bg-surface-bg flex flex-col font-body">
      {/* Titlebar */}
      <div className="oc-titlebar">
        <span style={{ flex: 1, textAlign: "center" }}>OpenCred</span>
      </div>

      {/* Sidebar + Content */}
      <div className="flex flex-1 min-h-0">
        {/* Sidebar navigation */}
        <Navigation activeTab={activeTab} onChange={setActiveTab} />

        {/* Main content area */}
        <main className="flex-1 overflow-y-auto bg-surface-bg">
          <div className="px-7 py-6 max-w-[900px]">
            {/* Page header — editorial typography */}
            <div className="oc-page-eyebrow">{meta.eyebrow}</div>
            <h1 className="oc-page-title">{meta.title}</h1>
            <p className="oc-page-subtitle">{meta.subtitle}</p>

            {/* Page content */}
            {activeTab === "issue" && <IssuePage />}
            {activeTab === "verify" && <VerifyPage />}
            {activeTab === "batch" && <BatchIssuance />}
            {activeTab === "settings" && <SettingsPage />}
          </div>
        </main>
      </div>

      {/* Status bar */}
      <div className="oc-status-bar">
        <span
          className={`h-1.5 w-1.5 rounded-full ${
            isOffline ? "bg-amber-500" : "bg-green-500"
          }`}
          aria-hidden="true"
        />
        {isOffline ? "Offline" : "Connected"}

        {/* Update notification toast */}
        <UpdateNotification />
      </div>
    </div>
  );
}
