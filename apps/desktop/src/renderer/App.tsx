/**
 * App — root component for the OpenCred desktop renderer.
 *
 * Google Docs-style layout: top bar + home screen with template cards.
 *
 * On first launch (no keys imported) shows the OnboardingWizard.
 * After onboarding, displays a top-bar-driven interface:
 *   - Home: template gallery + recent credentials (Google Docs style)
 *   - Builder: credential builder (opened from template selection)
 *   - Verify: credential verification
 *   - Settings: key management and app settings
 */

import { useState, useEffect, useCallback } from "react";
import { OnboardingWizard } from "./components/OnboardingWizard";
import { TopBar } from "./components/TopBar";
import { HomeScreen } from "./components/HomeScreen";
import { CredentialBuilderPage } from "./components/CredentialBuilderPage";
import { VerifyPage } from "./components/VerifyPage";
import { SettingsPage } from "./components/SettingsPage";
import { UpdateNotification } from "./components/UpdateNotification";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type View = "home" | "builder" | "verify" | "settings";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function App() {
  const [activeView, setActiveView] = useState<View>("home");
  const [isOffline, setIsOffline] = useState(false);
  const [showOnboarding, setShowOnboarding] = useState<boolean | null>(null);

  // Builder state — which schema was selected from the home screen
  const [builderSchemaId, setBuilderSchemaId] = useState<string>("blank");
  const [builderIsBlank, setBuilderIsBlank] = useState(true);

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
  // Navigation helpers
  // ------------------------------------------------------------------

  function handleSelectTemplate(schemaId: string, isBlank: boolean) {
    setBuilderSchemaId(schemaId);
    setBuilderIsBlank(isBlank);
    setActiveView("builder");
  }

  function handleBackToHome() {
    setActiveView("home");
  }

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
  // Main top-bar layout
  // ------------------------------------------------------------------

  return (
    <div className="min-h-screen bg-surface-bg flex flex-col font-body">
      {/* Top bar */}
      <TopBar
        activeView={activeView}
        isOffline={isOffline}
        onNavigate={setActiveView}
      />

      {/* Main content area */}
      <main className="flex-1 overflow-y-auto bg-surface-bg">
        <div className="px-7 py-6 max-w-[900px] mx-auto">
          {activeView === "home" && (
            <HomeScreen onSelectTemplate={handleSelectTemplate} />
          )}
          {activeView === "builder" && (
            <CredentialBuilderPage
              schemaId={builderSchemaId}
              isBlank={builderIsBlank}
              onBack={handleBackToHome}
            />
          )}
          {activeView === "verify" && <VerifyPage />}
          {activeView === "settings" && <SettingsPage />}
        </div>
      </main>

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
