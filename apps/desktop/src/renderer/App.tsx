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
import { HistoryPage } from "./components/HistoryPage";
import { UpdateNotification } from "./components/UpdateNotification";
import { ErrorBoundary } from "./components/ErrorBoundary";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type View = "home" | "builder" | "verify" | "history" | "settings";

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/** Number of days before a key is considered overdue for rotation. */
const ROTATION_THRESHOLD_DAYS = 90;

export default function App() {
  const [activeView, setActiveView] = useState<View>("home");
  const [isOffline, setIsOffline] = useState(false);
  const [showOnboarding, setShowOnboarding] = useState<boolean | null>(null);
  const [rotationOverdue, setRotationOverdue] = useState(false);

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

  const checkRotationStatus = useCallback(async () => {
    try {
      const response = await window.opencred.listKeys();
      if (response.keys.length === 0) {
        setRotationOverdue(false);
        return;
      }

      // Check if dismissed
      const dismissedUntil = await window.opencred.getConfig("keyRotationDismissedUntil") as string | undefined;
      if (dismissedUntil && new Date(dismissedUntil) > new Date()) {
        setRotationOverdue(false);
        return;
      }

      // Check if any active key is older than the threshold
      const now = Date.now();
      const thresholdMs = ROTATION_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;
      const hasOldKey = response.keys.some((key) => {
        const keyDate = new Date(key.importedAt).getTime();
        return now - keyDate > thresholdMs;
      });
      setRotationOverdue(hasOldKey);
    } catch {
      setRotationOverdue(false);
    }
  }, []);

  useEffect(() => {
    void checkFirstLaunch();
    void checkOfflineStatus();
    void checkRotationStatus();

    const interval = setInterval(() => void checkOfflineStatus(), 30_000);
    return () => clearInterval(interval);
  }, [checkFirstLaunch, checkOfflineStatus, checkRotationStatus]);

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
      <ErrorBoundary>
        <div className="min-h-screen bg-surface-bg flex items-center justify-center">
          <p className="text-body-sm text-txt-muted font-body">Loading...</p>
        </div>
      </ErrorBoundary>
    );
  }

  // ------------------------------------------------------------------
  // Onboarding wizard
  // ------------------------------------------------------------------

  if (showOnboarding) {
    return (
      <ErrorBoundary>
        <OnboardingWizard
          onComplete={() => setShowOnboarding(false)}
        />
      </ErrorBoundary>
    );
  }

  // ------------------------------------------------------------------
  // Main top-bar layout
  // ------------------------------------------------------------------

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-surface-bg flex flex-col font-body">
        {/* Top bar */}
        <TopBar
          activeView={activeView}
          isOffline={isOffline}
          rotationOverdue={rotationOverdue}
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
                onNavigate={(view) => setActiveView(view as View)}
              />
            )}
            {activeView === "verify" && <VerifyPage />}
            {activeView === "history" && (
              <HistoryPage onReissue={handleSelectTemplate} />
            )}
            {activeView === "settings" && <SettingsPage onRotationDismissed={checkRotationStatus} />}
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
    </ErrorBoundary>
  );
}
