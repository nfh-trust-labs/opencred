/**
 * TopBar — horizontal navigation bar replacing the sidebar.
 *
 * Left: Back arrow (when not on home) + OpenCred logo (click → home).
 * Right: Verify button, Settings button, online/offline status dot.
 */

import type { View } from "../App";

interface Props {
  activeView: View;
  isOffline: boolean;
  rotationOverdue?: boolean;
  onNavigate: (view: View) => void;
}

export function TopBar({ activeView, isOffline, rotationOverdue, onNavigate }: Props) {
  const showBack = activeView !== "home";

  return (
    <div className="oc-topbar">
      {/* Left: Back + Logo */}
      <div className="oc-topbar-actions">
        {showBack && (
          <button
            onClick={() => onNavigate("home")}
            className="oc-topbar-nav-btn"
            aria-label="Back to home"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
            </svg>
            Home
          </button>
        )}
        <button
          onClick={() => onNavigate("home")}
          className="oc-topbar-logo"
          aria-label="Go to home"
        >
          OpenCred
        </button>
      </div>

      {/* Spacer (drag region) */}
      <div className="oc-topbar-drag" />

      {/* Right: nav buttons */}
      <div className="oc-topbar-actions">
        <button
          onClick={() => onNavigate("verify")}
          className={`oc-topbar-nav-btn ${activeView === "verify" ? "active" : ""}`}
          aria-label="Verify credential"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
          </svg>
          Verify
        </button>

        <button
          onClick={() => onNavigate("settings")}
          className={`oc-topbar-nav-btn ${activeView === "settings" ? "active" : ""}`}
          aria-label="Settings"
          style={{ position: "relative" }}
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 010 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 010-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28z" />
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
          </svg>
          Settings
          {rotationOverdue && (
            <span
              style={{
                position: "absolute",
                top: 2,
                right: 2,
                width: 7,
                height: 7,
                borderRadius: "50%",
                backgroundColor: "#f59e0b",
              }}
              aria-label="Key rotation overdue"
            />
          )}
        </button>

        {/* Status dot */}
        <span
          className={`h-1.5 w-1.5 rounded-full flex-shrink-0 ml-1 ${
            isOffline ? "bg-amber-500" : "bg-green-500"
          }`}
          title={isOffline ? "Offline" : "Connected"}
          aria-hidden="true"
        />
      </div>
    </div>
  );
}
