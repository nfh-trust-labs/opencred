/**
 * BugReportDialog — modal for collecting system info + logs for bug reports.
 *
 * Shows system info (auto-filled), recent logs (with privacy warning),
 * and provides buttons to copy a formatted report and open the bug report form.
 */

import { useState, useEffect, useCallback } from "react";
import type { SystemInfoResponse } from "../../shared/ipc-types";

interface BugReportDialogProps {
  open: boolean;
  onClose: () => void;
}

export function BugReportDialog({ open, onClose }: BugReportDialogProps) {
  const [systemInfo, setSystemInfo] = useState<SystemInfoResponse | null>(null);
  const [logs, setLogs] = useState("");
  const [logPath, setLogPath] = useState("");
  const [formUrl, setFormUrl] = useState("https://forms.gle/f1wFUhzN1VwgR5QD6");
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [info, logResult, storedUrl] = await Promise.all([
        window.opencred.getSystemInfo(),
        window.opencred.getRecentLogs(100),
        window.opencred.getConfig("bugReportFormUrl") as Promise<string | undefined>,
      ]);
      setSystemInfo(info);
      setLogs(logResult.logs);
      setLogPath(logResult.logPath);
      if (storedUrl) setFormUrl(storedUrl);
    } catch {
      setSystemInfo(null);
      setLogs("Failed to load logs.");
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    if (open) {
      void loadData();
      setCopied(false);
    }
  }, [open, loadData]);

  if (!open) return null;

  const formattedReport = systemInfo
    ? [
        "## System Information",
        `- **App Version:** ${systemInfo.appVersion}`,
        `- **Electron:** ${systemInfo.electronVersion}`,
        `- **Node.js:** ${systemInfo.nodeVersion}`,
        `- **OS:** ${systemInfo.os} ${systemInfo.osVersion} (${systemInfo.arch})`,
        `- **Log Path:** ${systemInfo.logPath}`,
        "",
        "## Recent Logs",
        "```",
        logs,
        "```",
      ].join("\n")
    : "";

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(formattedReport);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API may fail
    }
  }

  function handleOpenForm() {
    // Open the bug report form — URL is configurable via store
    window.open(formUrl, "_blank");
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-lg shadow-xl w-[600px] max-h-[80vh] flex flex-col border border-border-default">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-border-default">
          <h2 className="text-heading-sm font-heading text-txt-primary">
            Report a Bug
          </h2>
          <button
            onClick={onClose}
            className="text-txt-muted hover:text-txt-primary p-1 rounded transition-colors"
            aria-label="Close"
          >
            <svg className="w-5 h-5" viewBox="0 0 20 20" fill="currentColor">
              <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-4 space-y-4">
          {loading ? (
            <p className="text-body-sm text-txt-muted">Loading system info...</p>
          ) : (
            <>
              {/* System info */}
              <div>
                <h3 className="text-xs font-medium text-gray-600 uppercase tracking-wide mb-2">
                  System Information
                </h3>
                {systemInfo && (
                  <div className="bg-gray-50 border border-gray-200 rounded p-3 text-xs font-mono space-y-1">
                    <p>App: OpenCred v{systemInfo.appVersion}</p>
                    <p>Electron: {systemInfo.electronVersion}</p>
                    <p>Node.js: {systemInfo.nodeVersion}</p>
                    <p>OS: {systemInfo.os} {systemInfo.osVersion} ({systemInfo.arch})</p>
                  </div>
                )}
              </div>

              {/* Log preview */}
              <div>
                <h3 className="text-xs font-medium text-gray-600 uppercase tracking-wide mb-2">
                  Recent Logs
                </h3>
                <div className="bg-amber-50 border border-amber-200 rounded px-3 py-2 mb-2">
                  <p className="text-xs text-amber-800">
                    Review these logs for sensitive information before sharing.
                    Logs are from: <span className="font-mono">{logPath}</span>
                  </p>
                </div>
                <pre className="bg-gray-50 border border-gray-200 rounded p-3 text-[11px] font-mono overflow-auto max-h-48 whitespace-pre-wrap text-gray-700">
                  {logs || "(no logs available)"}
                </pre>
              </div>
            </>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-5 py-4 border-t border-border-default">
          <button
            onClick={() => void handleCopy()}
            disabled={loading}
            className="px-4 py-2 text-sm font-medium text-txt-primary bg-surface-card border border-border-default rounded hover:bg-gray-100 transition-colors disabled:opacity-50"
          >
            {copied ? "Copied!" : "Copy Report to Clipboard"}
          </button>
          <button
            onClick={handleOpenForm}
            disabled={loading}
            className="px-4 py-2 text-sm font-medium text-white bg-brand-blue rounded hover:bg-brand-blue/90 transition-colors disabled:opacity-50"
          >
            Open Report Form
          </button>
        </div>
      </div>
    </div>
  );
}
