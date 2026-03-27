/**
 * HistoryPage — compact table of issued credentials with detail modal.
 * Moved from HomeScreen to keep the home page focused on templates.
 */

import { useState, useEffect, useCallback } from "react";
import { getVisual } from "./ui/TemplateCard";
import { Button } from "./ui/Button";

interface HistoryEntry {
  id: string;
  schemaId: string;
  schemaName: string;
  subjectSummary: string;
  issuedAt: string;
  credentialJson: string;
  keyFingerprint: string;
}

interface Props {
  onReissue: (schemaId: string, isBlank: boolean) => void;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function truncateDid(did: string): string {
  if (did.length <= 32) return did;
  const parts = did.split(":");
  if (parts.length >= 3) {
    const method = parts.slice(0, 2).join(":");
    const id = parts.slice(2).join(":");
    return `${method}:${id.slice(0, 8)}...${id.slice(-8)}`;
  }
  return `${did.slice(0, 16)}...${did.slice(-8)}`;
}

function formatDateLong(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("en-US", { year: "numeric", month: "long", day: "numeric" });
  } catch { return iso; }
}

function formatDateShort(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
  } catch { return iso; }
}

function labelForField(name: string): string {
  return name.replace(/([a-z])([A-Z])/g, "$1 $2").replace(/^./, (c) => c.toUpperCase());
}

// ---------------------------------------------------------------------------
// Detail Modal
// ---------------------------------------------------------------------------

function CredentialDetailModal({
  entry, onClose, onDelete, onReissue,
}: {
  entry: HistoryEntry;
  onClose: () => void;
  onDelete: () => void;
  onReissue: () => void;
}) {
  const v = getVisual(entry.schemaId);
  let vc: Record<string, unknown>;
  try { vc = JSON.parse(entry.credentialJson) as Record<string, unknown>; } catch { vc = {}; }
  const subject = (vc.credentialSubject ?? {}) as Record<string, unknown>;
  const subjectEntries = Object.entries(subject).filter(([key, value]) => key !== "id" && typeof value !== "object");
  const issuer = typeof vc.issuer === "string" ? vc.issuer : (vc.issuer as Record<string, unknown>)?.id ?? "Unknown";
  const proofType = (vc.proof as Record<string, unknown>)?.type ?? null;
  const issuanceDate = (vc.issuanceDate ?? vc.validFrom ?? "") as string;
  const expirationDate = (vc.expirationDate ?? vc.validUntil ?? null) as string | null;

  async function handleExportJson() {
    try {
      await window.opencred.saveFile({
        defaultName: `credential-${entry.schemaId}.json`,
        content: JSON.stringify(JSON.parse(entry.credentialJson), null, 2),
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
    } catch { /* User cancelled */ }
  }

  return (
    <div
      style={{ position: "fixed", inset: 0, zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center", backgroundColor: "rgba(0,0,0,0.4)", backdropFilter: "blur(4px)" }}
      onClick={onClose}
    >
      <div
        style={{ width: "100%", maxWidth: 520, maxHeight: "85vh", overflow: "auto", borderRadius: 14, backgroundColor: "var(--oc-surface)", boxShadow: `0 24px 64px -12px ${v.fg}30, 0 8px 24px rgba(0,0,0,0.12)` }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ background: `linear-gradient(135deg, ${v.fg}, ${v.border})`, padding: "28px 28px 24px", position: "relative" }}>
          <button onClick={onClose} style={{ position: "absolute", top: 14, right: 14, width: 28, height: 28, borderRadius: 8, border: "none", background: "rgba(255,255,255,0.15)", color: "#fff", cursor: "pointer", display: "flex", alignItems: "center", justifyContent: "center" }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
          </button>
          <div style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.56rem", letterSpacing: "0.12em", textTransform: "uppercase", color: "rgba(255,255,255,0.6)", marginBottom: 4 }}>{entry.schemaName}</div>
          <h3 style={{ fontFamily: "var(--oc-font-display)", fontSize: "1.35rem", color: "#fff", margin: 0, fontWeight: 400 }}>{entry.subjectSummary}</h3>
        </div>

        {/* Subject fields */}
        {subjectEntries.length > 0 && (
          <div style={{ padding: "22px 28px 16px" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px 28px" }}>
              {subjectEntries.map(([key, value]) => (
                <div key={key}>
                  <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.56rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)" }}>{labelForField(key)}</dt>
                  <dd style={{ fontFamily: "var(--oc-font-body)", fontSize: "0.88rem", fontWeight: 500, color: "var(--oc-text-primary)", margin: 0, marginTop: 3 }}>{String(value)}</dd>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Metadata */}
        <div style={{ padding: "14px 28px", borderTop: "1px solid var(--oc-border-light)", backgroundColor: "var(--oc-bg)" }}>
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px 28px" }}>
            <div>
              <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.54rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)" }}>Issuer</dt>
              <dd style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.7rem", color: "var(--oc-text-secondary)", margin: 0, marginTop: 2 }} title={String(issuer)}>{truncateDid(String(issuer))}</dd>
            </div>
            {proofType && (
              <div>
                <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.54rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)" }}>Proof</dt>
                <dd style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.7rem", color: "var(--oc-text-secondary)", margin: 0, marginTop: 2 }}>{String(proofType)}</dd>
              </div>
            )}
            <div>
              <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.54rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)" }}>Issued</dt>
              <dd style={{ fontFamily: "var(--oc-font-body)", fontSize: "0.78rem", color: "var(--oc-text-primary)", margin: 0, marginTop: 2 }}>{formatDateLong(issuanceDate)}</dd>
            </div>
            {expirationDate && (
              <div>
                <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.54rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)" }}>Expires</dt>
                <dd style={{ fontFamily: "var(--oc-font-body)", fontSize: "0.78rem", color: "var(--oc-text-primary)", margin: 0, marginTop: 2 }}>{formatDateLong(expirationDate)}</dd>
              </div>
            )}
          </div>
        </div>

        {/* Export */}
        <div style={{ padding: "16px 28px", borderTop: "1px solid var(--oc-border-light)", display: "flex", flexWrap: "wrap", gap: 8 }}>
          <Button variant="secondary" size="sm" onClick={() => void handleExportJson()}>Download JSON</Button>
        </div>

        {/* Bottom actions */}
        <div style={{ padding: "14px 28px", borderTop: "1px solid var(--oc-border-light)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <button
            onClick={onDelete}
            style={{ fontFamily: "var(--oc-font-body)", fontSize: "0.72rem", color: "var(--oc-text-muted)", background: "none", border: "none", cursor: "pointer", padding: "4px 8px", borderRadius: 4 }}
            onMouseEnter={(e) => { e.currentTarget.style.color = "#DC2626"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--oc-text-muted)"; }}
          >
            Remove from history
          </button>
          <Button size="sm" onClick={onReissue}>Reissue</Button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function HistoryPage({ onReissue }: Props) {
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewingEntry, setViewingEntry] = useState<HistoryEntry | null>(null);

  const loadData = useCallback(async () => {
    try {
      const res = await window.opencred.credentialHistoryList();
      setHistory(res.entries);
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { void loadData(); }, [loadData]);

  async function handleDelete(id: string) {
    try {
      await window.opencred.credentialHistoryDelete({ id });
      setHistory((prev) => prev.filter((e) => e.id !== id));
      setViewingEntry(null);
    } catch { /* ignore */ }
  }

  function handleReissue(entry: HistoryEntry) {
    onReissue(entry.schemaId, entry.schemaId === "blank");
  }

  if (loading) return <p className="text-sm text-gray-400">Loading...</p>;

  return (
    <div>
      <h2 className="oc-page-title" style={{ marginBottom: "16px" }}>Credential History</h2>

      {history.length === 0 ? (
        <p className="text-sm text-gray-400 italic">No credentials issued yet.</p>
      ) : (
        <div style={{ borderRadius: 10, border: "1px solid var(--oc-border)", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "var(--oc-font-body)", fontSize: "0.82rem" }}>
            <thead>
              <tr style={{ backgroundColor: "var(--oc-bg)", borderBottom: "1px solid var(--oc-border)" }}>
                {["Type", "Subject", "Issued", ""].map((h) => (
                  <th key={h} style={{ padding: "10px 16px", textAlign: h ? "left" : "right", fontFamily: "var(--oc-font-mono)", fontSize: "0.6rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)", fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.map((entry) => (
                <tr
                  key={entry.id}
                  style={{ borderBottom: "1px solid var(--oc-border-light)", cursor: "pointer", transition: "background-color 0.1s" }}
                  onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "var(--oc-bg)"; }}
                  onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "transparent"; }}
                  onClick={() => setViewingEntry(entry)}
                >
                  <td style={{ padding: "10px 16px", fontFamily: "var(--oc-font-mono)", fontSize: "0.68rem", fontWeight: 600, color: "var(--oc-text-primary)", letterSpacing: "0.04em" }}>{entry.schemaName}</td>
                  <td style={{ padding: "10px 16px", color: "var(--oc-text-primary)", fontWeight: 500 }}>{entry.subjectSummary}</td>
                  <td style={{ padding: "10px 16px", fontFamily: "var(--oc-font-mono)", fontSize: "0.72rem", color: "var(--oc-text-secondary)" }}>{formatDateShort(entry.issuedAt)}</td>
                  <td style={{ padding: "10px 16px", textAlign: "right" }}>
                    <button
                      onClick={(e) => { e.stopPropagation(); handleReissue(entry); }}
                      style={{ padding: "4px 12px", borderRadius: 5, border: "1px solid var(--oc-border)", background: "transparent", color: "var(--oc-text-primary)", fontFamily: "var(--oc-font-body)", fontSize: "0.7rem", fontWeight: 500, cursor: "pointer" }}
                    >
                      Reissue
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {viewingEntry && (
        <CredentialDetailModal
          entry={viewingEntry}
          onClose={() => setViewingEntry(null)}
          onDelete={() => void handleDelete(viewingEntry.id)}
          onReissue={() => { setViewingEntry(null); handleReissue(viewingEntry); }}
        />
      )}
    </div>
  );
}
