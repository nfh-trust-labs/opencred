/**
 * HomeScreen — Google Docs-style landing page with template cards,
 * recent credential history, and a detail modal for viewing/exporting.
 */

import { useState, useEffect, useCallback } from "react";
import { TemplateCard } from "./ui/TemplateCard";
import { CredentialHistoryCard } from "./ui/CredentialHistoryCard";
import { getVisual } from "./ui/TemplateCard";
import { Button } from "./ui/Button";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface HistoryEntry {
  id: string;
  schemaId: string;
  schemaName: string;
  subjectSummary: string;
  issuedAt: string;
  credentialJson: string;
  keyFingerprint: string;
}

interface CustomSchema {
  id: string;
  name: string;
}

interface Props {
  onSelectTemplate: (schemaId: string, isBlank: boolean) => void;
}

const SCHEMA_LABELS: Record<string, string> = {
  education: "Education Credential",
  employment: "Employment Credential",
  identity: "Identity Credential",
  health: "Health Credential",
  business: "Business Credential",
  "energy-prosumer": "Energy Prosumer",
};

// ---------------------------------------------------------------------------
// Credential Detail Modal
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
    return new Date(iso).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

function labelForField(name: string): string {
  return name
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/^./, (c) => c.toUpperCase());
}

interface CredentialDetailModalProps {
  entry: HistoryEntry;
  onClose: () => void;
  onDelete: () => void;
  onReissue: () => void;
}

function CredentialDetailModal({ entry, onClose, onDelete, onReissue }: CredentialDetailModalProps) {
  const v = getVisual(entry.schemaId);
  let vc: Record<string, unknown>;
  try {
    vc = JSON.parse(entry.credentialJson) as Record<string, unknown>;
  } catch {
    vc = {};
  }
  const subject = ((vc.credentialSubject ?? {}) as Record<string, unknown>);
  const subjectEntries = Object.entries(subject).filter(
    ([key, value]) => key !== "id" && typeof value !== "object",
  );
  const issuer = typeof vc.issuer === "string" ? vc.issuer : vc.issuer?.id ?? "Unknown";
  const proofType = vc.proof?.type ?? null;
  const issuanceDate = vc.issuanceDate ?? vc.validFrom ?? "";
  const expirationDate = vc.expirationDate ?? vc.validUntil ?? null;

  async function handleExportJson() {
    try {
      await window.opencred.saveFile({
        defaultName: `credential-${entry.schemaId}.json`,
        content: JSON.stringify(JSON.parse(entry.credentialJson), null, 2),
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
    } catch { /* User cancelled */ }
  }

  async function handleExportPdf() {
    try {
      const result = await window.opencred.packageCredential({
        credential: entry.credentialJson,
        formats: ["pdf"],
      });
      if (result.success && result.outputs && result.outputs.length > 0) {
        await window.opencred.saveFile({
          defaultName: result.outputs[0].suggestedFileName,
          content: result.outputs[0].data,
          encoding: "base64",
          filters: [{ name: "PDF", extensions: ["pdf"] }],
        });
      }
    } catch { /* User cancelled */ }
  }

  async function handleShowQr() {
    try {
      const result = await window.opencred.packageCredential({
        credential: entry.credentialJson,
        formats: ["qr-png"],
      });
      if (result.success && result.outputs && result.outputs.length > 0) {
        const qrOutput = result.outputs[0];
        const base64Data = qrOutput.data.includes(",") ? qrOutput.data.split(",")[1] : qrOutput.data;
        await window.opencred.saveFile({
          defaultName: qrOutput.suggestedFileName,
          content: base64Data,
          encoding: "base64",
          filters: [{ name: "PNG Image", extensions: ["png"] }],
        });
      }
    } catch { /* User cancelled */ }
  }

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1000,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        backgroundColor: "rgba(0, 0, 0, 0.4)",
        backdropFilter: "blur(4px)",
      }}
      onClick={onClose}
    >
      <div
        style={{
          width: "100%",
          maxWidth: 520,
          maxHeight: "85vh",
          overflow: "auto",
          borderRadius: 14,
          backgroundColor: "var(--oc-surface)",
          boxShadow: `0 24px 64px -12px ${v.fg}30, 0 8px 24px rgba(0,0,0,0.12)`,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header with gradient */}
        <div
          style={{
            background: `linear-gradient(135deg, ${v.fg}, ${v.border})`,
            padding: "28px 28px 24px",
            position: "relative",
            overflow: "hidden",
          }}
        >
          <div
            style={{
              position: "absolute",
              right: -20,
              top: -20,
              width: 100,
              height: 100,
              borderRadius: "50%",
              border: "1px solid rgba(255,255,255,0.1)",
            }}
          />
          <button
            onClick={onClose}
            style={{
              position: "absolute",
              top: 14,
              right: 14,
              width: 28,
              height: 28,
              borderRadius: 8,
              border: "none",
              background: "rgba(255,255,255,0.15)",
              color: "#fff",
              cursor: "pointer",
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
          <div
            style={{
              fontFamily: "var(--oc-font-mono)",
              fontSize: "0.56rem",
              letterSpacing: "0.12em",
              textTransform: "uppercase",
              color: "rgba(255,255,255,0.6)",
              marginBottom: 4,
            }}
          >
            {entry.schemaName}
          </div>
          <h3
            style={{
              fontFamily: "var(--oc-font-display)",
              fontSize: "1.35rem",
              color: "#fff",
              margin: 0,
              fontWeight: 400,
            }}
          >
            {entry.subjectSummary}
          </h3>
        </div>

        {/* Subject fields */}
        {subjectEntries.length > 0 && (
          <div style={{ padding: "22px 28px 16px" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px 28px" }}>
              {subjectEntries.map(([key, value]) => (
                <div key={key}>
                  <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.56rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)" }}>
                    {labelForField(key)}
                  </dt>
                  <dd style={{ fontFamily: "var(--oc-font-body)", fontSize: "0.88rem", fontWeight: 500, color: "var(--oc-text-primary)", margin: 0, marginTop: 3 }}>
                    {String(value)}
                  </dd>
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
              <dd style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.7rem", color: "var(--oc-text-secondary)", margin: 0, marginTop: 2 }} title={issuer}>{truncateDid(issuer)}</dd>
            </div>
            {proofType && (
              <div>
                <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.54rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)" }}>Proof</dt>
                <dd style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.7rem", color: "var(--oc-text-secondary)", margin: 0, marginTop: 2 }}>{proofType}</dd>
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

        {/* Export + actions bar */}
        <div style={{ padding: "16px 28px", borderTop: "1px solid var(--oc-border-light)", display: "flex", flexWrap: "wrap", gap: 8 }}>
          {[
            { label: "Download JSON", icon: "M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5", fn: handleExportJson },
            { label: "Download PDF", icon: "M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z", fn: handleExportPdf },
            { label: "QR Code", icon: "M3.75 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 013.75 9.375v-4.5zM3.75 14.625c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5a1.125 1.125 0 01-1.125-1.125v-4.5zM13.5 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 0113.5 9.375v-4.5z", fn: handleShowQr },
          ].map((action) => (
            <Button key={action.label} variant="secondary" size="sm" onClick={() => void action.fn()}>
              <span style={{ display: "inline-flex", alignItems: "center", gap: 5 }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d={action.icon} />
                </svg>
                {action.label}
              </span>
            </Button>
          ))}
        </div>

        {/* Bottom actions */}
        <div
          style={{
            padding: "14px 28px",
            borderTop: "1px solid var(--oc-border-light)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <button
            onClick={onDelete}
            style={{
              fontFamily: "var(--oc-font-body)",
              fontSize: "0.72rem",
              color: "var(--oc-text-muted)",
              background: "none",
              border: "none",
              cursor: "pointer",
              padding: "4px 8px",
              borderRadius: 4,
              transition: "color 0.15s",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = "#DC2626"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--oc-text-muted)"; }}
          >
            Remove from history
          </button>
          <Button size="sm" onClick={onReissue}>
            Reissue
          </Button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function HomeScreen({ onSelectTemplate }: Props) {
  const [schemas, setSchemas] = useState<string[]>([]);
  const [customSchemas, setCustomSchemas] = useState<CustomSchema[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewingEntry, setViewingEntry] = useState<HistoryEntry | null>(null);
  const [renamingSchemaId, setRenamingSchemaId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");

  const loadData = useCallback(async () => {
    try {
      const [schemaRes, customRes, historyRes] = await Promise.all([
        window.opencred.listSchemas(),
        window.opencred.customSchemaList(),
        window.opencred.credentialHistoryList(),
      ]);
      setSchemas(schemaRes.schemas);
      setCustomSchemas(customRes.schemas.map((s) => ({ id: s.id, name: s.name })));
      setHistory(historyRes.entries);
    } catch {
      // Data may not be available yet
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  /**
   * Reissue a credential — ensures the schema is saved so the builder
   * shows fields directly without the "Define Fields" step.
   *
   * For old entries with schemaId "blank": extracts the schema from the
   * stored credential JSON, saves it as a custom schema, and updates
   * the history entry's schemaId.
   */
  async function handleReissue(entry: HistoryEntry) {
    let effectiveSchemaId = entry.schemaId;

    if (effectiveSchemaId === "blank") {
      // Migrate: extract schema from credential, save as custom schema
      try {
        const vc = JSON.parse(entry.credentialJson);
        const subject = (vc.credentialSubject ?? {}) as Record<string, unknown>;
        // Build a JSON Schema from the credential subject fields
        const properties: Record<string, Record<string, unknown>> = {};
        for (const [key, value] of Object.entries(subject)) {
          if (key === "id") continue;
          if (typeof value === "number") {
            properties[key] = { type: "number" };
          } else if (typeof value === "string" && /^\d{4}-\d{2}-\d{2}/.test(value)) {
            properties[key] = { type: "string", format: "date" };
          } else {
            properties[key] = { type: "string" };
          }
        }
        const schema = { type: "object", properties, required: Object.keys(properties) };

        const saved = await window.opencred.customSchemaSave({
          name: entry.schemaName || "Custom Credential",
          schema,
        });
        effectiveSchemaId = saved.id;

        // Update the history entry's schemaId so future reissues are fast
        // (delete + re-add with new schemaId)
        await window.opencred.credentialHistoryDelete({ id: entry.id });
        await window.opencred.credentialHistoryAdd({
          schemaId: effectiveSchemaId,
          schemaName: entry.schemaName,
          subjectSummary: entry.subjectSummary,
          credentialJson: entry.credentialJson,
          keyFingerprint: entry.keyFingerprint,
        });
        // Update local state
        setHistory((prev) =>
          prev.map((e) => (e.id === entry.id ? { ...e, schemaId: effectiveSchemaId } : e)),
        );
      } catch {
        // Fall back to blank builder if migration fails
        onSelectTemplate("blank", true);
        return;
      }
    }

    onSelectTemplate(effectiveSchemaId, false);
  }

  async function handleDeleteHistory(id: string) {
    try {
      await window.opencred.credentialHistoryDelete({ id });
      setHistory((prev) => prev.filter((e) => e.id !== id));
      setViewingEntry(null);
    } catch { /* Ignore */ }
  }

  async function handleRenameSchema(schemaId: string, newName: string) {
    if (!newName.trim()) return;
    try {
      // Load the full schema, save with updated name
      const list = await window.opencred.customSchemaList();
      const existing = list.schemas.find((s) => s.id === schemaId);
      if (!existing) return;
      await window.opencred.customSchemaSave({ id: schemaId, name: newName.trim(), schema: existing.schema });
      setCustomSchemas((prev) => prev.map((cs) => cs.id === schemaId ? { ...cs, name: newName.trim() } : cs));
    } catch { /* Ignore */ }
    setRenamingSchemaId(null);
  }

  async function handleDeleteSchema(schemaId: string) {
    try {
      await window.opencred.customSchemaDelete({ id: schemaId });
      setCustomSchemas((prev) => prev.filter((cs) => cs.id !== schemaId));
    } catch { /* Ignore */ }
  }

  if (loading) {
    return <p className="text-sm text-gray-400">Loading...</p>;
  }

  return (
    <div className="space-y-8">
      {/* Section: Issue a new credential */}
      <section>
        <h2 className="oc-page-title" style={{ marginBottom: "16px" }}>
          Issue a new credential
        </h2>
        <div className="oc-template-grid">
          <TemplateCard
            name="Blank credential"
            isBlank
            onClick={() => onSelectTemplate("blank", true)}
          />
          {schemas.map((id) => (
            <TemplateCard
              key={id}
              schemaId={id}
              name={SCHEMA_LABELS[id] ?? id}
              onClick={() => onSelectTemplate(id, false)}
            />
          ))}
          {customSchemas.map((cs) => (
            <div key={cs.id} className="relative group">
              {renamingSchemaId === cs.id ? (
                <div className="oc-template-card" style={{ padding: "16px", gap: 8, justifyContent: "flex-start" }}>
                  <input
                    type="text"
                    value={renameValue}
                    onChange={(e) => setRenameValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void handleRenameSchema(cs.id, renameValue);
                      if (e.key === "Escape") setRenamingSchemaId(null);
                    }}
                    autoFocus
                    className="w-full rounded border border-gray-300 px-2 py-1 text-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  />
                  <div className="flex gap-2">
                    <button
                      onClick={() => void handleRenameSchema(cs.id, renameValue)}
                      className="text-xs text-blue-600 hover:text-blue-800"
                    >
                      Save
                    </button>
                    <button
                      onClick={() => setRenamingSchemaId(null)}
                      className="text-xs text-gray-400 hover:text-gray-600"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <TemplateCard
                    schemaId={cs.id}
                    name={cs.name}
                    onClick={() => onSelectTemplate(cs.id, false)}
                  />
                  {/* Hover actions: rename & delete */}
                  <div className="absolute top-1 right-1 hidden group-hover:flex gap-1">
                    <button
                      onClick={(e) => { e.stopPropagation(); setRenamingSchemaId(cs.id); setRenameValue(cs.name); }}
                      title="Rename"
                      className="p-1 rounded bg-white/80 text-gray-400 hover:text-blue-600 transition-colors"
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125" />
                      </svg>
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); void handleDeleteSchema(cs.id); }}
                      title="Delete"
                      className="p-1 rounded bg-white/80 text-gray-400 hover:text-red-500 transition-colors"
                    >
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                </>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Section: Recent credentials — compact table */}
      <section>
        <h2 className="oc-page-title" style={{ marginBottom: "16px" }}>
          Recent credentials
        </h2>
        {history.length === 0 ? (
          <p className="text-sm text-gray-400 italic">No credentials issued yet.</p>
        ) : (
          <div style={{ borderRadius: 10, border: "1px solid var(--oc-border)", overflow: "hidden" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "var(--oc-font-body)", fontSize: "0.82rem" }}>
              <thead>
                <tr style={{ backgroundColor: "var(--oc-bg)", borderBottom: "1px solid var(--oc-border)" }}>
                  <th style={{ padding: "10px 16px", textAlign: "left", fontFamily: "var(--oc-font-mono)", fontSize: "0.6rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)", fontWeight: 600 }}>Type</th>
                  <th style={{ padding: "10px 16px", textAlign: "left", fontFamily: "var(--oc-font-mono)", fontSize: "0.6rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)", fontWeight: 600 }}>Subject</th>
                  <th style={{ padding: "10px 16px", textAlign: "left", fontFamily: "var(--oc-font-mono)", fontSize: "0.6rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)", fontWeight: 600 }}>Issued</th>
                  <th style={{ padding: "10px 16px", textAlign: "right", fontFamily: "var(--oc-font-mono)", fontSize: "0.6rem", letterSpacing: "0.08em", textTransform: "uppercase", color: "var(--oc-text-muted)", fontWeight: 600 }}></th>
                </tr>
              </thead>
              <tbody>
                {history.map((entry) => {
                  const v = getVisual(entry.schemaId);
                  return (
                    <tr
                      key={entry.id}
                      style={{ borderBottom: "1px solid var(--oc-border-light)", cursor: "pointer", transition: "background-color 0.1s" }}
                      onMouseEnter={(e) => { e.currentTarget.style.backgroundColor = "var(--oc-bg)"; }}
                      onMouseLeave={(e) => { e.currentTarget.style.backgroundColor = "transparent"; }}
                      onClick={() => setViewingEntry(entry)}
                    >
                      <td style={{ padding: "10px 16px" }}>
                        <span style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.68rem", fontWeight: 600, color: v.fg, letterSpacing: "0.04em" }}>
                          {entry.schemaName}
                        </span>
                      </td>
                      <td style={{ padding: "10px 16px", color: "var(--oc-text-primary)", fontWeight: 500 }}>
                        {entry.subjectSummary}
                      </td>
                      <td style={{ padding: "10px 16px", fontFamily: "var(--oc-font-mono)", fontSize: "0.72rem", color: "var(--oc-text-muted)" }}>
                        {new Date(entry.issuedAt).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
                      </td>
                      <td style={{ padding: "10px 16px", textAlign: "right" }}>
                        <button
                          onClick={(e) => { e.stopPropagation(); void handleReissue(entry); }}
                          style={{
                            padding: "4px 12px", borderRadius: 5, border: "none",
                            background: v.fg, color: "#fff", fontFamily: "var(--oc-font-body)",
                            fontSize: "0.7rem", fontWeight: 600, cursor: "pointer",
                          }}
                        >
                          Reissue
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Credential detail modal */}
      {viewingEntry && (
        <CredentialDetailModal
          entry={viewingEntry}
          onClose={() => setViewingEntry(null)}
          onDelete={() => void handleDeleteHistory(viewingEntry.id)}
          onReissue={() => {
            setViewingEntry(null);
            void handleReissue(viewingEntry);
          }}
        />
      )}
    </div>
  );
}
