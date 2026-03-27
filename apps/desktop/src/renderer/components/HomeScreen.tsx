/**
 * HomeScreen — landing page with template cards and recently used templates.
 * No credential data is stored or displayed here — only template metadata.
 */

import { useState, useEffect, useCallback } from "react";
import { TemplateCard } from "./ui/TemplateCard";
import { Button } from "./ui/Button";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RecentTemplate {
  schemaId: string;
  schemaName: string;
  lastUsedAt: string;
  useCount: number;
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
// Component
// ---------------------------------------------------------------------------

export function HomeScreen({ onSelectTemplate }: Props) {
  const [schemas, setSchemas] = useState<string[]>([]);
  const [customSchemas, setCustomSchemas] = useState<CustomSchema[]>([]);
  const [recentTemplates, setRecentTemplates] = useState<RecentTemplate[]>([]);
  const [loading, setLoading] = useState(true);
  const [renamingSchemaId, setRenamingSchemaId] = useState<string | null>(null);
  const [renameValue, setRenameValue] = useState("");

  const loadData = useCallback(async () => {
    try {
      const [schemaRes, customRes, recentRes] = await Promise.all([
        window.opencred.listSchemas(),
        window.opencred.customSchemaList(),
        window.opencred.recentTemplatesList(),
      ]);
      setSchemas(schemaRes.schemas);
      setCustomSchemas(customRes.schemas.map((s) => ({ id: s.id, name: s.name })));
      setRecentTemplates(recentRes.templates);
    } catch {
      // Data may not be available yet
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  async function handleRenameSchema(schemaId: string, newName: string) {
    if (!newName.trim()) return;
    try {
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

      {/* Section: Recently used */}
      {recentTemplates.length > 0 && (
        <section>
          <h2 className="oc-page-title" style={{ marginBottom: "16px" }}>
            Recently used
          </h2>
          <div className="oc-template-grid">
            {recentTemplates.map((t) => (
              <TemplateCard
                key={t.schemaId}
                schemaId={t.schemaId}
                name={t.schemaName}
                subtitle={`Used ${t.useCount} time${t.useCount !== 1 ? "s" : ""}`}
                onClick={() => onSelectTemplate(t.schemaId, t.schemaId.startsWith("custom:"))}
              />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
