/**
 * CredentialBuilderPage — unified credential builder with Single/Batch toggle.
 *
 * Opened from the home screen when a template is selected. Schema is
 * pre-selected (no dropdown needed unless blank). Supports both single
 * issuance (form) and batch issuance (CSV) via a segmented control.
 *
 * After successful issuance, auto-saves to credential history.
 */

import { useState, useEffect, useCallback } from "react";
import type { KeyMetadata, UiProofFormat } from "../../shared/ipc-types";
import { Button } from "./ui/Button";
import { Card } from "./ui/Card";
import { getVisual } from "./ui/TemplateCard";
import { BatchIssuance } from "./BatchIssuance";
import { BlankCredentialBuilder } from "./BlankCredentialBuilder";
import { MoreOptions } from "./MoreOptions";
import { formatKeyDate } from "../utils/format";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface SchemaField {
  name: string;
  type: string;
  required: boolean;
  format?: string;
}

type BuilderMode = "single" | "batch";

interface Props {
  schemaId: string;
  isBlank: boolean;
  onBack: () => void;
  onNavigate?: (view: string) => void;
}

// ---------------------------------------------------------------------------
// Helpers (reused from IssuePage)
// ---------------------------------------------------------------------------

const SCHEMA_LABELS: Record<string, string> = {
  education: "Education Credential",
  employment: "Employment Credential",
  identity: "Identity Credential",
  health: "Health Credential",
  business: "Business Credential",
  "energy-prosumer": "Energy Prosumer",
};

function extractFields(schema: Record<string, unknown>): SchemaField[] {
  const properties = schema["properties"] as
    | Record<string, Record<string, unknown>>
    | undefined;
  const required = (schema["required"] as string[]) ?? [];
  if (!properties) return [];
  return Object.entries(properties).map(([name, prop]) => ({
    name,
    type: String(prop["type"] ?? "string"),
    required: required.includes(name),
    format: prop["format"] as string | undefined,
  }));
}

function inputTypeForField(field: SchemaField): string {
  if (field.format === "date") return "date";
  if (field.format === "date-time") return "datetime-local";
  if (field.format === "email") return "email";
  if (field.format === "uri") return "url";
  if (field.type === "number" || field.type === "integer") return "number";
  return "text";
}

function labelForField(name: string): string {
  return name
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/^./, (c) => c.toUpperCase());
}

function todayIso(): string {
  return new Date().toISOString().split("T")[0];
}

function oneYearFromNow(): string {
  const d = new Date();
  d.setFullYear(d.getFullYear() + 1);
  return d.toISOString().split("T")[0];
}

// formatKeyDate is imported from ../utils/format

/** Parse a VC JSON string into display-friendly fields. */
function parseCredential(raw: string): {
  types: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate: string | null;
  subject: Record<string, unknown>;
  proofType: string | null;
} {
  const vc = JSON.parse(raw);
  const types: string[] = Array.isArray(vc.type) ? vc.type : [vc.type ?? "VerifiableCredential"];
  const issuer = typeof vc.issuer === "string" ? vc.issuer : vc.issuer?.id ?? "Unknown";
  const issuanceDate = vc.issuanceDate ?? vc.validFrom ?? "";
  const expirationDate = vc.expirationDate ?? vc.validUntil ?? null;
  const subject = (vc.credentialSubject ?? {}) as Record<string, unknown>;
  const proofType = vc.proof?.type ?? null;
  return { types, issuer, issuanceDate, expirationDate, subject, proofType };
}

function formatDate(iso: string): string {
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

/** Build a one-line subject summary from credential subject values. */
function buildSubjectSummary(values: Record<string, string>): string {
  const vals = Object.values(values).filter(Boolean);
  if (vals.length === 0) return "Credential";
  return vals.slice(0, 3).join(" — ");
}

// ---------------------------------------------------------------------------
// Credential Result Display
// ---------------------------------------------------------------------------

interface CredentialResultProps {
  signedCredential: string;
  schemaId?: string;
  schemaName?: string;
  onExportJson: () => void;
  onExportPdf: () => void;
  onShowQr: () => void;
}

function CredentialResult({ signedCredential, schemaId, schemaName, onExportJson, onExportPdf, onShowQr }: CredentialResultProps) {
  const [showRaw, setShowRaw] = useState(false);
  const vc = parseCredential(signedCredential);
  const typeFromVc = vc.types.find((t) => t !== "VerifiableCredential");
  const displayType = typeFromVc ?? schemaName ?? "Verifiable Credential";
  const v = getVisual(schemaId);

  const subjectEntries = Object.entries(vc.subject).filter(
    ([key, value]) => key !== "id" && typeof value !== "object",
  );

  return (
    <div style={{ marginTop: 20 }}>
      {/* Success banner — understated */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "10px 16px",
          borderRadius: "10px 10px 0 0",
          background: `linear-gradient(135deg, ${v.bg}, #fff)`,
          borderBottom: "none",
        }}
      >
        <div
          style={{
            width: 22,
            height: 22,
            borderRadius: "50%",
            backgroundColor: "#10B981",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth={3}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <span
          style={{
            fontFamily: "var(--oc-font-body)",
            fontSize: "0.82rem",
            fontWeight: 600,
            color: "var(--oc-text-primary)",
          }}
        >
          Credential issued and signed
        </span>
        <span
          style={{
            marginLeft: "auto",
            fontFamily: "var(--oc-font-mono)",
            fontSize: "0.56rem",
            letterSpacing: "0.1em",
            textTransform: "uppercase" as const,
            color: "#10B981",
            fontWeight: 700,
            padding: "3px 8px",
            borderRadius: 4,
            backgroundColor: "#10B98115",
          }}
        >
          Signed
        </span>
      </div>

      {/* Main credential card */}
      <div
        style={{
          borderRadius: "0 0 12px 12px",
          overflow: "hidden",
          border: "1px solid var(--oc-border)",
          borderTop: "none",
          backgroundColor: "var(--oc-surface)",
          boxShadow: `0 8px 32px -8px ${v.fg}20, 0 2px 8px rgba(0,0,0,0.04)`,
        }}
      >
        {/* Grand header with gradient */}
        <div
          style={{
            background: `linear-gradient(135deg, ${v.fg}, ${v.border})`,
            padding: "28px 28px 24px",
            position: "relative",
            overflow: "hidden",
          }}
        >
          {/* Decorative circle pattern */}
          <div
            style={{
              position: "absolute",
              right: -20,
              top: -20,
              width: 120,
              height: 120,
              borderRadius: "50%",
              border: "1px solid rgba(255,255,255,0.12)",
            }}
          />
          <div
            style={{
              position: "absolute",
              right: -40,
              top: -40,
              width: 160,
              height: 160,
              borderRadius: "50%",
              border: "1px solid rgba(255,255,255,0.06)",
            }}
          />

          <div style={{ position: "relative", display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
            <div>
              <div
                style={{
                  fontFamily: "var(--oc-font-mono)",
                  fontSize: "0.58rem",
                  letterSpacing: "0.12em",
                  textTransform: "uppercase" as const,
                  color: "rgba(255,255,255,0.65)",
                  marginBottom: 6,
                }}
              >
                Verifiable Credential
              </div>
              <h3
                style={{
                  fontFamily: "var(--oc-font-display)",
                  fontSize: "1.5rem",
                  fontWeight: 400,
                  color: "#fff",
                  margin: 0,
                  lineHeight: 1.2,
                }}
              >
                {typeFromVc
                  ? (labelForField(typeFromVc.replace("Credential", "").trim()) || "Credential")
                  : (displayType)}
              </h3>
            </div>
            <div
              style={{
                width: 44,
                height: 44,
                borderRadius: 12,
                backgroundColor: "rgba(255,255,255,0.15)",
                backdropFilter: "blur(8px)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
              }}
            >
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
          </div>
        </div>

        {/* Subject fields — generous spacing */}
        {subjectEntries.length > 0 && (
          <div style={{ padding: "24px 28px 20px" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "18px 32px" }}>
              {subjectEntries.map(([key, value]) => (
                <div key={key}>
                  <dt
                    style={{
                      fontFamily: "var(--oc-font-mono)",
                      fontSize: "0.58rem",
                      letterSpacing: "0.08em",
                      textTransform: "uppercase" as const,
                      color: "var(--oc-text-muted)",
                      marginBottom: 4,
                    }}
                  >
                    {labelForField(key)}
                  </dt>
                  <dd
                    style={{
                      fontFamily: "var(--oc-font-body)",
                      fontSize: "0.92rem",
                      fontWeight: 500,
                      color: "var(--oc-text-primary)",
                      margin: 0,
                    }}
                  >
                    {String(value)}
                  </dd>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Metadata — subtle section */}
        <div
          style={{
            padding: "16px 28px",
            borderTop: "1px solid var(--oc-border-light)",
            backgroundColor: "var(--oc-bg)",
          }}
        >
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px 32px" }}>
            <div>
              <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.56rem", letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "var(--oc-text-muted)" }}>
                Issuer
              </dt>
              <dd style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.72rem", color: "var(--oc-text-secondary)", marginTop: 2, margin: 0 }} title={vc.issuer}>
                {truncateDid(vc.issuer)}
              </dd>
            </div>
            {vc.proofType && (
              <div>
                <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.56rem", letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "var(--oc-text-muted)" }}>
                  Proof
                </dt>
                <dd style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.72rem", color: "var(--oc-text-secondary)", marginTop: 2, margin: 0 }}>
                  {vc.proofType}
                </dd>
              </div>
            )}
            <div>
              <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.56rem", letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "var(--oc-text-muted)" }}>
                Issued
              </dt>
              <dd style={{ fontFamily: "var(--oc-font-body)", fontSize: "0.82rem", color: "var(--oc-text-primary)", marginTop: 2, margin: 0 }}>
                {formatDate(vc.issuanceDate)}
              </dd>
            </div>
            {vc.expirationDate && (
              <div>
                <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.56rem", letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "var(--oc-text-muted)" }}>
                  Expires
                </dt>
                <dd style={{ fontFamily: "var(--oc-font-body)", fontSize: "0.82rem", color: "var(--oc-text-primary)", marginTop: 2, margin: 0 }}>
                  {formatDate(vc.expirationDate)}
                </dd>
              </div>
            )}
          </div>
        </div>

        {/* Export actions — polished toolbar */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "14px 28px",
            borderTop: "1px solid var(--oc-border-light)",
            backgroundColor: "var(--oc-surface)",
          }}
        >
          {[
            { label: "JSON", icon: "M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5", onClick: onExportJson },
            { label: "PDF", icon: "M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z", onClick: onExportPdf },
            { label: "QR Code", icon: "M3.75 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 013.75 9.375v-4.5zM3.75 14.625c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5a1.125 1.125 0 01-1.125-1.125v-4.5zM13.5 4.875c0-.621.504-1.125 1.125-1.125h4.5c.621 0 1.125.504 1.125 1.125v4.5c0 .621-.504 1.125-1.125 1.125h-4.5A1.125 1.125 0 0113.5 9.375v-4.5z", onClick: onShowQr },
          ].map((action) => (
            <button
              key={action.label}
              onClick={action.onClick}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 6,
                padding: "8px 16px",
                borderRadius: 8,
                border: "1px solid var(--oc-border)",
                background: "var(--oc-surface)",
                fontFamily: "var(--oc-font-body)",
                fontSize: "0.76rem",
                fontWeight: 500,
                color: "var(--oc-text-secondary)",
                cursor: "pointer",
                transition: "all 0.2s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = v.fg;
                e.currentTarget.style.color = v.fg;
                e.currentTarget.style.backgroundColor = v.bg;
                e.currentTarget.style.boxShadow = `0 2px 8px ${v.fg}15`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = "var(--oc-border)";
                e.currentTarget.style.color = "var(--oc-text-secondary)";
                e.currentTarget.style.backgroundColor = "var(--oc-surface)";
                e.currentTarget.style.boxShadow = "none";
              }}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d={action.icon} />
              </svg>
              {action.label}
            </button>
          ))}

          {/* Raw toggle — pushed right */}
          <button
            onClick={() => setShowRaw((prev) => !prev)}
            style={{
              marginLeft: "auto",
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              padding: "6px 10px",
              borderRadius: 6,
              border: "none",
              background: "none",
              fontFamily: "var(--oc-font-mono)",
              fontSize: "0.68rem",
              color: "var(--oc-text-muted)",
              cursor: "pointer",
              transition: "color 0.15s",
            }}
            onMouseEnter={(e) => { e.currentTarget.style.color = "var(--oc-text-primary)"; }}
            onMouseLeave={(e) => { e.currentTarget.style.color = "var(--oc-text-muted)"; }}
          >
            {showRaw ? "Hide" : "Show"} Raw
            <svg
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              style={{ transition: "transform 0.2s", transform: showRaw ? "rotate(180deg)" : "none" }}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>

        {/* Raw JSON — collapsible */}
        {showRaw && (
          <div style={{ borderTop: "1px solid var(--oc-border-light)" }}>
            <pre
              style={{
                maxHeight: 300,
                overflow: "auto",
                backgroundColor: "#1e1e2e",
                color: "#cdd6f4",
                padding: "20px 28px",
                margin: 0,
                fontFamily: "var(--oc-font-mono)",
                fontSize: "0.72rem",
                lineHeight: 1.7,
                borderRadius: "0 0 12px 12px",
              }}
            >
              {JSON.stringify(JSON.parse(signedCredential), null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// SD-JWT-VC Result Display
// ---------------------------------------------------------------------------

interface SdJwtResultProps {
  signedCredential: string;
  onExport: () => void;
}

function SdJwtResult({ signedCredential, onExport }: SdJwtResultProps) {
  const [showRaw, setShowRaw] = useState(false);
  const disclosureCount = signedCredential.split("~").length - 1;

  return (
    <div style={{ marginTop: 20 }}>
      {/* Success banner */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          padding: "10px 16px",
          borderRadius: "10px 10px 0 0",
          background: "linear-gradient(135deg, #ecfdf5, #fff)",
          borderBottom: "none",
        }}
      >
        <div
          style={{
            width: 22,
            height: 22,
            borderRadius: "50%",
            backgroundColor: "#10B981",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            flexShrink: 0,
          }}
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth={3}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
          </svg>
        </div>
        <span
          style={{
            fontFamily: "var(--oc-font-body)",
            fontSize: "0.82rem",
            fontWeight: 600,
            color: "var(--oc-text-primary)",
          }}
        >
          Credential issued as SD-JWT-VC
        </span>
      </div>

      {/* Card body */}
      <div
        style={{
          borderRadius: "0 0 12px 12px",
          overflow: "hidden",
          border: "1px solid var(--oc-border)",
          borderTop: "none",
          backgroundColor: "var(--oc-surface)",
        }}
      >
        {/* Metadata */}
        <div style={{ padding: "16px 28px" }}>
          <div style={{ display: "flex", gap: 32 }}>
            <div>
              <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.56rem", letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "var(--oc-text-muted)" }}>
                Format
              </dt>
              <dd style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.72rem", color: "var(--oc-text-secondary)", marginTop: 2, margin: 0 }}>
                SD-JWT-VC
              </dd>
            </div>
            <div>
              <dt style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.56rem", letterSpacing: "0.08em", textTransform: "uppercase" as const, color: "var(--oc-text-muted)" }}>
                Disclosures
              </dt>
              <dd style={{ fontFamily: "var(--oc-font-mono)", fontSize: "0.72rem", color: "var(--oc-text-secondary)", marginTop: 2, margin: 0 }}>
                {disclosureCount}
              </dd>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            padding: "14px 28px",
            borderTop: "1px solid var(--oc-border-light)",
            backgroundColor: "var(--oc-surface)",
          }}
        >
          <button
            onClick={onExport}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 6,
              padding: "8px 16px",
              borderRadius: 8,
              border: "1px solid var(--oc-border)",
              background: "var(--oc-surface)",
              fontFamily: "var(--oc-font-body)",
              fontSize: "0.76rem",
              fontWeight: 500,
              color: "var(--oc-text-secondary)",
              cursor: "pointer",
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
            </svg>
            Export .sd-jwt
          </button>

          <button
            onClick={() => setShowRaw((prev) => !prev)}
            style={{
              marginLeft: "auto",
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              padding: "6px 10px",
              borderRadius: 6,
              border: "none",
              background: "none",
              fontFamily: "var(--oc-font-mono)",
              fontSize: "0.68rem",
              color: "var(--oc-text-muted)",
              cursor: "pointer",
            }}
          >
            {showRaw ? "Hide" : "Show"} Raw
            <svg
              width="12"
              height="12"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2}
              style={{ transition: "transform 0.2s", transform: showRaw ? "rotate(180deg)" : "none" }}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
            </svg>
          </button>
        </div>

        {/* Raw compact token */}
        {showRaw && (
          <div style={{ borderTop: "1px solid var(--oc-border-light)" }}>
            <pre
              style={{
                maxHeight: 300,
                overflow: "auto",
                backgroundColor: "#1e1e2e",
                color: "#cdd6f4",
                padding: "20px 28px",
                margin: 0,
                fontFamily: "var(--oc-font-mono)",
                fontSize: "0.72rem",
                lineHeight: 1.7,
                borderRadius: "0 0 12px 12px",
                wordBreak: "break-all",
                whiteSpace: "pre-wrap",
              }}
            >
              {signedCredential}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function CredentialBuilderPage({ schemaId, isBlank, onBack, onNavigate }: Props) {
  const [mode, setMode] = useState<BuilderMode>("single");

  // Schema
  const [schemaName, setSchemaName] = useState("");
  const [schemaSourceUrl, setSchemaSourceUrl] = useState<string | undefined>(undefined);
  const [schemaFields, setSchemaFields] = useState<SchemaField[]>([]);

  // Form state
  const [subjectValues, setSubjectValues] = useState<Record<string, string>>({});
  const [validFrom, setValidFrom] = useState(todayIso);
  const [validUntil, setValidUntil] = useState(oneYearFromNow);
  const [selectedKeyId, setSelectedKeyId] = useState("");
  const [keys, setKeys] = useState<KeyMetadata[]>([]);

  // Result
  const [signing, setSigning] = useState(false);
  const [signedCredential, setSignedCredential] = useState<string | null>(null);
  const [resultProofFormat, setResultProofFormat] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // More options
  const [proofFormat, setProofFormat] = useState<UiProofFormat>("vc-jwt");
  const [selectiveDisclosureClaims, setSelectiveDisclosureClaims] = useState<string[]>([]);
  const [revocationRegistryUrl, setRevocationRegistryUrl] = useState("");
  const [credentialSchemaUrl, setCredentialSchemaUrl] = useState("");

  // Rename
  const [editingName, setEditingName] = useState(false);
  const [nameInput, setNameInput] = useState("");

  // Blank credential inline schema
  const [inlineSchema, setInlineSchema] = useState<Record<string, unknown> | null>(null);

  // did:web publication warning
  const [showDidWebWarning, setShowDidWebWarning] = useState(false);
  const [didWarningDismissed, setDidWarningDismissed] = useState(false);

  // ------------------------------------------------------------------
  // Data loading
  // ------------------------------------------------------------------

  const loadKeys = useCallback(async () => {
    try {
      const response = await window.opencred.listKeys();
      setKeys(response.keys);
      if (response.keys.length > 0 && !selectedKeyId) {
        setSelectedKeyId(response.keys[0].id);
      }
    } catch {
      // Keys may not be loaded yet
    }
  }, [selectedKeyId]);

  const loadSchema = useCallback(async () => {
    if (isBlank) {
      setSchemaName("Blank Credential");
      return;
    }

    // Check if it's a custom schema
    if (schemaId.startsWith("custom:")) {
      try {
        const customRes = await window.opencred.customSchemaList();
        const cs = customRes.schemas.find((s) => s.id === schemaId);
        if (cs) {
          setSchemaName(cs.name);
          setSchemaFields(extractFields(cs.schema));
          setInlineSchema(cs.schema);
        }
      } catch {
        setError("Failed to load custom schema.");
      }
      return;
    }

    // Built-in schema
    setSchemaName(SCHEMA_LABELS[schemaId] ?? schemaId);
    try {
      const response = await window.opencred.getSchema({ schemaId });
      setSchemaFields(extractFields(response.schema));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load schema.");
    }
  }, [schemaId, isBlank]);

  const checkDidWebWarning = useCallback(async () => {
    try {
      const selectedKey = keys.find((k) => k.id === selectedKeyId);
      if (!selectedKey || selectedKey.source !== "generated") {
        setShowDidWebWarning(false);
        return;
      }
      const status = await window.opencred.dediGetStatus();
      setShowDidWebWarning(!status.configured);
    } catch {
      setShowDidWebWarning(false);
    }
  }, [keys, selectedKeyId]);

  useEffect(() => {
    void loadKeys();
    void loadSchema();
  }, [loadKeys, loadSchema]);

  useEffect(() => {
    void checkDidWebWarning();
  }, [checkDidWebWarning]);

  // Auto-revert proof format when key changes to RSA while "data-integrity" is selected
  const selectedKeyAlgorithm = keys.find((k) => k.id === selectedKeyId)?.algorithm;
  useEffect(() => {
    if (proofFormat === "data-integrity" && selectedKeyAlgorithm?.startsWith("RSA")) {
      setProofFormat("vc-jwt");
    }
  }, [selectedKeyId, selectedKeyAlgorithm, proofFormat]);

  // ------------------------------------------------------------------
  // Single issuance handlers
  // ------------------------------------------------------------------

  async function handleBuildAndSign() {
    if (!selectedKeyId) {
      setError("Please select a signing key.");
      return;
    }
    if (!isBlank && !schemaId) {
      setError("No schema selected.");
      return;
    }

    setError(null);
    setSignedCredential(null);
    setResultProofFormat(null);
    setSigning(true);

    try {
      const selectedKey = keys.find((k) => k.id === selectedKeyId);
      const issuerDid = selectedKey?.id ?? selectedKeyId;

      const effectiveSchemaId = isBlank ? "blank" : schemaId;

      const response = await window.opencred.buildAndSign({
        schemaId: effectiveSchemaId,
        issuerDid,
        credentialSubject: subjectValues,
        validFrom: new Date(validFrom + "T00:00:00").toISOString(),
        validUntil: validUntil ? new Date(validUntil + "T23:59:59").toISOString() : undefined,
        keyId: selectedKeyId,
        packageFormats: proofFormat === "sd-jwt-vc" ? [] : ["json-ld"],
        inlineSchema: inlineSchema ?? undefined,
        proofFormat,
        selectiveDisclosureClaims: proofFormat === "sd-jwt-vc" ? selectiveDisclosureClaims : undefined,
        revocationRegistryUrl: revocationRegistryUrl || undefined,
        credentialSchemaUrl: credentialSchemaUrl || undefined,
      });

      if (response.success && response.signedCredential) {
        setSignedCredential(response.signedCredential);
        setResultProofFormat(response.proofFormat ?? "vc-jwt");

        // For blank credentials: auto-save the custom schema so reissue works
        let savedSchemaId = effectiveSchemaId;
        if (isBlank && inlineSchema) {
          try {
            const saved = await window.opencred.customSchemaSave({
              name: schemaName || "Custom Credential",
              schema: inlineSchema,
              sourceUrl: schemaSourceUrl,
            });
            savedSchemaId = saved.id;
          } catch {
            // Non-fatal: schema save failure shouldn't block issuance
          }
        }

        // Auto-save to credential history (using saved schema ID for reissue)
        try {
          await window.opencred.credentialHistoryAdd({
            schemaId: savedSchemaId,
            schemaName: schemaName || effectiveSchemaId,
            subjectSummary: buildSubjectSummary(subjectValues),
            credentialJson: response.signedCredential,
            keyFingerprint: selectedKey?.fingerprint ?? "",
            proofFormat: response.proofFormat,
          });
        } catch {
          // Non-fatal: history save failure shouldn't block issuance
        }
      } else {
        const errMsg = response.errorField
          ? `${response.error} (field: ${response.errorField})`
          : (response.error ?? "Build and sign failed.");
        setError(errMsg);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Build and sign failed.");
    } finally {
      setSigning(false);
    }
  }

  async function handleExportJson() {
    if (!signedCredential) return;
    try {
      // SD-JWT-VC: export as compact token with .sd-jwt extension
      if (resultProofFormat === "sd-jwt-vc") {
        await window.opencred.saveFile({
          defaultName: "credential.sd-jwt",
          content: signedCredential,
          filters: [{ name: "SD-JWT-VC", extensions: ["sd-jwt"] }],
        });
      } else {
        await window.opencred.saveFile({
          defaultName: "credential.json",
          content: JSON.stringify(JSON.parse(signedCredential), null, 2),
          filters: [{ name: "JSON", extensions: ["json"] }],
        });
      }
    } catch {
      // User may have cancelled
    }
  }

  async function handleExportPdf() {
    if (!signedCredential) return;
    try {
      const result = await window.opencred.packageCredential({
        credential: signedCredential,
        formats: ["pdf"],
      });
      if (result.success && result.outputs && result.outputs.length > 0) {
        const pdfOutput = result.outputs[0];
        await window.opencred.saveFile({
          defaultName: pdfOutput.suggestedFileName,
          content: pdfOutput.data,
          encoding: "base64",
          filters: [{ name: "PDF", extensions: ["pdf"] }],
        });
      }
    } catch {
      // User may have cancelled
    }
  }

  async function handleShowQr() {
    if (!signedCredential) return;
    try {
      const result = await window.opencred.packageCredential({
        credential: signedCredential,
        formats: ["qr-png"],
      });
      if (result.success && result.outputs && result.outputs.length > 0) {
        const qrOutput = result.outputs[0];
        const base64Data = qrOutput.data.includes(",")
          ? qrOutput.data.split(",")[1]
          : qrOutput.data;
        await window.opencred.saveFile({
          defaultName: qrOutput.suggestedFileName,
          content: base64Data,
          encoding: "base64",
          filters: [{ name: "PNG Image", extensions: ["png"] }],
        });
      }
    } catch {
      // User may have cancelled
    }
  }

  // Callback when blank builder produces fields/schema
  function handleBlankSchemaReady(fields: SchemaField[], schema: Record<string, unknown>, credentialName: string, sourceUrl?: string) {
    setSchemaFields(fields);
    setInlineSchema(schema);
    setSchemaName(credentialName);
    setSchemaSourceUrl(sourceUrl);
  }

  // ------------------------------------------------------------------
  // Rename handler
  // ------------------------------------------------------------------

  const isRenameable = isBlank || schemaId.startsWith("custom:");

  async function handleRename() {
    const newName = nameInput.trim();
    if (!newName) { setEditingName(false); return; }
    setSchemaName(newName);
    setEditingName(false);

    // Persist rename for saved custom schemas
    if (schemaId.startsWith("custom:")) {
      try {
        const list = await window.opencred.customSchemaList();
        const existing = list.schemas.find((s) => s.id === schemaId);
        if (existing) {
          await window.opencred.customSchemaSave({ id: schemaId, name: newName, schema: existing.schema });
        }
      } catch { /* non-fatal */ }
    }
  }

  // ------------------------------------------------------------------
  // Render
  // ------------------------------------------------------------------

  return (
    <div className="space-y-4">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 text-sm">
        <button
          onClick={onBack}
          className="text-gray-500 hover:text-gray-700 transition-colors flex items-center gap-1"
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Home
        </button>
        <span className="text-gray-300">/</span>
        {showDidWebWarning && didWarningDismissed && (
          <span
            className="inline-block w-2 h-2 rounded-full bg-amber-400 flex-shrink-0"
            title="DID document not yet published"
          />
        )}
        {editingName ? (
          <input
            type="text"
            value={nameInput}
            onChange={(e) => setNameInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleRename();
              if (e.key === "Escape") setEditingName(false);
            }}
            onBlur={() => void handleRename()}
            autoFocus
            className="rounded border border-gray-300 px-2 py-0.5 text-sm font-medium focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            style={{ minWidth: 120 }}
          />
        ) : (
          <span
            className={`text-gray-700 font-medium ${isRenameable ? "cursor-pointer hover:text-blue-600" : ""}`}
            onClick={() => {
              if (isRenameable) {
                setNameInput(schemaName || "Credential");
                setEditingName(true);
              }
            }}
            title={isRenameable ? "Click to rename" : undefined}
          >
            {schemaName || "Credential"}
            {isRenameable && (
              <svg className="inline ml-1 opacity-0 group-hover:opacity-100" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} style={{ opacity: 0.4 }}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931z" />
              </svg>
            )}
          </span>
        )}
      </div>

      {/* Segmented control: Single / Batch */}
      <div className="oc-segmented-control">
        <button
          onClick={() => setMode("single")}
          className={`oc-segmented-option ${mode === "single" ? "active" : ""}`}
        >
          Single
        </button>
        <button
          onClick={() => setMode("batch")}
          className={`oc-segmented-option ${mode === "batch" ? "active" : ""}`}
        >
          Batch
        </button>
      </div>

      {/* did:web publication warning */}
      {showDidWebWarning && !didWarningDismissed && (
        <div className="flex items-center gap-3 rounded-lg border border-amber-300 bg-amber-50 px-4 py-3">
          <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-full bg-amber-200">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#92400e" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
            </svg>
          </span>
          <p className="text-sm text-amber-800 flex-1">
            Your DID document hasn't been published yet. Verifiers won't be able to discover your public key.
            {onNavigate && (
              <button
                onClick={() => onNavigate("settings")}
                className="ml-2 text-amber-900 underline hover:text-amber-700 text-sm font-medium bg-transparent border-none cursor-pointer p-0"
              >
                Set Up in Settings
              </button>
            )}
          </p>
          <button
            onClick={() => setDidWarningDismissed(true)}
            className="flex-shrink-0 p-1 rounded hover:bg-amber-200 transition-colors"
            aria-label="Dismiss warning"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#92400e" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
      )}

      {/* Single issuance mode */}
      {mode === "single" && (
        <div className="space-y-4">
          {/* Blank credential: show field builder */}
          {isBlank && (
            <BlankCredentialBuilder onSchemaReady={handleBlankSchemaReady} />
          )}

          {/* Dynamic form fields (for non-blank or after blank fields defined) */}
          {schemaFields.length > 0 && (
            <Card className="space-y-3">
              <h2 className="oc-card-label">Credential Details</h2>
              <div className="space-y-3">
                {schemaFields.map((field) => (
                  <div key={field.name}>
                    <label
                      htmlFor={`field-${field.name}`}
                      className="block text-xs font-medium text-gray-600"
                    >
                      {labelForField(field.name)}
                      {field.required && <span className="text-red-500 ml-0.5">*</span>}
                      {!field.required && <span className="text-gray-400 ml-1 font-normal">(optional)</span>}
                    </label>
                    <input
                      id={`field-${field.name}`}
                      type={inputTypeForField(field)}
                      value={subjectValues[field.name] ?? ""}
                      onChange={(e) =>
                        setSubjectValues((prev) => ({
                          ...prev,
                          [field.name]: e.target.value,
                        }))
                      }
                      required={field.required}
                      disabled={signing}
                      placeholder={`Enter ${labelForField(field.name).toLowerCase()}...`}
                      className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50 disabled:text-gray-400"
                    />
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Issuance settings */}
          <Card className="space-y-3">
            <h2 className="oc-card-label">Issuance Settings</h2>
            <div>
              <label htmlFor="builder-signing-key" className="block text-xs font-medium text-gray-600">
                Signing Key <span className="text-red-500">*</span>
              </label>
              {keys.length === 0 ? (
                <p className="mt-1 text-xs text-gray-400 italic">
                  No keys imported. Go to Settings to import or generate a key.
                </p>
              ) : (
                <select
                  id="builder-signing-key"
                  value={selectedKeyId}
                  onChange={(e) => setSelectedKeyId(e.target.value)}
                  disabled={signing}
                  className="mt-1 block w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
                >
                  {keys.map((key) => (
                    <option key={key.id} value={key.id} title={key.fingerprint}>
                      {key.label ?? key.algorithm} ({formatKeyDate(key.importedAt)})
                    </option>
                  ))}
                </select>
              )}
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label htmlFor="builder-valid-from" className="block text-xs font-medium text-gray-600">
                  Valid From
                </label>
                <input
                  id="builder-valid-from"
                  type="date"
                  value={validFrom}
                  onChange={(e) => setValidFrom(e.target.value)}
                  disabled={signing}
                  className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
                />
              </div>
              <div>
                <label htmlFor="builder-valid-until" className="block text-xs font-medium text-gray-600">
                  Valid Until
                </label>
                <input
                  id="builder-valid-until"
                  type="date"
                  value={validUntil}
                  onChange={(e) => setValidUntil(e.target.value)}
                  disabled={signing}
                  className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500 disabled:bg-gray-50"
                />
              </div>
            </div>
          </Card>

          {/* More Options */}
          <MoreOptions
            keyAlgorithm={selectedKeyAlgorithm}
            proofFormat={proofFormat}
            onProofFormatChange={setProofFormat}
            subjectFieldNames={schemaFields.map((f) => f.name)}
            selectiveDisclosureClaims={selectiveDisclosureClaims}
            onSelectiveDisclosureChange={setSelectiveDisclosureClaims}
            revocationRegistryUrl={revocationRegistryUrl}
            onRevocationRegistryUrlChange={setRevocationRegistryUrl}
            credentialSchemaUrl={credentialSchemaUrl}
            onCredentialSchemaUrlChange={setCredentialSchemaUrl}
            disabled={signing}
          />

          {/* Build & Sign */}
          <Card className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="oc-card-label">Build & Sign</h2>
                <p className="text-xs text-gray-500">
                  Keys never leave this machine. Signing works offline.
                </p>
              </div>
              <Button
                onClick={() => void handleBuildAndSign()}
                disabled={signing || !selectedKeyId || (schemaFields.length === 0 && !isBlank)}
              >
                {signing ? "Signing..." : "Issue Credential"}
              </Button>
            </div>

            {error && <p className="text-sm text-red-600">{error}</p>}

            {signedCredential && resultProofFormat === "sd-jwt-vc" && (
              <SdJwtResult
                signedCredential={signedCredential}
                onExport={() => void handleExportJson()}
              />
            )}

            {signedCredential && resultProofFormat !== "sd-jwt-vc" && (
              <CredentialResult
                signedCredential={signedCredential}
                schemaId={isBlank ? undefined : schemaId}
                schemaName={schemaName}
                onExportJson={() => void handleExportJson()}
                onExportPdf={() => void handleExportPdf()}
                onShowQr={() => void handleShowQr()}
              />
            )}
          </Card>
        </div>
      )}

      {/* Batch issuance mode */}
      {mode === "batch" && (
        <BatchIssuance
          preSelectedSchemaId={isBlank ? undefined : schemaId}
          preSelectedKeyId={selectedKeyId || undefined}
        />
      )}
    </div>
  );
}
