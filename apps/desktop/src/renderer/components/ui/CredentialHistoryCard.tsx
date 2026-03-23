/**
 * CredentialHistoryCard — editorial mini-card for recent credentials.
 *
 * Features a type-specific gradient accent bar at top, schema icon,
 * and two clean actions: View (opens detail modal) and Reissue.
 */

import { getVisual } from "./TemplateCard";

interface Props {
  schemaId?: string;
  schemaName: string;
  subjectSummary: string;
  issuedAt: string;
  onView: () => void;
  onReissue: () => void;
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

function timeAgo(iso: string): string {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return "Just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    if (days < 7) return `${days}d ago`;
    return formatDate(iso);
  } catch {
    return formatDate(iso);
  }
}

export function CredentialHistoryCard({
  schemaId,
  schemaName,
  subjectSummary,
  issuedAt,
  onView,
  onReissue,
}: Props) {
  const v = getVisual(schemaId);

  return (
    <div
      className="group"
      style={{
        borderRadius: 12,
        overflow: "hidden",
        backgroundColor: "var(--oc-surface)",
        border: "1px solid var(--oc-border)",
        transition: "box-shadow 0.25s ease, transform 0.25s ease, border-color 0.25s ease",
        cursor: "pointer",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.boxShadow = `0 8px 24px -4px ${v.fg}18, 0 2px 8px rgba(0,0,0,0.04)`;
        e.currentTarget.style.transform = "translateY(-2px)";
        e.currentTarget.style.borderColor = `${v.border}80`;
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.boxShadow = "none";
        e.currentTarget.style.transform = "none";
        e.currentTarget.style.borderColor = "var(--oc-border)";
      }}
      onClick={onView}
    >
      {/* Gradient accent bar */}
      <div
        style={{
          height: 4,
          background: `linear-gradient(90deg, ${v.fg}, ${v.border})`,
        }}
      />

      {/* Card body */}
      <div style={{ padding: "16px 18px 14px" }}>
        {/* Top row: icon + meta */}
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              width: 38,
              height: 38,
              borderRadius: 10,
              backgroundColor: v.bg,
              color: v.fg,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              flexShrink: 0,
            }}
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5}>
              {v.icon.props.children}
            </svg>
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{
                fontFamily: "var(--oc-font-mono)",
                fontSize: "0.58rem",
                letterSpacing: "0.08em",
                textTransform: "uppercase" as const,
                color: v.fg,
                fontWeight: 600,
              }}
            >
              {schemaName}
            </div>
            <div
              style={{
                fontFamily: "var(--oc-font-body)",
                fontSize: "0.88rem",
                fontWeight: 500,
                color: "var(--oc-text-primary)",
                marginTop: 2,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap" as const,
              }}
            >
              {subjectSummary}
            </div>
          </div>
        </div>

        {/* Bottom row: date + actions */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            marginTop: 14,
            paddingTop: 12,
            borderTop: "1px solid var(--oc-border-light)",
          }}
        >
          <span
            style={{
              fontFamily: "var(--oc-font-mono)",
              fontSize: "0.62rem",
              color: "var(--oc-text-muted)",
              letterSpacing: "0.02em",
            }}
          >
            {timeAgo(issuedAt)}
          </span>

          <div style={{ display: "flex", gap: 6 }}>
            {/* View button */}
            <button
              onClick={(e) => { e.stopPropagation(); onView(); }}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
                padding: "5px 12px",
                borderRadius: 6,
                border: "1px solid var(--oc-border)",
                background: "none",
                fontFamily: "var(--oc-font-body)",
                fontSize: "0.72rem",
                fontWeight: 500,
                color: "var(--oc-text-secondary)",
                cursor: "pointer",
                transition: "all 0.15s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = v.fg;
                e.currentTarget.style.color = v.fg;
                e.currentTarget.style.backgroundColor = v.bg;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = "var(--oc-border)";
                e.currentTarget.style.color = "var(--oc-text-secondary)";
                e.currentTarget.style.backgroundColor = "transparent";
              }}
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
              View
            </button>

            {/* Reissue button */}
            <button
              onClick={(e) => { e.stopPropagation(); onReissue(); }}
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: 4,
                padding: "5px 12px",
                borderRadius: 6,
                border: "none",
                background: v.fg,
                fontFamily: "var(--oc-font-body)",
                fontSize: "0.72rem",
                fontWeight: 600,
                color: "#fff",
                cursor: "pointer",
                transition: "all 0.15s",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.filter = "brightness(1.15)";
                e.currentTarget.style.boxShadow = `0 2px 8px ${v.fg}40`;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.filter = "none";
                e.currentTarget.style.boxShadow = "none";
              }}
            >
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182M20.016 4.657v4.992" />
              </svg>
              Reissue
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
