/**
 * RevocationPage — surface the revocation queue and let issuers
 * revoke a credential with an optional reason.
 *
 * The reason flows through `window.opencred.queueRevocation` →
 * `revocation-queue` → DeDi's canonical `revoke` tag. It is stored
 * locally alongside the queue item so this page can display
 * "Revoked: <reason>" once a row exists.
 */

import { useCallback, useEffect, useState } from "react";
import { Button } from "./ui/Button";
import { RevocationDialog } from "./RevocationDialog";

interface QueueItem {
  queueId: string;
  credentialId: string;
  registryUrl: string;
  status: string;
  queuedAt: string;
  lastAttemptAt?: string;
  lastError?: string;
  attemptCount: number;
  reason?: string;
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function statusBadgeColor(status: string): { bg: string; fg: string } {
  switch (status) {
    case "published":
      return { bg: "#DCFCE7", fg: "#166534" };
    case "publishing":
      return { bg: "#DBEAFE", fg: "#1E40AF" };
    case "failed":
      return { bg: "#FEE2E2", fg: "#991B1B" };
    default:
      return { bg: "#FEF3C7", fg: "#92400E" };
  }
}

export function RevocationPage() {
  const [items, setItems] = useState<QueueItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [credentialIdInput, setCredentialIdInput] = useState("");
  const [registryUrlInput, setRegistryUrlInput] = useState("");
  const [dialogOpen, setDialogOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | undefined>(undefined);

  const reload = useCallback(async () => {
    try {
      const res = await window.opencred.getRevocationStatus();
      setItems(res.items);
    } catch {
      /* non-fatal — surface via empty state */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  function openDialog() {
    setFormError(undefined);
    if (!credentialIdInput.trim()) {
      setFormError("Enter the credential ID you want to revoke.");
      return;
    }
    if (!registryUrlInput.trim()) {
      setFormError("Enter the revocation registry URL.");
      return;
    }
    setDialogOpen(true);
  }

  async function handleConfirm(reason: string | undefined) {
    setSubmitting(true);
    setFormError(undefined);
    try {
      const result = await window.opencred.queueRevocation({
        credentialId: credentialIdInput.trim(),
        registryUrl: registryUrlInput.trim(),
        reason,
      });
      if (!result.success) {
        setFormError(result.error ?? "Failed to queue revocation.");
        return;
      }
      setCredentialIdInput("");
      setRegistryUrlInput("");
      setDialogOpen(false);
      await reload();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : "Failed to queue revocation.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div>
      <h2 className="oc-page-title" style={{ marginBottom: 16 }}>
        Credential Revocation
      </h2>

      <div
        style={{
          borderRadius: 10,
          border: "1px solid var(--oc-border)",
          background: "var(--oc-surface)",
          padding: 20,
          marginBottom: 20,
        }}
      >
        <h3
          style={{
            fontFamily: "var(--oc-font-mono)",
            fontSize: "0.62rem",
            letterSpacing: "0.1em",
            textTransform: "uppercase",
            color: "var(--oc-text-muted)",
            margin: 0,
            marginBottom: 12,
          }}
        >
          Revoke a credential
        </h3>
        <div style={{ display: "grid", gap: 10 }}>
          <div>
            <label
              htmlFor="rev-credential-id"
              style={{
                display: "block",
                fontFamily: "var(--oc-font-mono)",
                fontSize: "0.6rem",
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: "var(--oc-text-muted)",
                marginBottom: 4,
              }}
            >
              Credential ID
            </label>
            <input
              id="rev-credential-id"
              type="text"
              value={credentialIdInput}
              onChange={(e) => setCredentialIdInput(e.target.value)}
              placeholder="urn:uuid:..."
              style={{
                width: "100%",
                padding: "8px 10px",
                borderRadius: 6,
                border: "1px solid var(--oc-border)",
                background: "var(--oc-surface)",
                color: "var(--oc-text-primary)",
                fontFamily: "var(--oc-font-mono)",
                fontSize: "0.8rem",
              }}
            />
          </div>
          <div>
            <label
              htmlFor="rev-registry-url"
              style={{
                display: "block",
                fontFamily: "var(--oc-font-mono)",
                fontSize: "0.6rem",
                letterSpacing: "0.08em",
                textTransform: "uppercase",
                color: "var(--oc-text-muted)",
                marginBottom: 4,
              }}
            >
              Revocation registry URL
            </label>
            <input
              id="rev-registry-url"
              type="text"
              value={registryUrlInput}
              onChange={(e) => setRegistryUrlInput(e.target.value)}
              placeholder="https://dedi.example/revocations/..."
              style={{
                width: "100%",
                padding: "8px 10px",
                borderRadius: 6,
                border: "1px solid var(--oc-border)",
                background: "var(--oc-surface)",
                color: "var(--oc-text-primary)",
                fontFamily: "var(--oc-font-mono)",
                fontSize: "0.8rem",
              }}
            />
          </div>
          {formError && (
            <p
              role="alert"
              style={{
                margin: 0,
                color: "#991B1B",
                fontFamily: "var(--oc-font-body)",
                fontSize: "0.78rem",
              }}
            >
              {formError}
            </p>
          )}
          <div style={{ display: "flex", justifyContent: "flex-end" }}>
            <Button variant="danger" size="sm" onClick={openDialog} disabled={submitting}>
              Revoke credential…
            </Button>
          </div>
        </div>
      </div>

      <h3
        style={{
          fontFamily: "var(--oc-font-mono)",
          fontSize: "0.62rem",
          letterSpacing: "0.1em",
          textTransform: "uppercase",
          color: "var(--oc-text-muted)",
          margin: 0,
          marginBottom: 10,
        }}
      >
        Revocation history
      </h3>

      {loading ? (
        <p className="text-sm text-gray-400">Loading…</p>
      ) : items.length === 0 ? (
        <p className="text-sm text-gray-400 italic">No revocations queued yet.</p>
      ) : (
        <div
          style={{
            borderRadius: 10,
            border: "1px solid var(--oc-border)",
            background: "var(--oc-surface)",
            overflow: "hidden",
          }}
        >
          {items.map((item, idx) => {
            const badge = statusBadgeColor(item.status);
            return (
              <div
                key={item.queueId}
                style={{
                  padding: "12px 16px",
                  borderTop: idx === 0 ? "none" : "1px solid var(--oc-border-light)",
                  display: "flex",
                  flexDirection: "column",
                  gap: 4,
                }}
              >
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    gap: 8,
                  }}
                >
                  <div
                    style={{
                      fontFamily: "var(--oc-font-mono)",
                      fontSize: "0.78rem",
                      color: "var(--oc-text-primary)",
                      wordBreak: "break-all",
                    }}
                  >
                    {item.credentialId}
                  </div>
                  <span
                    style={{
                      flexShrink: 0,
                      padding: "2px 8px",
                      borderRadius: 999,
                      backgroundColor: badge.bg,
                      color: badge.fg,
                      fontFamily: "var(--oc-font-mono)",
                      fontSize: "0.62rem",
                      letterSpacing: "0.06em",
                      textTransform: "uppercase",
                      fontWeight: 600,
                    }}
                  >
                    {item.status}
                  </span>
                </div>
                <div
                  style={{
                    fontFamily: "var(--oc-font-body)",
                    fontSize: "0.74rem",
                    color: "var(--oc-text-secondary)",
                  }}
                >
                  {item.reason ? (
                    <span>
                      <span style={{ color: "var(--oc-text-muted)" }}>Revoked:</span> {item.reason}
                    </span>
                  ) : (
                    <span style={{ color: "var(--oc-text-muted)" }}>No reason recorded</span>
                  )}
                </div>
                <div
                  style={{
                    fontFamily: "var(--oc-font-mono)",
                    fontSize: "0.66rem",
                    color: "var(--oc-text-muted)",
                  }}
                >
                  Queued {formatDate(item.queuedAt)}
                  {item.lastError ? ` • ${item.lastError}` : ""}
                </div>
              </div>
            );
          })}
        </div>
      )}

      <RevocationDialog
        open={dialogOpen}
        credentialId={credentialIdInput.trim() || undefined}
        submitting={submitting}
        onCancel={() => {
          if (!submitting) setDialogOpen(false);
        }}
        onConfirm={(reason) => void handleConfirm(reason)}
      />
    </div>
  );
}
