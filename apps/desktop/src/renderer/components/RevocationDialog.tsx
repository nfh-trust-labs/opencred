/**
 * RevocationDialog — confirmation modal for revoking a credential.
 *
 * Captures an optional reason via a dropdown of predefined reasons plus
 * a free-text "Other" field. Submitting without a reason is allowed:
 * the dialog calls `onConfirm(undefined)` and the rest of the
 * revocation pipeline (queue, IPC, DeDi) already handles a missing
 * `reason`.
 */

import { useEffect, useId, useState } from "react";
import { Button } from "./ui/Button";
import {
  OTHER_REASON_KEY,
  PREDEFINED_REVOCATION_REASONS,
  REVOCATION_REASON_MAX_LENGTH,
  resolveRevocationReason,
} from "./revocation-reasons";

interface Props {
  open: boolean;
  /** Identifier shown in the modal header for confirmation context. */
  credentialId?: string;
  /** Disable the confirm button while a parent submit is in flight. */
  submitting?: boolean;
  onCancel: () => void;
  onConfirm: (reason: string | undefined) => void;
}

export function RevocationDialog({
  open,
  credentialId,
  submitting = false,
  onCancel,
  onConfirm,
}: Props) {
  const [selectedKey, setSelectedKey] = useState<string>("");
  const [freeText, setFreeText] = useState<string>("");
  const reasonSelectId = useId();
  const reasonTextId = useId();

  useEffect(() => {
    if (!open) {
      setSelectedKey("");
      setFreeText("");
    }
  }, [open]);

  if (!open) {
    return null;
  }

  function handleConfirm() {
    const reason = resolveRevocationReason(selectedKey, freeText);
    onConfirm(reason);
  }

  const showOtherField = selectedKey === OTHER_REASON_KEY;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="revocation-dialog-title"
      style={{
        position: "fixed",
        inset: 0,
        zIndex: 1100,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        backgroundColor: "rgba(0,0,0,0.4)",
        backdropFilter: "blur(4px)",
      }}
      onClick={onCancel}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: "100%",
          maxWidth: 460,
          borderRadius: 14,
          backgroundColor: "var(--oc-surface)",
          padding: "24px 28px 20px",
          boxShadow: "0 24px 64px -12px rgba(0,0,0,0.25), 0 8px 24px rgba(0,0,0,0.12)",
        }}
      >
        <h3
          id="revocation-dialog-title"
          style={{
            fontFamily: "var(--oc-font-display)",
            fontSize: "1.1rem",
            margin: 0,
            marginBottom: 6,
            color: "var(--oc-text-primary)",
            fontWeight: 500,
          }}
        >
          Revoke credential
        </h3>
        {credentialId && (
          <p
            style={{
              fontFamily: "var(--oc-font-mono)",
              fontSize: "0.72rem",
              color: "var(--oc-text-muted)",
              margin: 0,
              marginBottom: 14,
              wordBreak: "break-all",
            }}
            aria-label="Credential being revoked"
          >
            {credentialId}
          </p>
        )}
        <p
          style={{
            fontFamily: "var(--oc-font-body)",
            fontSize: "0.82rem",
            color: "var(--oc-text-secondary)",
            margin: 0,
            marginBottom: 16,
          }}
        >
          Revoking marks this credential as no longer valid. The optional reason is published with
          the revocation record.
        </p>

        <label
          htmlFor={reasonSelectId}
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
          Reason for revocation (optional)
        </label>
        <select
          id={reasonSelectId}
          value={selectedKey}
          onChange={(e) => setSelectedKey(e.target.value)}
          style={{
            width: "100%",
            padding: "8px 10px",
            borderRadius: 6,
            border: "1px solid var(--oc-border)",
            background: "var(--oc-surface)",
            color: "var(--oc-text-primary)",
            fontFamily: "var(--oc-font-body)",
            fontSize: "0.85rem",
          }}
        >
          <option value="">— No reason —</option>
          {PREDEFINED_REVOCATION_REASONS.map((r) => (
            <option key={r.key} value={r.key}>
              {r.label}
            </option>
          ))}
        </select>

        {showOtherField && (
          <div style={{ marginTop: 12 }}>
            <label
              htmlFor={reasonTextId}
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
              Describe the reason
            </label>
            <textarea
              id={reasonTextId}
              value={freeText}
              onChange={(e) => setFreeText(e.target.value)}
              maxLength={REVOCATION_REASON_MAX_LENGTH}
              rows={3}
              placeholder="Optional — leave blank if you do not want to record a reason."
              style={{
                width: "100%",
                padding: "8px 10px",
                borderRadius: 6,
                border: "1px solid var(--oc-border)",
                background: "var(--oc-surface)",
                color: "var(--oc-text-primary)",
                fontFamily: "var(--oc-font-body)",
                fontSize: "0.85rem",
                resize: "vertical",
              }}
            />
          </div>
        )}

        <div
          style={{
            display: "flex",
            justifyContent: "flex-end",
            gap: 8,
            marginTop: 20,
          }}
        >
          <Button variant="secondary" size="sm" onClick={onCancel} disabled={submitting}>
            Cancel
          </Button>
          <Button variant="danger" size="sm" onClick={handleConfirm} disabled={submitting}>
            {submitting ? "Revoking…" : "Revoke credential"}
          </Button>
        </div>
      </div>
    </div>
  );
}
