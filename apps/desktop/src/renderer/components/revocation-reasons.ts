/**
 * Predefined revocation reasons and the resolver used by the
 * revocation dialog.
 *
 * The reason is optional end-to-end: the dialog can submit `undefined`
 * when the user does not pick a predefined reason and does not type a
 * free-text "Other" value. The DeDi `revoke` tag schema treats `reason`
 * as optional too, so submitting `undefined` is the canonical "no
 * reason given" signal.
 *
 * Kept as a pure module (no React imports) so the resolver can be unit
 * tested in the node-environment vitest config.
 */

export const OTHER_REASON_KEY = "other" as const;

/**
 * Predefined reason choices surfaced in the dropdown, in display order.
 *
 * `key` is a stable identifier used for radio/dropdown state.
 * `label` is the human-readable text shown in the UI and also the value
 * that ends up persisted as the revocation reason for the four
 * canonical choices.
 */
export interface RevocationReasonOption {
  key: string;
  label: string;
}

export const PREDEFINED_REVOCATION_REASONS: readonly RevocationReasonOption[] = [
  { key: "key-compromised", label: "Key compromised" },
  { key: "issued-in-error", label: "Issued in error" },
  { key: "subject-requested-deletion", label: "Subject requested deletion" },
  { key: "superseded-by-new-credential", label: "Superseded by new credential" },
  { key: OTHER_REASON_KEY, label: "Other" },
] as const;

/** Reason strings are bounded at the IPC layer; this is the same cap. */
export const REVOCATION_REASON_MAX_LENGTH = 1024;

/**
 * Resolve the selected dropdown key and free-text "Other" value into the
 * single reason string that gets persisted in the revocation queue.
 *
 * Rules:
 *  - No selection (`selectedKey` empty / unknown) → `undefined`.
 *  - "Other" with empty / whitespace-only free text → `undefined` (reason
 *    is optional; an "Other" choice with nothing typed shouldn't pretend
 *    to be a real reason).
 *  - "Other" with text → trimmed free text.
 *  - Any other predefined key → the predefined label.
 *
 * The trim on free-text input prevents callers from queueing items with
 * a reason consisting entirely of whitespace, which downstream UIs would
 * render as a blank "Reason: " row.
 */
export function resolveRevocationReason(
  selectedKey: string | undefined,
  freeText: string | undefined,
): string | undefined {
  if (!selectedKey) {
    return undefined;
  }
  if (selectedKey === OTHER_REASON_KEY) {
    const trimmed = freeText?.trim();
    return trimmed ? trimmed : undefined;
  }
  const match = PREDEFINED_REVOCATION_REASONS.find((r) => r.key === selectedKey);
  return match?.label;
}
