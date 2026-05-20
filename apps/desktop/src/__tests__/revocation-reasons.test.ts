/**
 * Tests for the revocation reason resolver.
 *
 * The dialog has a dropdown of predefined reasons plus a free-text
 * "Other" option. `resolveRevocationReason` is the pure function the
 * dialog calls on submit; these tests pin its behaviour so the UI can
 * stay thin.
 */

import { describe, it, expect } from "vitest";
import {
  OTHER_REASON_KEY,
  PREDEFINED_REVOCATION_REASONS,
  REVOCATION_REASON_MAX_LENGTH,
  resolveRevocationReason,
} from "../renderer/components/revocation-reasons";

describe("resolveRevocationReason", () => {
  it("returns undefined when no key is selected", () => {
    expect(resolveRevocationReason(undefined, undefined)).toBeUndefined();
    expect(resolveRevocationReason("", "")).toBeUndefined();
  });

  it("returns the predefined label for a known key", () => {
    expect(resolveRevocationReason("key-compromised", "")).toBe("Key compromised");
    expect(resolveRevocationReason("issued-in-error", "")).toBe("Issued in error");
    expect(resolveRevocationReason("subject-requested-deletion", "")).toBe(
      "Subject requested deletion",
    );
    expect(resolveRevocationReason("superseded-by-new-credential", "")).toBe(
      "Superseded by new credential",
    );
  });

  it("ignores the free-text field for predefined keys", () => {
    // Free text is only consulted when "Other" is picked. For predefined
    // keys we always emit the canonical label, even if the user typed
    // something into the textarea before switching back.
    expect(resolveRevocationReason("key-compromised", "stray text")).toBe("Key compromised");
  });

  it("returns the trimmed free text when Other is selected", () => {
    expect(resolveRevocationReason(OTHER_REASON_KEY, "  Out-of-band rotation  ")).toBe(
      "Out-of-band rotation",
    );
  });

  it("returns undefined when Other is selected with empty or whitespace text", () => {
    // Reason is optional — an "Other" pick with nothing typed must not
    // produce a blank-but-truthy reason that downstream UIs would render
    // as "Reason: ".
    expect(resolveRevocationReason(OTHER_REASON_KEY, "")).toBeUndefined();
    expect(resolveRevocationReason(OTHER_REASON_KEY, "   ")).toBeUndefined();
    expect(resolveRevocationReason(OTHER_REASON_KEY, undefined)).toBeUndefined();
  });

  it("returns undefined for an unknown key", () => {
    expect(resolveRevocationReason("not-a-real-key", "")).toBeUndefined();
  });

  it("exposes the predefined options including Other", () => {
    const keys = PREDEFINED_REVOCATION_REASONS.map((r) => r.key);
    expect(keys).toContain("key-compromised");
    expect(keys).toContain("issued-in-error");
    expect(keys).toContain("subject-requested-deletion");
    expect(keys).toContain("superseded-by-new-credential");
    expect(keys).toContain(OTHER_REASON_KEY);
  });

  it("has a sensible upper bound to keep IPC payloads small", () => {
    // Sanity check — the IPC schema enforces this length, but the
    // constant lives in the reason module so the dialog can clamp the
    // textarea to match.
    expect(REVOCATION_REASON_MAX_LENGTH).toBeGreaterThanOrEqual(256);
    expect(REVOCATION_REASON_MAX_LENGTH).toBeLessThanOrEqual(8192);
  });
});
