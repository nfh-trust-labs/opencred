// @vitest-environment happy-dom
import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CredentialVerifier } from "../renderer/components/CredentialVerifier";

afterEach(() => {
  cleanup();
  // First render test in the desktop app — reset the IPC-bridge stub so it
  // never leaks into a future `.test.tsx` sharing the same module worker.
  delete (window as unknown as { opencred?: unknown }).opencred;
  vi.restoreAllMocks();
});

describe("CredentialVerifier (render)", () => {
  // Phase A of #658: the revocation reason produced by `checkRevocation`
  // (main process) arrives in a check's `detail`; the verifier UI renders
  // `check.detail` verbatim, so the reason must surface end-to-end.
  it("renders the revocation reason carried in a check detail (#658)", async () => {
    const verifyCredential = vi.fn().mockResolvedValue({
      success: true,
      valid: false,
      message: "Invalid.",
      checks: [
        {
          name: "revocation",
          passed: false,
          detail: "Credential revoked at 2026-06-01T00:00:00Z. Reason: Key compromised.",
        },
      ],
    });
    (window as unknown as { opencred: Record<string, unknown> }).opencred = {
      getOfflineStatus: vi.fn().mockResolvedValue(false),
      verifyCredential,
    };

    const user = userEvent.setup();
    render(<CredentialVerifier />);

    await user.type(screen.getByPlaceholderText(/Paste a signed Verifiable Credential/i), "x");
    await user.click(screen.getByRole("button", { name: /^verify$/i }));

    await waitFor(() => {
      expect(screen.getByText(/Reason: Key compromised\./)).toBeTruthy();
    });
    expect(verifyCredential).toHaveBeenCalledTimes(1);
  });
});
