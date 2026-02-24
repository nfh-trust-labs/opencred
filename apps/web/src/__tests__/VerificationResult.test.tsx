import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { VerificationResult } from "../components/VerificationResult";
import type { VerifyResponse } from "../api/client";

function makeResult(overrides: Partial<VerifyResponse> = {}): VerifyResponse {
  return {
    status: "VALID",
    checks: {
      signature: { passed: true },
      expiry: { passed: true },
      revocation: { passed: true },
    },
    ...overrides,
  };
}

describe("VerificationResult", () => {
  it("displays VALID status", () => {
    render(<VerificationResult result={makeResult()} />);
    expect(screen.getByTestId("verification-status")).toHaveTextContent("VALID");
  });

  it("displays INVALID status", () => {
    render(
      <VerificationResult
        result={makeResult({
          status: "INVALID",
          checks: {
            signature: { passed: false, detail: "Signature mismatch" },
            expiry: { passed: true },
            revocation: { passed: true },
          },
        })}
      />,
    );
    expect(screen.getByTestId("verification-status")).toHaveTextContent("INVALID");
  });

  it("displays REVOKED status", () => {
    render(<VerificationResult result={makeResult({ status: "REVOKED" })} />);
    expect(screen.getByTestId("verification-status")).toHaveTextContent("REVOKED");
  });

  it("displays EXPIRED status", () => {
    render(<VerificationResult result={makeResult({ status: "EXPIRED" })} />);
    expect(screen.getByTestId("verification-status")).toHaveTextContent("EXPIRED");
  });

  it("displays UNRESOLVABLE status", () => {
    render(<VerificationResult result={makeResult({ status: "UNRESOLVABLE" })} />);
    expect(screen.getByTestId("verification-status")).toHaveTextContent("UNRESOLVABLE");
  });

  it("displays DELEGATION_INVALID status", () => {
    render(
      <VerificationResult
        result={makeResult({
          status: "DELEGATION_INVALID",
          checks: {
            signature: { passed: true },
            expiry: { passed: true },
            revocation: { passed: true },
            delegation: { passed: false, detail: "Delegation expired" },
          },
        })}
      />,
    );
    expect(screen.getByTestId("verification-status")).toHaveTextContent("DELEGATION INVALID");
    expect(screen.getByText("Delegation expired")).toBeInTheDocument();
  });

  it("shows check details when present", () => {
    render(
      <VerificationResult
        result={makeResult({
          checks: {
            signature: { passed: true },
            expiry: { passed: false, detail: "Credential has expired" },
            revocation: { passed: true },
          },
        })}
      />,
    );
    expect(screen.getByText("Credential has expired")).toBeInTheDocument();
  });

  it("renders DSC chain check when present", () => {
    render(
      <VerificationResult
        result={makeResult({
          checks: {
            signature: { passed: true },
            expiry: { passed: true },
            revocation: { passed: true },
            dscChain: { passed: true },
          },
        })}
      />,
    );
    expect(screen.getByText("DSC chain")).toBeInTheDocument();
  });

  it("renders delegation check when present", () => {
    render(
      <VerificationResult
        result={makeResult({
          checks: {
            signature: { passed: true },
            expiry: { passed: true },
            revocation: { passed: true },
            delegation: { passed: true },
          },
        })}
      />,
    );
    expect(screen.getByText("delegation")).toBeInTheDocument();
  });

  it("renders delegation chain details", () => {
    render(
      <VerificationResult
        result={makeResult({
          delegationChain: [
            {
              delegationId: "del-abc",
              issuer: "did:key:z123",
              scope: ["education"],
              validFrom: "2024-01-01",
              validUntil: "2025-01-01",
            },
            {
              delegationId: "del-def",
              issuer: "did:key:z456",
              scope: ["education", "health"],
              validFrom: "2024-06-01",
              validUntil: "2025-06-01",
            },
          ],
        })}
      />,
    );
    expect(screen.getByText("Delegation Chain")).toBeInTheDocument();
    expect(screen.getByText("del-abc")).toBeInTheDocument();
    expect(screen.getByText("del-def")).toBeInTheDocument();
    expect(screen.getByText("did:key:z123")).toBeInTheDocument();
    expect(screen.getByText("did:key:z456")).toBeInTheDocument();
    expect(screen.getByText("Level 1")).toBeInTheDocument();
    expect(screen.getByText("Level 2")).toBeInTheDocument();
  });

  it("does not render delegation chain when empty", () => {
    render(<VerificationResult result={makeResult({ delegationChain: [] })} />);
    expect(screen.queryByText("Delegation Chain")).not.toBeInTheDocument();
  });
});
