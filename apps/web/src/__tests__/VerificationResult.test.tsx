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
});
