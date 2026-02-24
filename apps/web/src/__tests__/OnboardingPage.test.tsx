import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { OnboardingPage } from "../components/OnboardingPage";

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

function jsonResponse(data: unknown, status = 200) {
  return Promise.resolve({
    ok: status >= 200 && status < 300,
    status,
    json: () => Promise.resolve(data),
  });
}

describe("OnboardingPage", () => {
  it("renders three onboarding type tabs", () => {
    render(<OnboardingPage apiUrl="/api" token="" />);
    expect(screen.getByRole("button", { name: /type a/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /type b/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /type d/i })).toBeInTheDocument();
  });

  it("defaults to Type A DSC onboarding", () => {
    render(<OnboardingPage apiUrl="/api" token="" />);
    expect(screen.getByLabelText(/dsc certificate chain/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /submit dsc chain/i })).toBeInTheDocument();
  });

  it("submits Type A DSC chain", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(jsonResponse({ issuerId: "issuer-123", status: "active" }));

    render(<OnboardingPage apiUrl="http://localhost:3000" token="" />);
    const textarea = screen.getByLabelText(/dsc certificate chain/i);
    fireEvent.change(textarea, {
      target: { value: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----" },
    });
    await user.click(screen.getByRole("button", { name: /submit dsc chain/i }));

    expect(await screen.findByText(/onboarding successful/i)).toBeInTheDocument();
    expect(screen.getByText(/issuer-123/)).toBeInTheDocument();
  });

  it("switches to Type B domain verification", async () => {
    const user = userEvent.setup();
    render(<OnboardingPage apiUrl="/api" token="" />);
    await user.click(screen.getByRole("button", { name: /type b/i }));
    expect(screen.getByLabelText(/^domain$/i)).toBeInTheDocument();
    expect(screen.getByRole("radio", { name: /dns txt record/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /request challenge/i })).toBeInTheDocument();
  });

  it("requests domain challenge for Type B", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({
        challengeId: "ch-123",
        challengeType: "dns",
        challengeValue: "opencred-verify=abc123",
        instructions: "Add this TXT record to your DNS",
      }),
    );

    render(<OnboardingPage apiUrl="http://localhost:3000" token="" />);
    await user.click(screen.getByRole("button", { name: /type b/i }));
    await user.type(screen.getByLabelText(/^domain$/i), "example.com");
    await user.click(screen.getByRole("button", { name: /request challenge/i }));

    expect(await screen.findByText(/challenge created/i)).toBeInTheDocument();
    expect(screen.getByText(/opencred-verify=abc123/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /confirm verification/i })).toBeInTheDocument();
  });

  it("switches to Type D business VC onboarding", async () => {
    const user = userEvent.setup();
    render(<OnboardingPage apiUrl="/api" token="" />);
    await user.click(screen.getByRole("button", { name: /type d/i }));
    expect(screen.getByLabelText(/business verifiable credential/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /submit business vc/i })).toBeInTheDocument();
  });

  it("submits Type D business VC and shows delegation info", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({
        delegationId: "del-999",
        issuerId: "issuer-456",
        capabilityToken: "cap-tok-xyz",
        scope: ["education", "employment"],
        validFrom: "2024-01-01T00:00:00Z",
        validUntil: "2025-01-01T00:00:00Z",
      }),
    );

    render(<OnboardingPage apiUrl="http://localhost:3000" token="" />);
    await user.click(screen.getByRole("button", { name: /type d/i }));

    const textarea = screen.getByLabelText(/business verifiable credential/i);
    fireEvent.change(textarea, {
      target: { value: '{"@context":[],"type":"VerifiableCredential"}' },
    });

    await user.click(screen.getByRole("button", { name: /submit business vc/i }));

    expect(await screen.findByText(/onboarding successful/i)).toBeInTheDocument();
    expect(screen.getByText(/del-999/)).toBeInTheDocument();
    expect(screen.getByText(/issuer-456/)).toBeInTheDocument();
    expect(screen.getByText(/education, employment/)).toBeInTheDocument();
  });

  it("shows error for invalid JSON in Type D", async () => {
    const user = userEvent.setup();
    render(<OnboardingPage apiUrl="/api" token="" />);
    await user.click(screen.getByRole("button", { name: /type d/i }));

    const textarea = screen.getByLabelText(/business verifiable credential/i);
    fireEvent.change(textarea, { target: { value: "not json" } });

    await user.click(screen.getByRole("button", { name: /submit business vc/i }));

    expect(await screen.findByText(/invalid json/i)).toBeInTheDocument();
  });

  it("shows API error for Type A", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({ error: { code: "VALIDATION_ERROR", message: "Invalid certificate" } }, 400),
    );

    render(<OnboardingPage apiUrl="http://localhost:3000" token="" />);
    const textarea = screen.getByLabelText(/dsc certificate chain/i);
    fireEvent.change(textarea, { target: { value: "bad-cert" } });
    await user.click(screen.getByRole("button", { name: /submit dsc chain/i }));

    expect(await screen.findByText("Invalid certificate")).toBeInTheDocument();
  });
});
