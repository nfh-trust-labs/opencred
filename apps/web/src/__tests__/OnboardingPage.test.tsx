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
  it("renders two onboarding type tabs and Type A info banner", () => {
    render(<OnboardingPage apiUrl="/api" token="" />);
    expect(screen.getByText(/issuers with an existing dsc/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /type b/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /type d/i })).toBeInTheDocument();
  });

  it("defaults to Type B domain verification", () => {
    render(<OnboardingPage apiUrl="/api" token="" />);
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

  it("shows API error for Type B domain challenge", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({ error: { code: "VALIDATION_ERROR", message: "Invalid domain" } }, 400),
    );

    render(<OnboardingPage apiUrl="http://localhost:3000" token="" />);
    await user.type(screen.getByLabelText(/^domain$/i), "bad-domain");
    await user.click(screen.getByRole("button", { name: /request challenge/i }));

    expect(await screen.findByText("Invalid domain")).toBeInTheDocument();
  });
});
