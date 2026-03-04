import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { CredentialVerifier } from "../components/CredentialVerifier";

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

function setTextareaValue(textarea: HTMLElement, value: string) {
  fireEvent.change(textarea, { target: { value } });
}

describe("CredentialVerifier", () => {
  it("renders the JSON input and verify button", () => {
    render(<CredentialVerifier apiUrl="/api" token="" />);
    expect(screen.getByLabelText(/verifiable credential/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /verify/i })).toBeInTheDocument();
  });

  it("shows error for invalid JSON", async () => {
    const user = userEvent.setup();
    render(<CredentialVerifier apiUrl="/api" token="" />);
    await user.type(screen.getByLabelText(/verifiable credential/i), "not json");
    await user.click(screen.getByRole("button", { name: /verify/i }));
    expect(screen.getByText(/unrecognized format/i)).toBeInTheDocument();
  });

  it("displays verification result on success", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            status: "VALID",
            checks: {
              signature: { passed: true },
              expiry: { passed: true },
              revocation: { passed: true },
            },
          }),
      }),
    );

    render(<CredentialVerifier apiUrl="http://localhost:3000" token="" />);
    const textarea = screen.getByLabelText(/verifiable credential/i);
    setTextareaValue(textarea, '{"@context":[],"type":"VerifiableCredential"}');
    await user.click(screen.getByRole("button", { name: /verify/i }));

    expect(await screen.findByTestId("verification-status")).toHaveTextContent("VALID");
  });

  it("displays API errors", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: false,
        status: 400,
        json: () =>
          Promise.resolve({ error: { code: "VALIDATION_ERROR", message: "Bad credential" } }),
      }),
    );

    render(<CredentialVerifier apiUrl="http://localhost:3000" token="" />);
    const textarea = screen.getByLabelText(/verifiable credential/i);
    setTextareaValue(textarea, '{"type":"test"}');
    await user.click(screen.getByRole("button", { name: /verify/i }));

    expect(await screen.findByText("Bad credential")).toBeInTheDocument();
  });

  it("disables verify button when textarea is empty", () => {
    render(<CredentialVerifier apiUrl="/api" token="" />);
    expect(screen.getByRole("button", { name: /verify/i })).toBeDisabled();
  });
});
