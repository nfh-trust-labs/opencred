import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { RevocationPage } from "../components/RevocationPage";

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

describe("RevocationPage", () => {
  it("renders single and batch mode tabs", () => {
    render(<RevocationPage apiUrl="/api" token="" />);
    expect(screen.getByText(/single revocation/i)).toBeInTheDocument();
    expect(screen.getByText(/batch revocation/i)).toBeInTheDocument();
  });

  it("defaults to single revocation mode with hash input", () => {
    render(<RevocationPage apiUrl="/api" token="" />);
    expect(screen.getByRole("textbox", { name: /credential hash/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /revoke credential/i })).toBeInTheDocument();
  });

  it("disables revoke button when input is empty", () => {
    render(<RevocationPage apiUrl="/api" token="" />);
    expect(screen.getByRole("button", { name: /revoke credential/i })).toBeDisabled();
  });

  it("switches to credential JSON input mode", async () => {
    const user = userEvent.setup();
    render(<RevocationPage apiUrl="/api" token="" />);
    await user.click(screen.getByRole("radio", { name: /credential json/i }));
    expect(screen.getByRole("radio", { name: /credential json/i })).toBeChecked();
  });

  it("revokes a credential by hash", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(jsonResponse({ revoked: true, hash: "abc-hash" }));

    render(<RevocationPage apiUrl="http://localhost:3000" token="" />);
    await user.type(screen.getByRole("textbox", { name: /credential hash/i }), "abc-hash");
    await user.click(screen.getByRole("button", { name: /revoke credential/i }));

    expect(await screen.findByText(/credential revoked successfully/i)).toBeInTheDocument();
    expect(screen.getByText(/abc-hash/)).toBeInTheDocument();
  });

  it("shows error on revocation failure", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({ error: { code: "NOT_FOUND", message: "Credential not found" } }, 404),
    );

    render(<RevocationPage apiUrl="http://localhost:3000" token="" />);
    await user.type(screen.getByRole("textbox", { name: /credential hash/i }), "nonexistent");
    await user.click(screen.getByRole("button", { name: /revoke credential/i }));

    expect(await screen.findByText("Credential not found")).toBeInTheDocument();
  });

  it("switches to batch mode", async () => {
    const user = userEvent.setup();
    render(<RevocationPage apiUrl="/api" token="" />);
    await user.click(screen.getByText(/batch revocation/i));
    expect(screen.getByLabelText(/credential hashes/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /revoke all/i })).toBeInTheDocument();
  });

  it("performs batch revocation", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({
        results: [
          { hash: "hash1", revoked: true },
          { hash: "hash2", revoked: false, error: "Not found" },
        ],
      }),
    );

    render(<RevocationPage apiUrl="http://localhost:3000" token="" />);
    await user.click(screen.getByText(/batch revocation/i));

    const textarea = screen.getByLabelText(/credential hashes/i);
    fireEvent.change(textarea, { target: { value: "hash1\nhash2" } });
    await user.click(screen.getByRole("button", { name: /revoke all/i }));

    expect(await screen.findByText(/1\/2 revoked/i)).toBeInTheDocument();
    expect(screen.getByText("hash1")).toBeInTheDocument();
    expect(screen.getByText("hash2")).toBeInTheDocument();
  });
});
