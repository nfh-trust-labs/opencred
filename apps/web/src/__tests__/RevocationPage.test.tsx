import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { RevocationPage } from "../components/RevocationPage";

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
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
    expect(screen.getByText(/single hash/i)).toBeInTheDocument();
    expect(screen.getByText(/batch hashes/i)).toBeInTheDocument();
  });

  it("defaults to single hash mode with credential JSON input", () => {
    render(<RevocationPage apiUrl="/api" token="" />);
    expect(screen.getByRole("textbox", { name: /credential json/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /compute hash/i })).toBeInTheDocument();
  });

  it("disables compute hash button when input is empty", () => {
    render(<RevocationPage apiUrl="/api" token="" />);
    expect(screen.getByRole("button", { name: /compute hash/i })).toBeDisabled();
  });

  it("computes hash from credential JSON via API", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(jsonResponse({ hash: "computed-hash-xyz" }));

    render(<RevocationPage apiUrl="http://localhost:3000" token="" />);

    const textarea = screen.getByRole("textbox", { name: /credential json/i });
    fireEvent.change(textarea, { target: { value: '{"type":"VC"}' } });
    await user.click(screen.getByRole("button", { name: /compute hash/i }));

    expect(await screen.findByText("computed-hash-xyz")).toBeInTheDocument();
    expect(screen.getByText(/publish this hash to your dedi revocation registry/i)).toBeInTheDocument();
  });

  it("shows copy to clipboard button after hash computed", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(jsonResponse({ hash: "computed-hash-xyz" }));

    render(<RevocationPage apiUrl="http://localhost:3000" token="" />);

    const textarea = screen.getByRole("textbox", { name: /credential json/i });
    fireEvent.change(textarea, { target: { value: '{"type":"VC"}' } });
    await user.click(screen.getByRole("button", { name: /compute hash/i }));

    const copyBtn = await screen.findByRole("button", { name: /copy to clipboard/i });
    expect(copyBtn).toBeInTheDocument();
  });

  it("shows error on hash computation failure", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({ error: { code: "VALIDATION_ERROR", message: "Invalid credential" } }, 400),
    );

    render(<RevocationPage apiUrl="http://localhost:3000" token="" />);

    const textarea = screen.getByRole("textbox", { name: /credential json/i });
    fireEvent.change(textarea, { target: { value: '{"type":"VC"}' } });
    await user.click(screen.getByRole("button", { name: /compute hash/i }));

    expect(await screen.findByText("Invalid credential")).toBeInTheDocument();
  });

  it("shows error for invalid JSON", async () => {
    const user = userEvent.setup();
    render(<RevocationPage apiUrl="http://localhost:3000" token="" />);

    const textarea = screen.getByRole("textbox", { name: /credential json/i });
    await user.clear(textarea);
    await user.type(textarea, "not valid json");
    await user.click(screen.getByRole("button", { name: /compute hash/i }));

    expect(await screen.findByText(/invalid json/i)).toBeInTheDocument();
  });

  it("switches to batch mode", async () => {
    const user = userEvent.setup();
    render(<RevocationPage apiUrl="/api" token="" />);
    await user.click(screen.getByText(/batch hashes/i));
    expect(screen.getByLabelText(/credential jsons/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /compute hashes/i })).toBeInTheDocument();
  });

  it("performs batch hash computation", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({
        hashes: [
          { hash: "hash-a", index: 0 },
          { hash: "hash-b", index: 1 },
        ],
      }),
    );

    render(<RevocationPage apiUrl="http://localhost:3000" token="" />);
    await user.click(screen.getByText(/batch hashes/i));

    const textarea = screen.getByLabelText(/credential jsons/i);
    const creds = JSON.stringify([{ type: "VC1" }, { type: "VC2" }]);
    fireEvent.change(textarea, { target: { value: creds } });
    await user.click(screen.getByRole("button", { name: /compute hashes/i }));

    expect(await screen.findByText(/computed hashes/i)).toBeInTheDocument();
    expect(screen.getByText("hash-a")).toBeInTheDocument();
    expect(screen.getByText("hash-b")).toBeInTheDocument();
    expect(screen.getByText(/publish these hashes to your dedi revocation registry/i)).toBeInTheDocument();
  });
});
