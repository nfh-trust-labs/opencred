import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DelegatedIssuance } from "../components/DelegatedIssuance";

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

describe("DelegatedIssuance", () => {
  it("renders the delegation ID input in setup step", () => {
    render(<DelegatedIssuance apiUrl="/api" token="" />);
    expect(screen.getByLabelText(/delegation id/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /continue/i })).toBeInTheDocument();
  });

  it("disables continue when delegation ID is empty", () => {
    render(<DelegatedIssuance apiUrl="/api" token="" />);
    expect(screen.getByRole("button", { name: /continue/i })).toBeDisabled();
  });

  it("advances to form step when delegation ID is provided", async () => {
    const user = userEvent.setup();
    render(<DelegatedIssuance apiUrl="/api" token="" />);
    await user.type(screen.getByLabelText(/delegation id/i), "del-123");
    await user.click(screen.getByRole("button", { name: /continue/i }));
    expect(screen.getByLabelText(/credential type/i)).toBeInTheDocument();
    expect(screen.getByText(/del-123/)).toBeInTheDocument();
  });

  it("shows info banner about delegated signing", () => {
    render(<DelegatedIssuance apiUrl="/api" token="" />);
    expect(screen.getByText(/delegated issuance uses/i)).toBeInTheDocument();
  });

  it("issues a credential via delegated signing", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({
        credential: { "@context": [], type: "VerifiableCredential" },
        credentialHash: "hash-abc",
      }),
    );

    render(<DelegatedIssuance apiUrl="http://localhost:3000" token="tok" />);

    // Step 1: enter delegation ID
    await user.type(screen.getByLabelText(/delegation id/i), "del-xyz");
    await user.click(screen.getByRole("button", { name: /continue/i }));

    // Step 2: select schema and fill form
    await user.selectOptions(screen.getByLabelText(/credential type/i), "education");
    await user.type(screen.getByLabelText(/^name/i), "Alice");
    await user.type(screen.getByLabelText(/degree/i), "BSc");
    await user.type(screen.getByLabelText(/institution/i), "MIT");
    fireEvent.change(screen.getByLabelText(/date conferred/i), {
      target: { value: "2024-01-01" },
    });

    // Step 3: issue
    await user.click(screen.getByRole("button", { name: /issue credential/i }));

    // Should show success
    expect(await screen.findByText(/credential issued via delegated signing/i)).toBeInTheDocument();
    expect(screen.getByText(/hash-abc/)).toBeInTheDocument();
  });

  it("shows error on API failure", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      jsonResponse({ error: { code: "DELEGATION_ERROR", message: "Invalid delegation" } }, 403),
    );

    render(<DelegatedIssuance apiUrl="http://localhost:3000" token="" />);

    await user.type(screen.getByLabelText(/delegation id/i), "bad-del");
    await user.click(screen.getByRole("button", { name: /continue/i }));
    await user.selectOptions(screen.getByLabelText(/credential type/i), "education");
    await user.type(screen.getByLabelText(/^name/i), "Alice");
    await user.type(screen.getByLabelText(/degree/i), "BSc");
    await user.type(screen.getByLabelText(/institution/i), "MIT");
    fireEvent.change(screen.getByLabelText(/date conferred/i), {
      target: { value: "2024-01-01" },
    });

    await user.click(screen.getByRole("button", { name: /issue credential/i }));

    expect(await screen.findByText("Invalid delegation")).toBeInTheDocument();
  });
});
