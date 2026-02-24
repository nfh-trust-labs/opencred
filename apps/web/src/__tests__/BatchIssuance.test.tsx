import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { BatchIssuance } from "../components/BatchIssuance";

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("BatchIssuance", () => {
  it("renders the upload form", () => {
    render(<BatchIssuance apiUrl="/api" token="" />);
    expect(screen.getByText(/upload a csv file/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/credential type/i)).toBeInTheDocument();
    expect(screen.getByText(/signing flow/i)).toBeInTheDocument();
    expect(screen.getByText(/click to select csv file/i)).toBeInTheDocument();
  });

  it("defaults to delegated signing flow", () => {
    render(<BatchIssuance apiUrl="/api" token="" />);
    expect(screen.getByLabelText(/delegated signing/i)).toBeChecked();
  });

  it("shows delegation ID field for delegated signing", () => {
    render(<BatchIssuance apiUrl="/api" token="" />);
    expect(screen.getByLabelText(/delegation id/i)).toBeInTheDocument();
  });

  it("shows key import for interface signing", async () => {
    const user = userEvent.setup();
    render(<BatchIssuance apiUrl="/api" token="" />);
    await user.click(screen.getByLabelText(/interface signing/i));
    expect(screen.getByLabelText(/signing key/i)).toBeInTheDocument();
  });

  it("disables submit without all required fields", () => {
    render(<BatchIssuance apiUrl="/api" token="" />);
    expect(screen.getByRole("button", { name: /submit batch job/i })).toBeDisabled();
  });

  it("submits a batch job with CSV", async () => {
    const user = userEvent.setup();
    mockFetch.mockReturnValue(
      Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ jobId: "job-123", totalCredentials: 5, status: "pending" }),
      }),
    );

    render(<BatchIssuance apiUrl="http://localhost:3000" token="tok" />);

    // Select schema
    await user.selectOptions(screen.getByLabelText(/credential type/i), "education");

    // Enter delegation ID
    await user.type(screen.getByLabelText(/delegation id/i), "del-123");

    // Upload CSV — simulate file selection
    const csvContent = "name,degree,institution,dateConferred\nAlice,BSc,MIT,2024-01-01";
    const file = new File([csvContent], "test.csv", { type: "text/csv" });
    const fileInput = screen.getByText(/click to select csv file/i).closest("label")!;
    const input = fileInput.querySelector("input[type='file']") as HTMLInputElement;
    await user.upload(input, file);

    // Submit
    await user.click(screen.getByRole("button", { name: /submit batch job/i }));

    // Should show submitting/progress
    expect(mockFetch).toHaveBeenCalled();
  });
});
