import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi } from "vitest";
import App from "../App";

vi.mock("../crypto/extension-client", () => ({
  detectExtension: vi.fn().mockResolvedValue({ available: false }),
}));

describe("App", () => {
  it("renders the header and navigation tabs", () => {
    render(<App />);
    expect(screen.getByText("OpenCred")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /issue credential/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /verify/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /delegated issuance/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /batch issuance/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /revocation/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /onboarding/i })).toBeInTheDocument();
  });

  it("defaults to the builder tab", () => {
    render(<App />);
    const builderTab = screen.getByRole("tab", { name: /issue credential/i });
    expect(builderTab).toHaveAttribute("aria-selected", "true");
    expect(screen.getByLabelText(/credential type/i)).toBeInTheDocument();
  });

  it("switches to the verifier tab", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("tab", { name: /^verify$/i }));
    expect(screen.getByText(/verifiable credential/i)).toBeInTheDocument();
  });

  it("switches to the delegated issuance tab", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("tab", { name: /delegated issuance/i }));
    expect(screen.getByLabelText(/delegation id/i)).toBeInTheDocument();
  });

  it("switches to the revocation tab", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("tab", { name: /revocation/i }));
    expect(screen.getByText(/single hash/i)).toBeInTheDocument();
  });

  it("switches to the batch issuance tab", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("tab", { name: /batch issuance/i }));
    expect(screen.getByText(/upload a csv file/i)).toBeInTheDocument();
  });

  it("switches to the onboarding tab", async () => {
    const user = userEvent.setup();
    render(<App />);
    await user.click(screen.getByRole("tab", { name: /onboarding/i }));
    expect(screen.getByRole("button", { name: /type a/i })).toBeInTheDocument();
  });

  it("toggles settings panel", async () => {
    const user = userEvent.setup();
    render(<App />);
    expect(screen.queryByLabelText(/api base url/i)).not.toBeInTheDocument();
    await user.click(screen.getByText("Settings"));
    expect(screen.getByLabelText(/api base url/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/bearer token/i)).toBeInTheDocument();
  });
});
