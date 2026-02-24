import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect } from "vitest";
import App from "../App";

describe("App", () => {
  it("renders the header and tabs", () => {
    render(<App />);
    expect(screen.getByText("OpenCred")).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /issue credential/i })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /verify credential/i })).toBeInTheDocument();
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
    await user.click(screen.getByRole("tab", { name: /verify credential/i }));
    expect(screen.getByText(/verifiable credential/i)).toBeInTheDocument();
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
