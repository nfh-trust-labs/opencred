import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi } from "vitest";
import { SchemaSelector } from "../components/SchemaSelector";

describe("SchemaSelector", () => {
  it("renders all schema options", () => {
    render(<SchemaSelector value="" onChange={() => {}} />);
    expect(screen.getByText("Education Credential")).toBeInTheDocument();
    expect(screen.getByText("Employment Credential")).toBeInTheDocument();
    expect(screen.getByText("Identity Credential")).toBeInTheDocument();
    expect(screen.getByText("Health Credential")).toBeInTheDocument();
    expect(screen.getByText("Business Credential")).toBeInTheDocument();
  });

  it("calls onChange when a schema is selected", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<SchemaSelector value="" onChange={onChange} />);
    await user.selectOptions(screen.getByRole("combobox"), "education");
    expect(onChange).toHaveBeenCalledWith("education");
  });

  it("shows the selected value", () => {
    render(<SchemaSelector value="health" onChange={() => {}} />);
    expect(screen.getByRole("combobox")).toHaveValue("health");
  });
});
