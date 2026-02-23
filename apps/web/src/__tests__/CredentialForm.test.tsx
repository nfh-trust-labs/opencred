import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, it, expect, vi } from "vitest";
import { CredentialForm } from "../components/CredentialForm";
import type { CredentialSchema } from "../schemas";

const mockSchema: CredentialSchema = {
  id: "education",
  title: "Education Credential",
  fields: [
    { name: "name", type: "string", required: true, label: "Name" },
    { name: "degree", type: "string", required: true, label: "Degree" },
    {
      name: "dateConferred",
      type: "string",
      format: "date",
      required: true,
      label: "Date Conferred",
    },
  ],
};

describe("CredentialForm", () => {
  it("renders fields for the given schema", () => {
    render(<CredentialForm schema={mockSchema} values={{}} onChange={() => {}} />);
    expect(screen.getByLabelText(/name/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/degree/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/date conferred/i)).toBeInTheDocument();
  });

  it("renders date inputs for date-format fields", () => {
    render(<CredentialForm schema={mockSchema} values={{}} onChange={() => {}} />);
    const dateInput = screen.getByLabelText(/date conferred/i);
    expect(dateInput).toHaveAttribute("type", "date");
  });

  it("marks required fields", () => {
    render(<CredentialForm schema={mockSchema} values={{}} onChange={() => {}} />);
    const nameInput = screen.getByLabelText(/name/i);
    expect(nameInput).toBeRequired();
  });

  it("calls onChange when a field value changes", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<CredentialForm schema={mockSchema} values={{}} onChange={onChange} />);
    await user.type(screen.getByLabelText(/degree/i), "BSc");
    expect(onChange).toHaveBeenCalledWith("degree", "B");
  });

  it("displays existing values", () => {
    render(<CredentialForm schema={mockSchema} values={{ name: "Alice" }} onChange={() => {}} />);
    expect(screen.getByLabelText(/name/i)).toHaveValue("Alice");
  });
});
