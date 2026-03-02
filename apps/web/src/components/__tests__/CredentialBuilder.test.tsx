import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { CredentialBuilder } from "../CredentialBuilder";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockBuildCredential, mockPackageCredential, mockIssueDelegated } = vi.hoisted(() => ({
  mockBuildCredential: vi.fn(),
  mockPackageCredential: vi.fn(),
  mockIssueDelegated: vi.fn(),
}));

vi.mock("../../api/client", () => ({
  OpenCredClient: vi.fn().mockImplementation(() => ({
    buildCredential: mockBuildCredential,
    packageCredential: mockPackageCredential,
    issueDelegated: mockIssueDelegated,
  })),
}));

vi.mock("../../schemas", () => ({
  getSchema: vi.fn((id: string) =>
    id === "education"
      ? {
          id: "education",
          title: "Education Credential",
          fields: [
            { name: "name", type: "string", required: true, label: "Name" },
            { name: "degree", type: "string", required: true, label: "Degree" },
          ],
        }
      : undefined,
  ),
}));

// Mock SigningMethodSelector to control signer state
let capturedOnSignerReady: ((signer: unknown) => void) | undefined;
vi.mock("../SigningMethodSelector", () => ({
  SigningMethodSelector: ({
    onSignerReady,
    extensionAvailable,
  }: {
    onSignerReady: (signer: unknown) => void;
    extensionAvailable: boolean;
  }) => {
    capturedOnSignerReady = onSignerReady;
    return (
      <div data-testid="signing-method-selector" data-extension={String(extensionAvailable)}>
        SigningMethodSelector Stub
      </div>
    );
  },
}));

vi.mock("../SchemaSelector", () => ({
  SchemaSelector: ({
    value,
    onChange,
  }: {
    value: string;
    onChange: (id: string) => void;
  }) => (
    <select
      data-testid="schema-selector"
      value={value}
      onChange={(e) => onChange(e.target.value)}
    >
      <option value="">Select...</option>
      <option value="education">Education</option>
    </select>
  ),
}));

vi.mock("../CredentialForm", () => ({
  CredentialForm: ({
    values,
    onChange,
  }: {
    schema: unknown;
    values: Record<string, string>;
    onChange: (field: string, value: string) => void;
  }) => (
    <div data-testid="credential-form">
      <input
        data-testid="field-name"
        value={values.name ?? ""}
        onChange={(e) => onChange("name", e.target.value)}
      />
      <input
        data-testid="field-degree"
        value={values.degree ?? ""}
        onChange={(e) => onChange("degree", e.target.value)}
      />
    </div>
  ),
}));

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("CredentialBuilder", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    capturedOnSignerReady = undefined;
  });

  it("should render with SigningMethodSelector instead of KeyImport", () => {
    render(
      <CredentialBuilder apiUrl="/api" token="" extensionAvailable={false} />,
    );

    expect(screen.getByTestId("signing-method-selector")).toBeInTheDocument();
  });

  it("should pass extensionAvailable to SigningMethodSelector", () => {
    render(
      <CredentialBuilder apiUrl="/api" token="" extensionAvailable={true} />,
    );

    expect(screen.getByTestId("signing-method-selector")).toHaveAttribute(
      "data-extension",
      "true",
    );
  });

  it("should show SigningMethodSelector only in interface signing mode", async () => {
    const user = userEvent.setup();
    render(
      <CredentialBuilder apiUrl="/api" token="" extensionAvailable={false} />,
    );

    // Default is interface mode — selector should be visible
    expect(screen.getByTestId("signing-method-selector")).toBeInTheDocument();

    // Switch to delegated
    await user.click(screen.getByLabelText(/delegated signing/i));

    expect(screen.queryByTestId("signing-method-selector")).not.toBeInTheDocument();
  });

  it("should use webSigner.sign() for interface signing", async () => {
    const user = userEvent.setup();
    const mockSign = vi.fn().mockResolvedValue("mock-signature-b64url");

    mockBuildCredential.mockResolvedValue({
      sessionId: "sess-1",
      unsignedCredential: {},
      dataToSign: "dGVzdC1kYXRh",
      proofConfig: {},
    });
    mockPackageCredential.mockResolvedValue({
      credential: { "@context": ["https://www.w3.org/ns/credentials/v2"], type: "VerifiableCredential" },
      formats: { jsonld: {} },
    });

    render(
      <CredentialBuilder apiUrl="/api" token="tok" extensionAvailable={false} />,
    );

    // Fill out the form
    await user.selectOptions(screen.getByTestId("schema-selector"), "education");
    await user.type(screen.getByTestId("field-name"), "Alice");
    await user.type(screen.getByTestId("field-degree"), "BSc");
    await user.type(screen.getByPlaceholderText("did:key:z..."), "did:key:z123");

    // Simulate signer becoming ready
    expect(capturedOnSignerReady).toBeDefined();
    capturedOnSignerReady!({
      publicKeyId: "test-key-id",
      sign: mockSign,
      metadata: { type: "pkcs11" },
    });

    // Click build & sign
    await user.click(screen.getByText("Build & Sign Credential"));

    await waitFor(() => {
      expect(mockSign).toHaveBeenCalledWith("dGVzdC1kYXRh");
    });

    expect(mockBuildCredential).toHaveBeenCalledWith(
      expect.objectContaining({
        publicKey: "test-key-id",
      }),
    );

    expect(mockPackageCredential).toHaveBeenCalledWith({
      sessionId: "sess-1",
      signature: "mock-signature-b64url",
    });
  });

  it("should show credential after successful signing", async () => {
    const user = userEvent.setup();

    mockBuildCredential.mockResolvedValue({
      sessionId: "sess-1",
      unsignedCredential: {},
      dataToSign: "dGVzdA",
      proofConfig: {},
    });
    mockPackageCredential.mockResolvedValue({
      credential: { type: "VerifiableCredential", credentialSubject: { name: "Alice" } },
      formats: { jsonld: {} },
    });

    render(
      <CredentialBuilder apiUrl="/api" token="" extensionAvailable={false} />,
    );

    await user.selectOptions(screen.getByTestId("schema-selector"), "education");
    await user.type(screen.getByTestId("field-name"), "Alice");
    await user.type(screen.getByTestId("field-degree"), "BSc");
    await user.type(screen.getByPlaceholderText("did:key:z..."), "did:key:z123");

    capturedOnSignerReady!({
      publicKeyId: "key-1",
      sign: vi.fn().mockResolvedValue("sig"),
      metadata: { type: "jwk" },
    });

    await user.click(screen.getByText("Build & Sign Credential"));

    await waitFor(() => {
      expect(screen.getByText(/Credential issued successfully/)).toBeInTheDocument();
    });
  });

  it("should show error when signing fails", async () => {
    const user = userEvent.setup();

    mockBuildCredential.mockRejectedValue(new Error("Server error"));

    render(
      <CredentialBuilder apiUrl="/api" token="" extensionAvailable={false} />,
    );

    await user.selectOptions(screen.getByTestId("schema-selector"), "education");
    await user.type(screen.getByTestId("field-name"), "Alice");
    await user.type(screen.getByTestId("field-degree"), "BSc");
    await user.type(screen.getByPlaceholderText("did:key:z..."), "did:key:z123");

    capturedOnSignerReady!({
      publicKeyId: "key-1",
      sign: vi.fn(),
      metadata: { type: "jwk" },
    });

    await user.click(screen.getByText("Build & Sign Credential"));

    await waitFor(() => {
      expect(screen.getByText("Server error")).toBeInTheDocument();
    });
  });
});
