import { describe, it, expect, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ExtensionSigning } from "../ExtensionSigning";

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const { mockPkcs11, mockOscert, mockCreatePkcs11Signer, mockCreateOsCertSigner } =
  vi.hoisted(() => {
    const mockPkcs11 = {
      listSlots: vi.fn(),
      listKeys: vi.fn(),
      connect: vi.fn(),
      sign: vi.fn(),
      disconnect: vi.fn().mockResolvedValue(undefined),
    };
    const mockOscert = {
      list: vi.fn(),
      connect: vi.fn(),
      sign: vi.fn(),
      disconnect: vi.fn().mockResolvedValue(undefined),
    };
    const mockCreatePkcs11Signer = vi.fn();
    const mockCreateOsCertSigner = vi.fn();
    return { mockPkcs11, mockOscert, mockCreatePkcs11Signer, mockCreateOsCertSigner };
  });

vi.mock("../../crypto/extension-client", () => ({
  pkcs11: mockPkcs11,
  oscert: mockOscert,
}));

vi.mock("../../crypto/signing-provider", () => ({
  createPkcs11Signer: mockCreatePkcs11Signer,
  createOsCertSigner: mockCreateOsCertSigner,
}));

// ---------------------------------------------------------------------------
// PKCS#11 flow tests
// ---------------------------------------------------------------------------

describe("ExtensionSigning — PKCS#11", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should render library path input and List Slots button", () => {
    render(<ExtensionSigning mode="pkcs11" onSignerReady={vi.fn()} />);

    expect(screen.getByLabelText("PKCS#11 Library Path")).toBeInTheDocument();
    expect(screen.getByText("List Slots")).toBeInTheDocument();
  });

  it("should disable List Slots when library path is empty", () => {
    render(<ExtensionSigning mode="pkcs11" onSignerReady={vi.fn()} />);

    expect(screen.getByText("List Slots")).toBeDisabled();
  });

  it("should list slots when button is clicked", async () => {
    const user = userEvent.setup();
    mockPkcs11.listSlots.mockResolvedValue({
      slots: [
        { index: 0, description: "SoftHSM slot 0", tokenPresent: true, tokenLabel: "Test Token" },
      ],
    });

    render(<ExtensionSigning mode="pkcs11" onSignerReady={vi.fn()} />);

    await user.type(screen.getByLabelText("PKCS#11 Library Path"), "/usr/lib/softhsm.so");
    await user.click(screen.getByText("List Slots"));

    await waitFor(() => {
      expect(screen.getByLabelText("Token Slot")).toBeInTheDocument();
    });
  });

  it("should show PIN input after selecting a slot", async () => {
    const user = userEvent.setup();
    mockPkcs11.listSlots.mockResolvedValue({
      slots: [
        { index: 0, description: "SoftHSM slot 0", tokenPresent: true, tokenLabel: "Test Token" },
      ],
    });

    render(<ExtensionSigning mode="pkcs11" onSignerReady={vi.fn()} />);

    await user.type(screen.getByLabelText("PKCS#11 Library Path"), "/usr/lib/softhsm.so");
    await user.click(screen.getByText("List Slots"));

    await waitFor(() => {
      expect(screen.getByLabelText("Token Slot")).toBeInTheDocument();
    });

    await user.selectOptions(screen.getByLabelText("Token Slot"), "0");

    expect(screen.getByLabelText("PIN")).toBeInTheDocument();
  });

  it("should connect to token and call onSignerReady", async () => {
    const user = userEvent.setup();
    const onSignerReady = vi.fn();

    mockPkcs11.listSlots.mockResolvedValue({
      slots: [
        { index: 0, description: "SoftHSM slot 0", tokenPresent: true },
      ],
    });
    mockPkcs11.connect.mockResolvedValue({
      signerId: "signer-123",
      metadata: { id: "key-id", algorithm: "P-256", type: "pkcs11", fingerprint: "abc" },
    });
    const fakeSigner = { publicKeyId: "key-id", sign: vi.fn(), metadata: { type: "pkcs11" } };
    mockCreatePkcs11Signer.mockReturnValue(fakeSigner);

    render(<ExtensionSigning mode="pkcs11" onSignerReady={onSignerReady} />);

    await user.type(screen.getByLabelText("PKCS#11 Library Path"), "/usr/lib/softhsm.so");
    await user.click(screen.getByText("List Slots"));

    await waitFor(() => {
      expect(screen.getByLabelText("Token Slot")).toBeInTheDocument();
    });

    await user.selectOptions(screen.getByLabelText("Token Slot"), "0");
    await user.type(screen.getByLabelText("PIN"), "1234");
    await user.click(screen.getByText("Connect to Token"));

    await waitFor(() => {
      expect(onSignerReady).toHaveBeenCalledWith(fakeSigner);
    });

    expect(screen.getByText(/Hardware token connected/)).toBeInTheDocument();
  });

  it("should show error when listSlots fails", async () => {
    const user = userEvent.setup();
    mockPkcs11.listSlots.mockRejectedValue(new Error("Library not found"));

    render(<ExtensionSigning mode="pkcs11" onSignerReady={vi.fn()} />);

    await user.type(screen.getByLabelText("PKCS#11 Library Path"), "/bad/path.so");
    await user.click(screen.getByText("List Slots"));

    await waitFor(() => {
      expect(screen.getByText("Library not found")).toBeInTheDocument();
    });
  });

  it("should show error when connect fails", async () => {
    const user = userEvent.setup();
    mockPkcs11.listSlots.mockResolvedValue({
      slots: [{ index: 0, description: "Slot 0", tokenPresent: true }],
    });
    mockPkcs11.connect.mockRejectedValue(new Error("PIN incorrect"));

    render(<ExtensionSigning mode="pkcs11" onSignerReady={vi.fn()} />);

    await user.type(screen.getByLabelText("PKCS#11 Library Path"), "/usr/lib/softhsm.so");
    await user.click(screen.getByText("List Slots"));

    await waitFor(() => {
      expect(screen.getByLabelText("Token Slot")).toBeInTheDocument();
    });

    await user.selectOptions(screen.getByLabelText("Token Slot"), "0");
    await user.type(screen.getByLabelText("PIN"), "wrong");
    await user.click(screen.getByText("Connect to Token"));

    await waitFor(() => {
      expect(screen.getByText("PIN incorrect")).toBeInTheDocument();
    });
  });
});

// ---------------------------------------------------------------------------
// OS Certificate flow tests
// ---------------------------------------------------------------------------

describe("ExtensionSigning — OS Certificate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("should render List Certificates button", () => {
    render(<ExtensionSigning mode="os-cert" onSignerReady={vi.fn()} />);

    expect(screen.getByText("List Certificates")).toBeInTheDocument();
  });

  it("should list certificates when button is clicked", async () => {
    const user = userEvent.setup();
    mockOscert.list.mockResolvedValue({
      certificates: [
        {
          id: "cert-1",
          subject: "CN=Test User",
          issuer: "CN=Test CA",
          serialNumber: "001",
          validFrom: "2025-01-01",
          validUntil: "2026-01-01",
          keyAlgorithm: "EC P-256",
          isExportable: false,
          thumbprint: "abc123",
        },
      ],
    });

    render(<ExtensionSigning mode="os-cert" onSignerReady={vi.fn()} />);

    await user.click(screen.getByText("List Certificates"));

    await waitFor(() => {
      expect(screen.getByLabelText("Certificate")).toBeInTheDocument();
    });
  });

  it("should show Connect button after selecting a certificate", async () => {
    const user = userEvent.setup();
    mockOscert.list.mockResolvedValue({
      certificates: [
        {
          id: "cert-1",
          subject: "CN=Test User",
          issuer: "CN=Test CA",
          serialNumber: "001",
          validFrom: "2025-01-01",
          validUntil: "2026-01-01",
          keyAlgorithm: "EC P-256",
          isExportable: false,
          thumbprint: "abc123",
        },
      ],
    });

    render(<ExtensionSigning mode="os-cert" onSignerReady={vi.fn()} />);

    await user.click(screen.getByText("List Certificates"));

    await waitFor(() => {
      expect(screen.getByLabelText("Certificate")).toBeInTheDocument();
    });

    await user.selectOptions(screen.getByLabelText("Certificate"), "cert-1");

    expect(screen.getByText("Connect")).toBeInTheDocument();
  });

  it("should connect to certificate and call onSignerReady", async () => {
    const user = userEvent.setup();
    const onSignerReady = vi.fn();

    mockOscert.list.mockResolvedValue({
      certificates: [
        {
          id: "cert-1",
          subject: "CN=Test User",
          issuer: "CN=Test CA",
          serialNumber: "001",
          validFrom: "2025-01-01",
          validUntil: "2026-01-01",
          keyAlgorithm: "EC P-256",
          isExportable: false,
          thumbprint: "abc123",
        },
      ],
    });
    mockOscert.connect.mockResolvedValue({
      signerId: "signer-456",
      metadata: { id: "cert-key-id", algorithm: "P-256", type: "os-cert", fingerprint: "xyz" },
    });
    const fakeSigner = { publicKeyId: "cert-key-id", sign: vi.fn(), metadata: { type: "os-cert" } };
    mockCreateOsCertSigner.mockReturnValue(fakeSigner);

    render(<ExtensionSigning mode="os-cert" onSignerReady={onSignerReady} />);

    await user.click(screen.getByText("List Certificates"));

    await waitFor(() => {
      expect(screen.getByLabelText("Certificate")).toBeInTheDocument();
    });

    await user.selectOptions(screen.getByLabelText("Certificate"), "cert-1");
    await user.click(screen.getByText("Connect"));

    await waitFor(() => {
      expect(onSignerReady).toHaveBeenCalledWith(fakeSigner);
    });

    expect(screen.getByText(/OS certificate connected/)).toBeInTheDocument();
  });

  it("should show error when list fails", async () => {
    const user = userEvent.setup();
    mockOscert.list.mockRejectedValue(new Error("No keychain access"));

    render(<ExtensionSigning mode="os-cert" onSignerReady={vi.fn()} />);

    await user.click(screen.getByText("List Certificates"));

    await waitFor(() => {
      expect(screen.getByText("No keychain access")).toBeInTheDocument();
    });
  });

  it("should show error when connect fails", async () => {
    const user = userEvent.setup();
    mockOscert.list.mockResolvedValue({
      certificates: [
        {
          id: "cert-1",
          subject: "CN=Test User",
          issuer: "CN=Test CA",
          serialNumber: "001",
          validFrom: "2025-01-01",
          validUntil: "2026-01-01",
          keyAlgorithm: "EC P-256",
          isExportable: false,
          thumbprint: "abc123",
        },
      ],
    });
    mockOscert.connect.mockRejectedValue(new Error("Access denied"));

    render(<ExtensionSigning mode="os-cert" onSignerReady={vi.fn()} />);

    await user.click(screen.getByText("List Certificates"));

    await waitFor(() => {
      expect(screen.getByLabelText("Certificate")).toBeInTheDocument();
    });

    await user.selectOptions(screen.getByLabelText("Certificate"), "cert-1");
    await user.click(screen.getByText("Connect"));

    await waitFor(() => {
      expect(screen.getByText("Access denied")).toBeInTheDocument();
    });
  });
});
