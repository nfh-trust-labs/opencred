import { describe, it, expect, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SigningMethodSelector } from "../SigningMethodSelector";

// Mock child components to isolate unit behavior
vi.mock("../KeyImport", () => ({
  KeyImport: ({ onKeyImported }: { onKeyImported: (key: unknown) => void }) => (
    <button
      data-testid="key-import-stub"
      onClick={() =>
        onKeyImported({
          signingKey: {} as CryptoKey,
          publicKeyId: "test-pub-key-id",
        })
      }
    >
      KeyImport Stub
    </button>
  ),
}));

vi.mock("../ExtensionSigning", () => ({
  ExtensionSigning: ({
    mode,
    onSignerReady,
  }: {
    mode: string;
    onSignerReady: (signer: unknown) => void;
  }) => (
    <button
      data-testid={`extension-signing-${mode}`}
      onClick={() =>
        onSignerReady({
          publicKeyId: `${mode}-key-id`,
          sign: vi.fn(),
          metadata: { type: mode },
        })
      }
    >
      ExtensionSigning ({mode})
    </button>
  ),
}));

vi.mock("../../crypto/signing-provider", () => ({
  createJwkSigner: vi.fn((_key: unknown, publicKeyId: string) => ({
    publicKeyId,
    sign: vi.fn(),
    metadata: { type: "jwk" },
  })),
}));

describe("SigningMethodSelector", () => {
  it("should render three tabs", () => {
    render(
      <SigningMethodSelector extensionAvailable={true} onSignerReady={vi.fn()} />,
    );

    expect(screen.getByText("Software Key")).toBeInTheDocument();
    expect(screen.getByText("Hardware Token")).toBeInTheDocument();
    expect(screen.getByText("OS Certificate")).toBeInTheDocument();
  });

  it("should show KeyImport by default (Software Key tab)", () => {
    render(
      <SigningMethodSelector extensionAvailable={true} onSignerReady={vi.fn()} />,
    );

    expect(screen.getByTestId("key-import-stub")).toBeInTheDocument();
  });

  it("should disable extension tabs when extension is not available", () => {
    render(
      <SigningMethodSelector extensionAvailable={false} onSignerReady={vi.fn()} />,
    );

    expect(screen.getByText("Hardware Token")).toBeDisabled();
    expect(screen.getByText("OS Certificate")).toBeDisabled();
  });

  it("should enable extension tabs when extension is available", () => {
    render(
      <SigningMethodSelector extensionAvailable={true} onSignerReady={vi.fn()} />,
    );

    expect(screen.getByText("Hardware Token")).not.toBeDisabled();
    expect(screen.getByText("OS Certificate")).not.toBeDisabled();
  });

  it("should switch to PKCS#11 view when Hardware Token tab is clicked", async () => {
    const user = userEvent.setup();
    render(
      <SigningMethodSelector extensionAvailable={true} onSignerReady={vi.fn()} />,
    );

    await user.click(screen.getByText("Hardware Token"));

    expect(screen.getByTestId("extension-signing-pkcs11")).toBeInTheDocument();
    expect(screen.queryByTestId("key-import-stub")).not.toBeInTheDocument();
  });

  it("should switch to OS Certificate view when OS Certificate tab is clicked", async () => {
    const user = userEvent.setup();
    render(
      <SigningMethodSelector extensionAvailable={true} onSignerReady={vi.fn()} />,
    );

    await user.click(screen.getByText("OS Certificate"));

    expect(screen.getByTestId("extension-signing-os-cert")).toBeInTheDocument();
    expect(screen.queryByTestId("key-import-stub")).not.toBeInTheDocument();
  });

  it("should call onSignerReady(null) when switching tabs", async () => {
    const user = userEvent.setup();
    const onSignerReady = vi.fn();
    render(
      <SigningMethodSelector extensionAvailable={true} onSignerReady={onSignerReady} />,
    );

    await user.click(screen.getByText("Hardware Token"));

    expect(onSignerReady).toHaveBeenCalledWith(null);
  });

  it("should call onSignerReady with JWK signer when key is imported", async () => {
    const user = userEvent.setup();
    const onSignerReady = vi.fn();
    render(
      <SigningMethodSelector extensionAvailable={true} onSignerReady={onSignerReady} />,
    );

    await user.click(screen.getByTestId("key-import-stub"));

    expect(onSignerReady).toHaveBeenCalledWith(
      expect.objectContaining({
        publicKeyId: "test-pub-key-id",
        metadata: { type: "jwk" },
      }),
    );
  });

  it("should call onSignerReady with extension signer when connected", async () => {
    const user = userEvent.setup();
    const onSignerReady = vi.fn();
    render(
      <SigningMethodSelector extensionAvailable={true} onSignerReady={onSignerReady} />,
    );

    await user.click(screen.getByText("Hardware Token"));
    onSignerReady.mockClear();

    await user.click(screen.getByTestId("extension-signing-pkcs11"));

    expect(onSignerReady).toHaveBeenCalledWith(
      expect.objectContaining({
        publicKeyId: "pkcs11-key-id",
        metadata: { type: "pkcs11" },
      }),
    );
  });

  it("should show extension hint when extension is not available", () => {
    render(
      <SigningMethodSelector extensionAvailable={false} onSignerReady={vi.fn()} />,
    );

    expect(
      screen.getByText(/Hardware Token and OS Certificate signing require/),
    ).toBeInTheDocument();
  });
});
