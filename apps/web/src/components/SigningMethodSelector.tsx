import { useState } from "react";
import { KeyImport } from "./KeyImport";
import { ExtensionSigning } from "./ExtensionSigning";
import { createJwkSigner } from "../crypto/signing-provider";
import type { WebSigner } from "../crypto/types";
import type { ImportedKey } from "./KeyImport";

type SigningMethod = "jwk" | "pkcs11" | "os-cert";

interface Props {
  extensionAvailable: boolean;
  onSignerReady: (signer: WebSigner | null) => void;
}

const TABS: { id: SigningMethod; label: string; requiresExtension: boolean }[] = [
  { id: "jwk", label: "Software Key", requiresExtension: false },
  { id: "pkcs11", label: "Hardware Token", requiresExtension: true },
  { id: "os-cert", label: "OS Certificate", requiresExtension: true },
];

export function SigningMethodSelector({ extensionAvailable, onSignerReady }: Props) {
  const [activeMethod, setActiveMethod] = useState<SigningMethod>("jwk");

  function handleTabChange(method: SigningMethod) {
    setActiveMethod(method);
    onSignerReady(null);
  }

  function handleKeyImported(key: ImportedKey) {
    const algo = (key.algorithm ?? "P-256") as import("../crypto/types").WebSigningAlgorithm;
    const signerType = key.certificateChain ? "pfx" : "jwk";
    const signer = createJwkSigner(key.signingKey, key.publicKeyId, algo, {
      type: signerType as "jwk" | "pfx",
      certificateChain: key.certificateChain,
    });
    onSignerReady(signer);
  }

  function handleExtensionSigner(signer: WebSigner) {
    onSignerReady(signer);
  }

  return (
    <div className="space-y-3">
      <label className="block text-sm font-medium text-gray-700">Signing Method</label>
      <div className="flex border-b border-gray-200">
        {TABS.map((tab) => {
          const disabled = tab.requiresExtension && !extensionAvailable;
          return (
            <button
              key={tab.id}
              type="button"
              disabled={disabled}
              onClick={() => handleTabChange(tab.id)}
              className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
                activeMethod === tab.id
                  ? "border-blue-600 text-blue-600"
                  : disabled
                    ? "border-transparent text-gray-300 cursor-not-allowed"
                    : "border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300"
              }`}
              title={disabled ? "Install the OpenCred browser extension to use this method" : undefined}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {!extensionAvailable && activeMethod === "jwk" && (
        <p className="text-xs text-gray-500">
          Hardware Token and OS Certificate signing require the OpenCred browser extension.
        </p>
      )}

      {activeMethod === "jwk" && (
        <KeyImport onKeyImported={handleKeyImported} />
      )}

      {activeMethod === "pkcs11" && (
        <ExtensionSigning mode="pkcs11" onSignerReady={handleExtensionSigner} />
      )}

      {activeMethod === "os-cert" && (
        <ExtensionSigning mode="os-cert" onSignerReady={handleExtensionSigner} />
      )}
    </div>
  );
}
