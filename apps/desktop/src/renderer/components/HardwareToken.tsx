/**
 * HardwareToken — PKCS#11 hardware token connection UI.
 *
 * Provides controls for connecting a USB token or smart card:
 *  - Select the PKCS#11 library path (.so/.dll/.dylib)
 *  - Enumerate available slots/tokens
 *  - Enter PIN (never stored — only used for the session)
 *  - List keys on the token
 *  - Select a signing key
 *
 * All operations happen via IPC — the renderer never touches key material.
 * Only key metadata (label, ID, algorithm, fingerprint) is displayed.
 */

import { useState } from "react";

/** Slot info from the IPC response. */
interface SlotInfo {
  index: number;
  description: string;
  tokenPresent: boolean;
  tokenLabel?: string;
  tokenManufacturer?: string;
}

/** Key info from the IPC response. */
interface TokenKeyInfo {
  label: string;
  id: string;
  keyType: string;
  hasPublicKey: boolean;
}

/** Connected key metadata. */
interface ConnectedKey {
  id: string;
  fingerprint: string;
  algorithm: string;
  label?: string;
}

type Step = "library" | "slots" | "pin" | "keys" | "connected";

export function HardwareToken() {
  const [step, setStep] = useState<Step>("library");
  const [libraryPath, setLibraryPath] = useState("");
  const [slots, setSlots] = useState<SlotInfo[]>([]);
  const [selectedSlot, setSelectedSlot] = useState<number>(0);
  const [pin, setPin] = useState("");
  const [keys, setKeys] = useState<TokenKeyInfo[]>([]);
  const [connectedKey, setConnectedKey] = useState<ConnectedKey | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleBrowseLibrary() {
    setError(null);
    try {
      const result = await window.opencred.openFile({
        title: "Select PKCS#11 Library",
        filters: [
          { name: "Shared Libraries", extensions: ["so", "dll", "dylib"] },
          { name: "All Files", extensions: ["*"] },
        ],
      });

      if (result.filePath) {
        setLibraryPath(result.filePath);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to open file dialog.");
    }
  }

  async function handleDetectAndListSlots() {
    if (!libraryPath.trim()) {
      setError("Please enter or browse for a PKCS#11 library path.");
      return;
    }
    setError(null);
    setLoading(true);

    try {
      // First check if the file exists
      const detectResult = await window.opencred.pkcs11Detect({ libraryPath });
      if (!detectResult.exists) {
        setError(detectResult.error ?? "Library file not found.");
        setLoading(false);
        return;
      }

      // List slots
      const slotsResult = await window.opencred.pkcs11ListSlots({ libraryPath });
      if (!slotsResult.success || !slotsResult.slots) {
        setError(slotsResult.error ?? "Failed to list slots.");
        setLoading(false);
        return;
      }

      setSlots(slotsResult.slots);
      const tokenSlots = slotsResult.slots.filter((s) => s.tokenPresent);
      if (tokenSlots.length === 0) {
        setError("No tokens detected in any slot. Is your hardware token plugged in?");
        setLoading(false);
        return;
      }

      // Auto-select first slot with a token
      setSelectedSlot(tokenSlots[0].index);

      if (tokenSlots.length === 1) {
        // Single token — skip slot selection, go to PIN
        setStep("pin");
      } else {
        setStep("slots");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to detect token.");
    } finally {
      setLoading(false);
    }
  }

  async function handleListKeys() {
    if (!pin.trim()) {
      setError("Please enter your token PIN.");
      return;
    }
    setError(null);
    setLoading(true);

    try {
      const result = await window.opencred.pkcs11ListKeys({
        libraryPath,
        slotIndex: selectedSlot,
        pin,
      });

      // Clear PIN from state immediately after use
      setPin("");

      if (!result.success || !result.keys) {
        setError(result.error ?? "Failed to list keys.");
        setLoading(false);
        return;
      }

      if (result.keys.length === 0) {
        setError("No EC signing keys found on this token.");
        setLoading(false);
        return;
      }

      setKeys(result.keys);
      setStep("keys");
    } catch (err) {
      setPin("");
      setError(err instanceof Error ? err.message : "Failed to list keys.");
    } finally {
      setLoading(false);
    }
  }

  async function handleConnect(keyId?: string) {
    setError(null);
    setLoading(true);

    // Re-prompt for PIN since we cleared it
    const connectPin = prompt("Enter your token PIN to connect:");
    if (!connectPin) {
      setLoading(false);
      return;
    }

    try {
      const result = await window.opencred.pkcs11Connect({
        libraryPath,
        slotIndex: selectedSlot,
        pin: connectPin,
        keyId,
      });

      if (!result.success || !result.key) {
        setError(result.error ?? "Failed to connect.");
        setLoading(false);
        return;
      }

      setConnectedKey({
        id: result.key.id,
        fingerprint: result.key.fingerprint,
        algorithm: result.key.algorithm,
        label: result.key.label,
      });
      setStep("connected");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to connect.");
    } finally {
      setLoading(false);
    }
  }

  function handleReset() {
    setStep("library");
    setLibraryPath("");
    setSlots([]);
    setSelectedSlot(0);
    setPin("");
    setKeys([]);
    setConnectedKey(null);
    setError(null);
  }

  return (
    <div className="rounded-lg border border-gray-200 bg-white p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-700">Hardware Token (PKCS#11)</h2>
        {step !== "library" && (
          <button
            onClick={handleReset}
            className="text-xs text-gray-500 hover:text-gray-700 underline"
          >
            Reset
          </button>
        )}
      </div>

      <p className="text-xs text-gray-500">
        Connect a USB token (YubiKey, ePass, SafeNet) or smart card via PKCS#11.
        Your private key never leaves the hardware token.
      </p>

      {error && <p className="text-sm text-red-600">{error}</p>}

      {/* Step 1: Library path */}
      {step === "library" && (
        <div className="space-y-3">
          <label className="block text-xs text-gray-600">PKCS#11 Library Path</label>
          <div className="flex gap-2">
            <input
              type="text"
              value={libraryPath}
              onChange={(e) => setLibraryPath(e.target.value)}
              placeholder="/usr/lib/opensc-pkcs11.so"
              className="flex-1 rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none"
            />
            <button
              onClick={() => void handleBrowseLibrary()}
              className="rounded-md border border-gray-300 px-3 py-1.5 text-sm text-gray-700 hover:bg-gray-50"
            >
              Browse
            </button>
          </div>
          <button
            onClick={() => void handleDetectAndListSlots()}
            disabled={loading}
            className="rounded-md bg-gray-700 px-4 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
          >
            {loading ? "Detecting..." : "Detect Token"}
          </button>
        </div>
      )}

      {/* Step 2: Slot selection (only if multiple slots) */}
      {step === "slots" && (
        <div className="space-y-3">
          <label className="block text-xs text-gray-600">Select Token Slot</label>
          <div className="space-y-2">
            {slots
              .filter((s) => s.tokenPresent)
              .map((slot) => (
                <label
                  key={slot.index}
                  className={`flex items-center gap-2 rounded-md border p-3 cursor-pointer ${
                    selectedSlot === slot.index
                      ? "border-blue-500 bg-blue-50"
                      : "border-gray-200 hover:bg-gray-50"
                  }`}
                >
                  <input
                    type="radio"
                    name="slot"
                    checked={selectedSlot === slot.index}
                    onChange={() => setSelectedSlot(slot.index)}
                    className="text-blue-600"
                  />
                  <div>
                    <p className="text-sm font-medium text-gray-700">
                      {slot.tokenLabel ?? `Slot ${slot.index}`}
                    </p>
                    <p className="text-xs text-gray-500">
                      {slot.description}
                      {slot.tokenManufacturer ? ` | ${slot.tokenManufacturer}` : ""}
                    </p>
                  </div>
                </label>
              ))}
          </div>
          <button
            onClick={() => setStep("pin")}
            className="rounded-md bg-gray-700 px-4 py-1.5 text-sm text-white hover:bg-gray-800"
          >
            Continue
          </button>
        </div>
      )}

      {/* Step 3: PIN entry */}
      {step === "pin" && (
        <div className="space-y-3">
          <label className="block text-xs text-gray-600">
            Enter PIN for{" "}
            {slots.find((s) => s.index === selectedSlot)?.tokenLabel ?? `Slot ${selectedSlot}`}
          </label>
          <p className="text-xs text-gray-400">
            Your PIN is used only for this session and is never stored.
          </p>
          <input
            type="password"
            value={pin}
            onChange={(e) => setPin(e.target.value)}
            placeholder="Token PIN"
            className="w-full rounded-md border border-gray-300 px-3 py-1.5 text-sm focus:border-blue-500 focus:outline-none"
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleListKeys();
            }}
          />
          <button
            onClick={() => void handleListKeys()}
            disabled={loading}
            className="rounded-md bg-gray-700 px-4 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
          >
            {loading ? "Authenticating..." : "Unlock Token"}
          </button>
        </div>
      )}

      {/* Step 4: Key selection */}
      {step === "keys" && (
        <div className="space-y-3">
          <label className="block text-xs text-gray-600">Select Signing Key</label>
          <div className="space-y-2">
            {keys.map((key) => (
              <div
                key={key.id}
                className="flex items-center justify-between rounded-md border border-gray-200 p-3"
              >
                <div>
                  <p className="text-sm font-medium text-gray-700">
                    {key.label || `Key ${key.id.slice(0, 8)}...`}
                  </p>
                  <p className="text-xs text-gray-500">
                    Type: {key.keyType} | ID: {key.id.slice(0, 16)}...
                    {!key.hasPublicKey && " | No public key (limited)"}
                  </p>
                </div>
                <button
                  onClick={() => void handleConnect(key.id)}
                  disabled={loading || !key.hasPublicKey}
                  className="rounded-md bg-blue-600 px-3 py-1 text-xs text-white hover:bg-blue-700 disabled:opacity-40"
                  title={!key.hasPublicKey ? "No public key available for verification" : "Connect this key for signing"}
                >
                  {loading ? "..." : "Connect"}
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Step 5: Connected */}
      {step === "connected" && connectedKey && (
        <div className="rounded-md border border-green-200 bg-green-50 p-3 text-xs">
          <p className="font-medium text-green-800">Hardware token connected</p>
          <div className="mt-1 text-green-700 space-y-0.5">
            <p>Algorithm: {connectedKey.algorithm}</p>
            {connectedKey.label && <p>Label: {connectedKey.label}</p>}
            <p>Fingerprint: {connectedKey.fingerprint.slice(0, 32)}...</p>
            <p className="font-mono text-[10px] text-green-600 break-all">
              ID: {connectedKey.id}
            </p>
          </div>
          <p className="mt-2 text-green-600">
            This key is now available for credential signing. Select it from the key list when issuing credentials.
          </p>
        </div>
      )}
    </div>
  );
}
