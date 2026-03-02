import { useState, useEffect, useRef } from "react";
import { pkcs11, oscert } from "../crypto/extension-client";
import { createPkcs11Signer, createOsCertSigner } from "../crypto/signing-provider";
import type { WebSigner, SlotInfo, TokenKeyInfo, CertInfo } from "../crypto/types";

interface Props {
  mode: "pkcs11" | "os-cert";
  onSignerReady: (signer: WebSigner) => void;
}

export function ExtensionSigning({ mode, onSignerReady }: Props) {
  if (mode === "pkcs11") {
    return <Pkcs11Flow onSignerReady={onSignerReady} />;
  }
  return <OsCertFlow onSignerReady={onSignerReady} />;
}

// ---------------------------------------------------------------------------
// PKCS#11 flow
// ---------------------------------------------------------------------------

function Pkcs11Flow({ onSignerReady }: { onSignerReady: (signer: WebSigner) => void }) {
  const [libraryPath, setLibraryPath] = useState("");
  const [slots, setSlots] = useState<SlotInfo[]>([]);
  const [selectedSlot, setSelectedSlot] = useState<number | null>(null);
  const [pin, setPin] = useState("");
  const [keys, setKeys] = useState<TokenKeyInfo[]>([]);
  const [selectedKey, setSelectedKey] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const signerIdRef = useRef<string | null>(null);

  useEffect(() => {
    return () => {
      const id = signerIdRef.current;
      if (id) {
        void pkcs11.disconnect(id).catch(() => {});
      }
    };
  }, []);

  async function handleListSlots() {
    setError(null);
    setSlots([]);
    setSelectedSlot(null);
    setKeys([]);
    setSelectedKey(null);
    setConnected(false);
    setLoading(true);
    try {
      const result = await pkcs11.listSlots(libraryPath);
      setSlots(result.slots);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to list slots");
    } finally {
      setLoading(false);
    }
  }

  async function handleListKeys() {
    if (selectedSlot === null) return;
    setError(null);
    setKeys([]);
    setSelectedKey(null);
    setConnected(false);
    setLoading(true);
    try {
      const result = await pkcs11.listKeys(libraryPath, selectedSlot, pin);
      setKeys(result.keys);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to list keys");
    } finally {
      setLoading(false);
    }
  }

  async function handleConnect() {
    if (selectedSlot === null) return;
    setError(null);
    setLoading(true);
    try {
      const result = await pkcs11.connect({
        libraryPath,
        slotIndex: selectedSlot,
        pin,
        keyId: selectedKey ?? undefined,
      });
      signerIdRef.current = result.signerId;
      const signer = createPkcs11Signer(result.signerId, result.metadata);
      setConnected(true);
      onSignerReady(signer);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to connect to token");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-3">
      <div>
        <label htmlFor="pkcs11-library" className="block text-sm font-medium text-gray-700">
          PKCS#11 Library Path
        </label>
        <div className="mt-1 flex gap-2">
          <input
            id="pkcs11-library"
            type="text"
            value={libraryPath}
            onChange={(e) => setLibraryPath(e.target.value)}
            placeholder="/usr/lib/opensc-pkcs11.so"
            className="block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          />
          <button
            type="button"
            onClick={handleListSlots}
            disabled={!libraryPath.trim() || loading}
            className="whitespace-nowrap rounded-md bg-gray-700 px-3 py-2 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
          >
            List Slots
          </button>
        </div>
      </div>

      {slots.length > 0 && (
        <div>
          <label htmlFor="pkcs11-slot" className="block text-sm font-medium text-gray-700">
            Token Slot
          </label>
          <select
            id="pkcs11-slot"
            value={selectedSlot ?? ""}
            onChange={(e) => {
              setSelectedSlot(e.target.value === "" ? null : Number(e.target.value));
              setKeys([]);
              setSelectedKey(null);
              setConnected(false);
            }}
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="">Select a slot...</option>
            {slots.map((slot) => (
              <option key={slot.index} value={slot.index}>
                Slot {slot.index}: {slot.description}
                {slot.tokenLabel ? ` (${slot.tokenLabel})` : ""}
              </option>
            ))}
          </select>
        </div>
      )}

      {selectedSlot !== null && (
        <div>
          <label htmlFor="pkcs11-pin" className="block text-sm font-medium text-gray-700">
            PIN
          </label>
          <div className="mt-1 flex gap-2">
            <input
              id="pkcs11-pin"
              type="password"
              value={pin}
              onChange={(e) => setPin(e.target.value)}
              placeholder="Enter token PIN"
              className="block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
            <button
              type="button"
              onClick={handleListKeys}
              disabled={!pin.trim() || loading}
              className="whitespace-nowrap rounded-md bg-gray-700 px-3 py-2 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
            >
              List Keys
            </button>
          </div>
        </div>
      )}

      {keys.length > 0 && (
        <div>
          <label htmlFor="pkcs11-key" className="block text-sm font-medium text-gray-700">
            Signing Key
          </label>
          <select
            id="pkcs11-key"
            value={selectedKey ?? ""}
            onChange={(e) => {
              setSelectedKey(e.target.value || null);
              setConnected(false);
            }}
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="">Auto-select first key</option>
            {keys.map((key) => (
              <option key={key.id} value={key.id}>
                {key.label} ({key.keyType})
              </option>
            ))}
          </select>
        </div>
      )}

      {selectedSlot !== null && pin.trim() && (
        <button
          type="button"
          onClick={handleConnect}
          disabled={loading || connected}
          className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-40"
        >
          {connected ? "Connected" : loading ? "Connecting..." : "Connect to Token"}
        </button>
      )}

      {connected && (
        <p className="text-sm text-green-600">Hardware token connected and ready for signing.</p>
      )}

      {error && <p className="text-sm text-red-600">{error}</p>}
    </div>
  );
}

// ---------------------------------------------------------------------------
// OS Certificate flow
// ---------------------------------------------------------------------------

function OsCertFlow({ onSignerReady }: { onSignerReady: (signer: WebSigner) => void }) {
  const [certificates, setCertificates] = useState<CertInfo[]>([]);
  const [selectedCertId, setSelectedCertId] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const signerIdRef = useRef<string | null>(null);

  useEffect(() => {
    return () => {
      const id = signerIdRef.current;
      if (id) {
        void oscert.disconnect(id).catch(() => {});
      }
    };
  }, []);

  async function handleListCerts() {
    setError(null);
    setCertificates([]);
    setSelectedCertId(null);
    setConnected(false);
    setLoading(true);
    try {
      const result = await oscert.list();
      setCertificates(result.certificates);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to list certificates");
    } finally {
      setLoading(false);
    }
  }

  async function handleConnect() {
    if (!selectedCertId) return;
    const cert = certificates.find((c) => c.id === selectedCertId);
    setError(null);
    setLoading(true);
    try {
      const result = await oscert.connect(selectedCertId, cert?.subject);
      signerIdRef.current = result.signerId;
      const signer = createOsCertSigner(result.signerId, result.metadata);
      setConnected(true);
      onSignerReady(signer);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to connect to certificate");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-3">
      <button
        type="button"
        onClick={handleListCerts}
        disabled={loading}
        className="rounded-md bg-gray-700 px-3 py-2 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
      >
        {loading ? "Loading..." : "List Certificates"}
      </button>

      {certificates.length > 0 && (
        <div>
          <label htmlFor="oscert-select" className="block text-sm font-medium text-gray-700">
            Certificate
          </label>
          <select
            id="oscert-select"
            value={selectedCertId ?? ""}
            onChange={(e) => {
              setSelectedCertId(e.target.value || null);
              setConnected(false);
            }}
            className="mt-1 block w-full rounded-md border border-gray-300 px-3 py-2 text-sm shadow-sm focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
          >
            <option value="">Select a certificate...</option>
            {certificates.map((cert) => (
              <option key={cert.id} value={cert.id}>
                {cert.subject} (expires {cert.validUntil})
              </option>
            ))}
          </select>
        </div>
      )}

      {selectedCertId && (
        <button
          type="button"
          onClick={handleConnect}
          disabled={loading || connected}
          className="rounded-md bg-blue-600 px-4 py-2 text-sm text-white hover:bg-blue-700 disabled:opacity-40"
        >
          {connected ? "Connected" : loading ? "Connecting..." : "Connect"}
        </button>
      )}

      {connected && (
        <p className="text-sm text-green-600">OS certificate connected and ready for signing.</p>
      )}

      {error && <p className="text-sm text-red-600">{error}</p>}
    </div>
  );
}
