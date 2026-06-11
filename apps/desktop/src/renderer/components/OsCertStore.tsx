/**
 * OsCertStore — OS certificate store browsing and signing UI.
 *
 * Provides controls for browsing the operating system's certificate store:
 *  - Detect platform (macOS Keychain / Windows Certificate Store)
 *  - Enumerate signing certificates with EC P-256 keys
 *  - Display certificate details (subject, issuer, validity, algorithm)
 *  - Select a certificate for credential signing
 *
 * All operations happen via IPC — the renderer never touches key material.
 * Only certificate metadata (subject, issuer, thumbprint) is displayed.
 * The private key never leaves the OS certificate store.
 */

import { useState } from "react";

/** Certificate info from the IPC response. */
interface CertInfo {
  id: string;
  subject: string;
  issuer: string;
  serialNumber: string;
  validFrom: string;
  validUntil: string;
  keyAlgorithm: string;
  isExportable: boolean;
  thumbprint: string;
}

/** Connected key metadata. */
interface ConnectedKey {
  id: string;
  fingerprint: string;
  algorithm: string;
  label?: string;
}

type Step = "browse" | "certificates" | "connected";

interface OsCertStoreProps {
  onKeyConnected?: () => void;
}

export function OsCertStore({ onKeyConnected }: OsCertStoreProps) {
  const [step, setStep] = useState<Step>("browse");
  const [certificates, setCertificates] = useState<CertInfo[]>([]);
  const [storeName, setStoreName] = useState<string>("");
  const [connectedKey, setConnectedKey] = useState<ConnectedKey | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleBrowseCertStore() {
    setError(null);
    setLoading(true);

    try {
      const result = await window.opencred.osCertList();

      if (!result.success) {
        setError(result.error ?? "Failed to list certificates.");
        setLoading(false);
        return;
      }

      if (!result.certificates || result.certificates.length === 0) {
        setError(
          "No EC P-256 signing certificates found in the " +
            (result.storeName ?? "OS certificate store") +
            ". Import a certificate with an ECDSA P-256 key first.",
        );
        setLoading(false);
        return;
      }

      setCertificates(result.certificates);
      setStoreName(result.storeName ?? "OS Certificate Store");
      setStep("certificates");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to access OS certificate store.");
    } finally {
      setLoading(false);
    }
  }

  async function handleConnect(cert: CertInfo) {
    setError(null);
    setLoading(true);

    try {
      const result = await window.opencred.osCertConnect({
        certificateId: cert.id,
        label: cert.subject || `OS Cert ${cert.thumbprint.slice(0, 8)}`,
      });

      if (!result.success || !result.key) {
        setError(result.error ?? "Failed to connect certificate.");
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
      onKeyConnected?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to connect certificate.");
    } finally {
      setLoading(false);
    }
  }

  function handleReset() {
    setStep("browse");
    setCertificates([]);
    setStoreName("");
    setConnectedKey(null);
    setError(null);
  }

  /**
   * Format an ISO date string for display.
   */
  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        year: "numeric",
        month: "short",
        day: "numeric",
      });
    } catch {
      return iso;
    }
  }

  /**
   * Check if a certificate is currently valid.
   */
  function isCertValid(cert: CertInfo): boolean {
    const now = new Date();
    const from = new Date(cert.validFrom);
    const until = new Date(cert.validUntil);
    return now >= from && now <= until;
  }

  return (
    <div className="rounded-lg border border-border-light bg-white p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-txt-secondary">OS Certificate Store</h2>
        {step !== "browse" && (
          <button
            onClick={handleReset}
            className="text-xs text-txt-muted hover:text-txt-secondary underline"
          >
            Reset
          </button>
        )}
      </div>

      <p className="text-xs text-txt-muted">
        Sign with certificates from your operating system's certificate store. Your private key
        never leaves the OS — signing is performed by the platform's native cryptography subsystem.
      </p>

      {error && <p className="text-sm text-state-danger">{error}</p>}

      {/* Step 1: Browse cert store */}
      {step === "browse" && (
        <div className="space-y-3">
          <button
            onClick={() => void handleBrowseCertStore()}
            disabled={loading}
            className="rounded-md bg-gray-700 px-4 py-1.5 text-sm text-white hover:bg-gray-800 disabled:opacity-40"
          >
            {loading ? "Scanning..." : "Browse Certificate Store"}
          </button>
          <p className="text-xs text-txt-muted">
            Scans for EC P-256 certificates suitable for credential signing.
          </p>
        </div>
      )}

      {/* Step 2: Certificate selection */}
      {step === "certificates" && (
        <div className="space-y-3">
          <label className="block text-xs text-txt-secondary">
            {storeName} — {certificates.length} certificate
            {certificates.length !== 1 ? "s" : ""} found
          </label>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {certificates.map((cert) => {
              const valid = isCertValid(cert);
              return (
                <div
                  key={cert.id}
                  className={`rounded-md border p-3 ${
                    valid
                      ? "border-border-light"
                      : "border-state-warning-border bg-state-warning-bg"
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-txt-secondary truncate">
                        {cert.subject || "Unknown Subject"}
                      </p>
                      <p className="text-xs text-txt-muted truncate">
                        Issuer: {cert.issuer || "Unknown"}
                      </p>
                      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5 text-xs text-txt-muted">
                        <span>Algorithm: {cert.keyAlgorithm}</span>
                        <span>
                          Valid: {formatDate(cert.validFrom)} &ndash; {formatDate(cert.validUntil)}
                        </span>
                        {!valid && (
                          <span className="text-amber-600 font-medium">
                            Expired / Not Yet Valid
                          </span>
                        )}
                        {cert.isExportable && <span className="text-txt-muted">Exportable</span>}
                      </div>
                      <p className="mt-0.5 text-[10px] text-txt-muted font-mono truncate">
                        Thumbprint: {cert.thumbprint}
                      </p>
                    </div>
                    <button
                      onClick={() => void handleConnect(cert)}
                      disabled={loading}
                      className="flex-shrink-0 rounded-md bg-brand px-3 py-1 text-xs text-white hover:bg-brand disabled:opacity-40"
                    >
                      {loading ? "..." : "Use"}
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Step 3: Connected */}
      {step === "connected" && connectedKey && (
        <div className="rounded-md border border-state-success-border bg-state-success-bg p-3 text-xs">
          <p className="font-medium text-state-success">OS certificate connected</p>
          <div className="mt-1 text-state-success space-y-0.5">
            <p>Algorithm: {connectedKey.algorithm}</p>
            {connectedKey.label && <p>Label: {connectedKey.label}</p>}
            <p>Fingerprint: {connectedKey.fingerprint.slice(0, 32)}...</p>
            <p className="font-mono text-[10px] text-state-success break-all">
              ID: {connectedKey.id}
            </p>
          </div>
          <p className="mt-2 text-state-success">
            This certificate is now available for credential signing. Select it from the key list
            when issuing credentials.
          </p>
        </div>
      )}
    </div>
  );
}
