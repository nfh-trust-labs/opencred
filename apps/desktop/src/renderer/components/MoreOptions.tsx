/**
 * MoreOptions — collapsible "More options" section for proof format,
 * selective disclosure, revocation URL, and schema URL.
 *
 * Shared between single and batch issuance.
 */

import { useState } from "react";
import type { UiProofFormat } from "../../shared/ipc-types";

interface MoreOptionsProps {
  keyAlgorithm: string | undefined;
  proofFormat: UiProofFormat;
  onProofFormatChange: (format: UiProofFormat) => void;
  subjectFieldNames: string[];
  selectiveDisclosureClaims: string[];
  onSelectiveDisclosureChange: (claims: string[]) => void;
  revocationRegistryUrl: string;
  onRevocationRegistryUrlChange: (url: string) => void;
  credentialSchemaUrl: string;
  onCredentialSchemaUrlChange: (url: string) => void;
  disabled?: boolean;
}

const PROOF_FORMAT_LABELS: Record<UiProofFormat, string> = {
  "vc-jwt": "VC-JWT",
  "data-integrity": "Data Integrity",
  "jws-2020": "JWS 2020",
  "sd-jwt-vc": "SD-JWT-VC",
};

const PROOF_FORMAT_HINTS: Record<UiProofFormat, string> = {
  "vc-jwt": "Most widely supported format. Works with standard JWT libraries.",
  "data-integrity": "Uses JSON-LD canonicalization. Required for linked data ecosystems.",
  "jws-2020":
    "JsonWebSignature2020 embedded proof with a detached JWS. Required by some verifier ecosystems.",
  "sd-jwt-vc": "Allows holders to selectively disclose individual fields.",
};

function isRsa(algorithm: string | undefined): boolean {
  return !!algorithm && algorithm.startsWith("RSA");
}

function validateUrl(value: string, requireHttps: boolean): string | null {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (requireHttps && url.protocol !== "https:") {
      return "Must be an HTTPS URL";
    }
    return null;
  } catch {
    return "Invalid URL";
  }
}

export function MoreOptions({
  keyAlgorithm,
  proofFormat,
  onProofFormatChange,
  subjectFieldNames,
  selectiveDisclosureClaims,
  onSelectiveDisclosureChange,
  revocationRegistryUrl,
  onRevocationRegistryUrlChange,
  credentialSchemaUrl,
  onCredentialSchemaUrlChange,
  disabled,
}: MoreOptionsProps) {
  const [open, setOpen] = useState(false);

  const revocationError = validateUrl(revocationRegistryUrl, true);
  const schemaError = validateUrl(credentialSchemaUrl, false);
  const isDataIntegrityDisabled = isRsa(keyAlgorithm);

  function handleProofFormatChange(format: UiProofFormat) {
    if (format === "data-integrity" && isDataIntegrityDisabled) return;
    onProofFormatChange(format);
    // Clear SD claims when switching away from SD-JWT-VC
    if (format !== "sd-jwt-vc" && selectiveDisclosureClaims.length > 0) {
      onSelectiveDisclosureChange([]);
    }
  }

  function toggleSdClaim(fieldName: string) {
    if (selectiveDisclosureClaims.includes(fieldName)) {
      onSelectiveDisclosureChange(selectiveDisclosureClaims.filter((c) => c !== fieldName));
    } else {
      onSelectiveDisclosureChange([...selectiveDisclosureClaims, fieldName]);
    }
  }

  return (
    <div>
      <button
        type="button"
        className="oc-more-options-trigger"
        onClick={() => setOpen((prev) => !prev)}
      >
        More options
        <svg
          className={`oc-more-options-chevron ${open ? "open" : ""}`}
          width="14"
          height="14"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {open && (
        <div
          style={{
            marginTop: 4,
            padding: "16px 20px",
            border: "1px solid var(--oc-border-light)",
            borderRadius: "var(--oc-radius)",
            backgroundColor: "var(--oc-bg)",
          }}
          className="space-y-4"
        >
          {/* Proof Format */}
          <div>
            <label className="block text-xs font-medium text-txt-secondary mb-1">
              Proof Format
            </label>
            <select
              value={proofFormat}
              onChange={(e) => handleProofFormatChange(e.target.value as UiProofFormat)}
              disabled={disabled}
              className="block w-full rounded-md border border-border bg-white px-3 py-2 text-sm shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500 disabled:bg-surface-warm"
            >
              {(Object.keys(PROOF_FORMAT_LABELS) as UiProofFormat[]).map((fmt) => (
                <option
                  key={fmt}
                  value={fmt}
                  disabled={fmt === "data-integrity" && isDataIntegrityDisabled}
                >
                  {PROOF_FORMAT_LABELS[fmt]}
                  {fmt === "data-integrity" && isDataIntegrityDisabled
                    ? " (not available for RSA)"
                    : ""}
                </option>
              ))}
            </select>
            <p className="mt-1 text-xs text-txt-muted">{PROOF_FORMAT_HINTS[proofFormat]}</p>
          </div>

          {/* SD-JWT-VC selective disclosure toggles */}
          {proofFormat === "sd-jwt-vc" && subjectFieldNames.length > 0 && (
            <div>
              <label className="block text-xs font-medium text-txt-secondary mb-1">
                Select fields the holder can selectively disclose
              </label>
              <div className="space-y-1">
                {subjectFieldNames.map((fieldName) => (
                  <label
                    key={fieldName}
                    className="flex items-center gap-2 text-xs text-txt-secondary cursor-pointer"
                  >
                    <input
                      type="checkbox"
                      checked={selectiveDisclosureClaims.includes(fieldName)}
                      onChange={() => toggleSdClaim(fieldName)}
                      disabled={disabled}
                      className="rounded border-border"
                    />
                    {fieldName}
                  </label>
                ))}
              </div>
            </div>
          )}

          {/* Revocation Registry URL */}
          <div>
            <label className="block text-xs font-medium text-txt-secondary mb-1">
              Revocation Registry URL
            </label>
            <input
              type="url"
              value={revocationRegistryUrl}
              onChange={(e) => onRevocationRegistryUrlChange(e.target.value)}
              placeholder="https://dedi.example/revocations/..."
              disabled={disabled}
              className="block w-full rounded-md border border-border px-3 py-2 text-sm shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500 disabled:bg-surface-warm"
            />
            {revocationError && <p className="mt-1 text-xs text-state-danger">{revocationError}</p>}
          </div>

          {/* Credential Schema URL */}
          <div>
            <label className="block text-xs font-medium text-txt-secondary mb-1">
              Credential Schema URL
            </label>
            <input
              type="url"
              value={credentialSchemaUrl}
              onChange={(e) => onCredentialSchemaUrlChange(e.target.value)}
              placeholder="https://example.com/schemas/education.json"
              disabled={disabled}
              className="block w-full rounded-md border border-border px-3 py-2 text-sm shadow-sm focus:border-brand focus:ring-1 focus:ring-blue-500 disabled:bg-surface-warm"
            />
            {schemaError && <p className="mt-1 text-xs text-state-danger">{schemaError}</p>}
          </div>
        </div>
      )}
    </div>
  );
}
