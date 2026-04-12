/**
 * BrandingSettings — issuer branding customization for credential templates.
 *
 * Allows configuring:
 *  - Primary color (color picker + hex input)
 *  - Logo (file upload with preview, PNG/SVG/JPG)
 *  - Issuer display name
 *
 * Includes a live preview card showing how branding will appear on credentials.
 * Settings are persisted to electron-store under the "branding" key.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";

const DEFAULT_COLOR = "#0057FF";
const MAX_LOGO_SIZE_BYTES = 512 * 1024; // 512 KB

/** Validate a CSS hex color string (3, 4, 6, or 8 hex digits). */
function isValidHexColor(value: string): boolean {
  return /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{4}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$/.test(value);
}

/** Validate a data URI for an image. */
function isValidImageDataUri(value: string): boolean {
  return /^data:image\/(png|jpeg|jpg|svg\+xml|webp);base64,/.test(value);
}

interface BrandingState {
  primaryColor?: string;
  logoDataUri?: string;
  issuerDisplayName?: string;
}

export function BrandingSettings() {
  const [branding, setBranding] = useState<BrandingState>({});
  const [colorInput, setColorInput] = useState(DEFAULT_COLOR);
  const [colorError, setColorError] = useState<string | null>(null);
  const [logoError, setLogoError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadBranding = useCallback(async () => {
    try {
      const stored = (await window.opencred.getConfig("branding")) as BrandingState | undefined;
      if (stored) {
        setBranding(stored);
        setColorInput(stored.primaryColor ?? DEFAULT_COLOR);
      }
    } catch {
      // non-fatal
    }
  }, []);

  useEffect(() => {
    void loadBranding();
  }, [loadBranding]);

  // Debounced save
  const saveBranding = useCallback(
    (updated: BrandingState) => {
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
      saveTimerRef.current = setTimeout(() => {
        void (async () => {
          setSaving(true);
          try {
            // Only persist non-empty fields
            const toSave: BrandingState = {};
            if (updated.primaryColor && updated.primaryColor !== DEFAULT_COLOR) {
              toSave.primaryColor = updated.primaryColor;
            }
            if (updated.logoDataUri) toSave.logoDataUri = updated.logoDataUri;
            if (updated.issuerDisplayName?.trim()) {
              toSave.issuerDisplayName = updated.issuerDisplayName.trim();
            }

            const hasValues = Object.keys(toSave).length > 0;
            await window.opencred.setConfig("branding", hasValues ? toSave : undefined);
            setSaved(true);
            setTimeout(() => setSaved(false), 2000);
          } catch {
            // non-fatal
          } finally {
            setSaving(false);
          }
        })();
      }, 600);
    },
    [],
  );

  function handleColorChange(hex: string) {
    setColorInput(hex);
    setColorError(null);
    if (isValidHexColor(hex)) {
      const updated = { ...branding, primaryColor: hex };
      setBranding(updated);
      saveBranding(updated);
    } else if (hex.length >= 4) {
      setColorError("Enter a valid hex color (e.g. #0057FF)");
    }
  }

  function handleColorPickerChange(hex: string) {
    setColorInput(hex);
    setColorError(null);
    const updated = { ...branding, primaryColor: hex };
    setBranding(updated);
    saveBranding(updated);
  }

  function handleLogoSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;

    setLogoError(null);

    if (!file.type.startsWith("image/")) {
      setLogoError("Please select an image file (PNG, JPG, or SVG).");
      return;
    }

    if (file.size > MAX_LOGO_SIZE_BYTES) {
      setLogoError("Logo must be under 512 KB.");
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const dataUri = reader.result as string;
      if (!isValidImageDataUri(dataUri)) {
        setLogoError("Unsupported image format.");
        return;
      }
      const updated = { ...branding, logoDataUri: dataUri };
      setBranding(updated);
      saveBranding(updated);
    };
    reader.onerror = () => {
      setLogoError("Failed to read file.");
    };
    reader.readAsDataURL(file);

    // Reset input so the same file can be re-selected
    e.target.value = "";
  }

  function handleRemoveLogo() {
    const updated = { ...branding, logoDataUri: undefined };
    setBranding(updated);
    saveBranding(updated);
  }

  function handleDisplayNameChange(name: string) {
    const updated = { ...branding, issuerDisplayName: name };
    setBranding(updated);
    saveBranding(updated);
  }

  function handleResetDefaults() {
    const reset: BrandingState = {};
    setBranding(reset);
    setColorInput(DEFAULT_COLOR);
    setColorError(null);
    setLogoError(null);
    saveBranding(reset);
  }

  const effectiveColor = branding.primaryColor ?? DEFAULT_COLOR;

  return (
    <Card className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-medium text-gray-700">Credential Branding</h2>
          <p className="text-xs text-gray-500 mt-0.5">
            Customize how your credentials look when exported as SVG or PDF.
          </p>
        </div>
        {saved && (
          <span className="flex items-center gap-1 text-xs text-green-600">
            <svg
              width="14"
              height="14"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth={2.5}
            >
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
            Saved
          </span>
        )}
        {saving && <span className="text-xs text-gray-400">Saving...</span>}
      </div>

      {/* Primary Color */}
      <div className="space-y-1.5">
        <label className="block text-xs font-medium text-gray-600">Primary Color</label>
        <div className="flex items-center gap-2">
          <input
            type="color"
            value={isValidHexColor(colorInput) ? colorInput : DEFAULT_COLOR}
            onChange={(e) => handleColorPickerChange(e.target.value)}
            className="h-9 w-9 cursor-pointer rounded border border-gray-300 p-0.5"
          />
          <input
            type="text"
            value={colorInput}
            onChange={(e) => handleColorChange(e.target.value)}
            placeholder="#0057FF"
            maxLength={9}
            className="w-28 rounded border border-gray-300 px-3 py-2 text-sm font-mono text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue"
          />
          <span className="text-xs text-gray-400">Default: {DEFAULT_COLOR}</span>
        </div>
        {colorError && <p className="text-xs text-red-600">{colorError}</p>}
      </div>

      {/* Logo Upload */}
      <div className="space-y-1.5">
        <label className="block text-xs font-medium text-gray-600">Logo</label>
        {branding.logoDataUri ? (
          <div className="flex items-center gap-3">
            <div className="h-12 w-12 rounded border border-gray-200 bg-gray-50 flex items-center justify-center overflow-hidden">
              <img
                src={branding.logoDataUri}
                alt="Logo preview"
                className="max-h-full max-w-full object-contain"
              />
            </div>
            <button
              onClick={handleRemoveLogo}
              className="text-xs font-medium text-red-600 hover:text-red-700 hover:underline"
            >
              Remove
            </button>
          </div>
        ) : (
          <div>
            <button
              onClick={() => fileInputRef.current?.click()}
              className="px-3 py-1.5 text-xs font-medium text-txt-primary bg-surface-card border border-border-default rounded hover:bg-gray-100 transition-colors"
            >
              Upload Logo
            </button>
            <span className="ml-2 text-xs text-gray-400">PNG, JPG, or SVG (max 512 KB)</span>
          </div>
        )}
        <input
          ref={fileInputRef}
          type="file"
          accept="image/png,image/jpeg,image/svg+xml"
          onChange={handleLogoSelect}
          className="hidden"
        />
        {logoError && <p className="text-xs text-red-600">{logoError}</p>}
      </div>

      {/* Display Name */}
      <div className="space-y-1.5">
        <label className="block text-xs font-medium text-gray-600">Issuer Display Name</label>
        <input
          type="text"
          value={branding.issuerDisplayName ?? ""}
          onChange={(e) => handleDisplayNameChange(e.target.value)}
          placeholder="e.g. Acme University"
          className="w-full max-w-sm rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue"
        />
        <p className="text-xs text-gray-400">
          Shown on credential templates. Falls back to your organization name if empty.
        </p>
      </div>

      {/* Live Preview */}
      <div className="space-y-1.5">
        <label className="block text-xs font-medium text-gray-600">Preview</label>
        <div className="rounded border border-gray-200 bg-white p-4 max-w-sm">
          {/* Color bar */}
          <div
            className="h-2 rounded-full mb-3"
            style={{ backgroundColor: effectiveColor }}
          />
          <div className="flex items-center gap-3">
            {/* Logo */}
            {branding.logoDataUri ? (
              <div className="h-10 w-10 rounded border border-gray-100 flex items-center justify-center overflow-hidden flex-shrink-0">
                <img
                  src={branding.logoDataUri}
                  alt=""
                  className="max-h-full max-w-full object-contain"
                />
              </div>
            ) : (
              <div className="h-10 w-10 rounded border border-dashed border-gray-300 flex items-center justify-center flex-shrink-0">
                <span className="text-[10px] text-gray-300">Logo</span>
              </div>
            )}
            {/* Name + credential title */}
            <div>
              <p className="text-sm font-medium text-gray-800">
                {branding.issuerDisplayName || "Your Organization"}
              </p>
              <p className="text-xs text-gray-400">Verifiable Credential</p>
            </div>
          </div>
        </div>
      </div>

      {/* Reset */}
      <div className="pt-1">
        <Button variant="secondary" size="sm" onClick={handleResetDefaults}>
          Reset to Defaults
        </Button>
      </div>
    </Card>
  );
}
