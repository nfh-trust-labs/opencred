/**
 * BrandingSettings — issuer branding customization for credential templates.
 *
 * Allows configuring:
 *  - Colors: primary, secondary, background, text, label
 *  - Logo: file upload with preview + width/height controls
 *  - Issuer display name
 *  - Footer text
 *  - Seal/badge image
 *
 * Includes a live preview card showing how branding will appear on credentials.
 * Settings are persisted to electron-store under the "branding" key.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";

const DEFAULT_PRIMARY = "#0057FF";
const DEFAULT_BACKGROUND = "#ffffff";
const DEFAULT_SECONDARY = "#2d5986";
const DEFAULT_TEXT = "#1a202c";
const DEFAULT_LABEL = "#718096";
const MAX_LOGO_SIZE_BYTES = 512 * 1024; // 512 KB
const MAX_FOOTER_LENGTH = 500;

/** Validate a CSS hex color string (3, 4, 6, or 8 hex digits). */
function isValidHexColor(value: string): boolean {
  return /^#([0-9A-Fa-f]{3}|[0-9A-Fa-f]{4}|[0-9A-Fa-f]{6}|[0-9A-Fa-f]{8})$/.test(value);
}

/**
 * Validate a data URI for an image. Raster formats only — SVG is rejected
 * because the template renderer refuses SVG data URIs (nested SVG can carry
 * script), so accepting one here would silently drop the logo at export time.
 */
function isValidImageDataUri(value: string): boolean {
  return /^data:image\/(png|jpeg|jpg|webp);base64,/.test(value);
}

interface BrandingState {
  primaryColor?: string;
  logoDataUri?: string;
  issuerDisplayName?: string;
  backgroundColor?: string;
  secondaryColor?: string;
  textColor?: string;
  labelColor?: string;
  logoWidth?: number;
  logoHeight?: number;
  footerText?: string;
  sealDataUri?: string;
}

export function BrandingSettings() {
  const [branding, setBranding] = useState<BrandingState>({});
  const [colorInput, setColorInput] = useState(DEFAULT_PRIMARY);
  const [bgColorInput, setBgColorInput] = useState(DEFAULT_BACKGROUND);
  const [secColorInput, setSecColorInput] = useState(DEFAULT_SECONDARY);
  const [txtColorInput, setTxtColorInput] = useState(DEFAULT_TEXT);
  const [lblColorInput, setLblColorInput] = useState(DEFAULT_LABEL);
  const [colorError, setColorError] = useState<string | null>(null);
  const [logoError, setLogoError] = useState<string | null>(null);
  const [sealError, setSealError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [saving, setSaving] = useState(false);
  const saveTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const sealInputRef = useRef<HTMLInputElement>(null);

  const loadBranding = useCallback(async () => {
    try {
      const stored = (await window.opencred.getConfig("branding")) as BrandingState | undefined;
      if (stored) {
        setBranding(stored);
        setColorInput(stored.primaryColor ?? DEFAULT_PRIMARY);
        setBgColorInput(stored.backgroundColor ?? DEFAULT_BACKGROUND);
        setSecColorInput(stored.secondaryColor ?? DEFAULT_SECONDARY);
        setTxtColorInput(stored.textColor ?? DEFAULT_TEXT);
        setLblColorInput(stored.labelColor ?? DEFAULT_LABEL);
      }
    } catch {
      // non-fatal
    }
  }, []);

  useEffect(() => {
    void loadBranding();
  }, [loadBranding]);

  // Debounced save
  const saveBranding = useCallback((updated: BrandingState) => {
    if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
    saveTimerRef.current = setTimeout(() => {
      void (async () => {
        setSaving(true);
        try {
          const toSave: BrandingState = {};
          if (updated.primaryColor && updated.primaryColor !== DEFAULT_PRIMARY) {
            toSave.primaryColor = updated.primaryColor;
          }
          if (updated.backgroundColor && updated.backgroundColor !== DEFAULT_BACKGROUND) {
            toSave.backgroundColor = updated.backgroundColor;
          }
          if (updated.secondaryColor && updated.secondaryColor !== DEFAULT_SECONDARY) {
            toSave.secondaryColor = updated.secondaryColor;
          }
          if (updated.textColor && updated.textColor !== DEFAULT_TEXT) {
            toSave.textColor = updated.textColor;
          }
          if (updated.labelColor && updated.labelColor !== DEFAULT_LABEL) {
            toSave.labelColor = updated.labelColor;
          }
          if (updated.logoDataUri) toSave.logoDataUri = updated.logoDataUri;
          if (updated.logoWidth && updated.logoWidth !== 60) toSave.logoWidth = updated.logoWidth;
          if (updated.logoHeight && updated.logoHeight !== 60)
            toSave.logoHeight = updated.logoHeight;
          if (updated.issuerDisplayName?.trim()) {
            toSave.issuerDisplayName = updated.issuerDisplayName.trim();
          }
          if (updated.footerText?.trim()) {
            toSave.footerText = updated.footerText.trim();
          }
          if (updated.sealDataUri) toSave.sealDataUri = updated.sealDataUri;

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
  }, []);

  function handleColorFieldChange(
    field: keyof BrandingState,
    hex: string,
    setter: (v: string) => void,
  ) {
    setter(hex);
    setColorError(null);
    if (isValidHexColor(hex)) {
      const updated = { ...branding, [field]: hex };
      setBranding(updated);
      saveBranding(updated);
    } else if (hex.length >= 4) {
      setColorError("Enter a valid hex color (e.g. #0057FF)");
    }
  }

  function handleColorPickerFieldChange(
    field: keyof BrandingState,
    hex: string,
    setter: (v: string) => void,
  ) {
    setter(hex);
    setColorError(null);
    const updated = { ...branding, [field]: hex };
    setBranding(updated);
    saveBranding(updated);
  }

  function handleImageSelect(
    e: React.ChangeEvent<HTMLInputElement>,
    field: "logoDataUri" | "sealDataUri",
    setError: (v: string | null) => void,
  ) {
    const file = e.target.files?.[0];
    if (!file) return;

    setError(null);

    if (!file.type.startsWith("image/")) {
      setError("Please select an image file (PNG, JPG, or WebP).");
      return;
    }

    if (file.size > MAX_LOGO_SIZE_BYTES) {
      setError("Image must be under 512 KB.");
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const dataUri = reader.result as string;
      if (!isValidImageDataUri(dataUri)) {
        setError("Unsupported image format.");
        return;
      }
      const updated = { ...branding, [field]: dataUri };
      setBranding(updated);
      saveBranding(updated);
    };
    reader.onerror = () => {
      setError("Failed to read file.");
    };
    reader.readAsDataURL(file);

    e.target.value = "";
  }

  function handleRemoveImage(field: "logoDataUri" | "sealDataUri") {
    const updated = { ...branding, [field]: undefined };
    setBranding(updated);
    saveBranding(updated);
  }

  function handleDisplayNameChange(name: string) {
    const updated = { ...branding, issuerDisplayName: name };
    setBranding(updated);
    saveBranding(updated);
  }

  function handleFooterTextChange(text: string) {
    if (text.length > MAX_FOOTER_LENGTH) return;
    const updated = { ...branding, footerText: text };
    setBranding(updated);
    saveBranding(updated);
  }

  function handleLogoDimensionChange(dim: "logoWidth" | "logoHeight", value: string) {
    const num = parseInt(value, 10);
    if (isNaN(num)) return;
    const clamped = Math.min(200, Math.max(10, num));
    const updated = { ...branding, [dim]: clamped };
    setBranding(updated);
    saveBranding(updated);
  }

  function handleResetDefaults() {
    const reset: BrandingState = {};
    setBranding(reset);
    setColorInput(DEFAULT_PRIMARY);
    setBgColorInput(DEFAULT_BACKGROUND);
    setSecColorInput(DEFAULT_SECONDARY);
    setTxtColorInput(DEFAULT_TEXT);
    setLblColorInput(DEFAULT_LABEL);
    setColorError(null);
    setLogoError(null);
    setSealError(null);
    saveBranding(reset);
  }

  const effectiveColor = branding.primaryColor ?? DEFAULT_PRIMARY;
  const effectiveBg = branding.backgroundColor ?? DEFAULT_BACKGROUND;
  const effectiveText = branding.textColor ?? DEFAULT_TEXT;
  const effectiveLabel = branding.labelColor ?? DEFAULT_LABEL;

  const colorPickerClass = "h-9 w-9 cursor-pointer rounded border border-border p-0.5";
  const hexInputClass =
    "w-28 rounded border border-border px-3 py-2 text-sm font-mono text-txt-primary placeholder:text-txt-muted focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue";
  const textInputClass =
    "w-full max-w-sm rounded border border-border px-3 py-2 text-sm text-txt-primary placeholder:text-txt-muted focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue";
  const numberInputClass =
    "w-20 rounded border border-border px-3 py-2 text-sm font-mono text-txt-primary focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue";

  return (
    <Card className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-medium text-txt-secondary">Credential Branding</h2>
          <p className="text-xs text-txt-muted mt-0.5">
            Customize how your credentials look when exported as SVG or PDF.
          </p>
        </div>
        {saved && (
          <span className="flex items-center gap-1 text-xs text-state-success">
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
        {saving && <span className="text-xs text-txt-muted">Saving...</span>}
      </div>

      {/* ---- Colors Section ---- */}
      <div className="space-y-3">
        <h3 className="text-xs font-semibold text-txt-muted uppercase tracking-wide">Colors</h3>

        {/* Primary Color */}
        <div className="space-y-1">
          <label className="block text-xs font-medium text-txt-secondary">Primary</label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={isValidHexColor(colorInput) ? colorInput : DEFAULT_PRIMARY}
              onChange={(e) =>
                handleColorPickerFieldChange("primaryColor", e.target.value, setColorInput)
              }
              className={colorPickerClass}
            />
            <input
              type="text"
              value={colorInput}
              onChange={(e) =>
                handleColorFieldChange("primaryColor", e.target.value, setColorInput)
              }
              placeholder="#0057FF"
              maxLength={9}
              className={hexInputClass}
            />
            <span className="text-xs text-txt-muted">Default: {DEFAULT_PRIMARY}</span>
          </div>
        </div>

        {/* Secondary Color */}
        <div className="space-y-1">
          <label className="block text-xs font-medium text-txt-secondary">Secondary</label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={isValidHexColor(secColorInput) ? secColorInput : DEFAULT_SECONDARY}
              onChange={(e) =>
                handleColorPickerFieldChange("secondaryColor", e.target.value, setSecColorInput)
              }
              className={colorPickerClass}
            />
            <input
              type="text"
              value={secColorInput}
              onChange={(e) =>
                handleColorFieldChange("secondaryColor", e.target.value, setSecColorInput)
              }
              placeholder={DEFAULT_SECONDARY}
              maxLength={9}
              className={hexInputClass}
            />
            <span className="text-xs text-txt-muted">Subheadings</span>
          </div>
        </div>

        {/* Background Color */}
        <div className="space-y-1">
          <label className="block text-xs font-medium text-txt-secondary">Background</label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={isValidHexColor(bgColorInput) ? bgColorInput : DEFAULT_BACKGROUND}
              onChange={(e) =>
                handleColorPickerFieldChange("backgroundColor", e.target.value, setBgColorInput)
              }
              className={colorPickerClass}
            />
            <input
              type="text"
              value={bgColorInput}
              onChange={(e) =>
                handleColorFieldChange("backgroundColor", e.target.value, setBgColorInput)
              }
              placeholder={DEFAULT_BACKGROUND}
              maxLength={9}
              className={hexInputClass}
            />
            <span className="text-xs text-txt-muted">Page background</span>
          </div>
        </div>

        {/* Text Color */}
        <div className="space-y-1">
          <label className="block text-xs font-medium text-txt-secondary">Text</label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={isValidHexColor(txtColorInput) ? txtColorInput : DEFAULT_TEXT}
              onChange={(e) =>
                handleColorPickerFieldChange("textColor", e.target.value, setTxtColorInput)
              }
              className={colorPickerClass}
            />
            <input
              type="text"
              value={txtColorInput}
              onChange={(e) =>
                handleColorFieldChange("textColor", e.target.value, setTxtColorInput)
              }
              placeholder={DEFAULT_TEXT}
              maxLength={9}
              className={hexInputClass}
            />
            <span className="text-xs text-txt-muted">Main text</span>
          </div>
        </div>

        {/* Label Color */}
        <div className="space-y-1">
          <label className="block text-xs font-medium text-txt-secondary">Label</label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={isValidHexColor(lblColorInput) ? lblColorInput : DEFAULT_LABEL}
              onChange={(e) =>
                handleColorPickerFieldChange("labelColor", e.target.value, setLblColorInput)
              }
              className={colorPickerClass}
            />
            <input
              type="text"
              value={lblColorInput}
              onChange={(e) =>
                handleColorFieldChange("labelColor", e.target.value, setLblColorInput)
              }
              placeholder={DEFAULT_LABEL}
              maxLength={9}
              className={hexInputClass}
            />
            <span className="text-xs text-txt-muted">Field labels</span>
          </div>
        </div>

        {colorError && <p className="text-xs text-state-danger">{colorError}</p>}
      </div>

      {/* ---- Logo Section ---- */}
      <div className="space-y-3">
        <h3 className="text-xs font-semibold text-txt-muted uppercase tracking-wide">Logo</h3>

        <div className="space-y-1.5">
          {branding.logoDataUri ? (
            <div className="flex items-center gap-3">
              <div className="h-12 w-12 rounded border border-border-light bg-surface-warm flex items-center justify-center overflow-hidden">
                <img
                  src={branding.logoDataUri}
                  alt="Logo preview"
                  className="max-h-full max-w-full object-contain"
                />
              </div>
              <button
                onClick={() => handleRemoveImage("logoDataUri")}
                className="text-xs font-medium text-state-danger hover:text-state-danger hover:underline"
              >
                Remove
              </button>
            </div>
          ) : (
            <div>
              <button
                onClick={() => fileInputRef.current?.click()}
                className="px-3 py-1.5 text-xs font-medium text-txt-primary bg-surface-card border border-border-default rounded hover:bg-surface-warm transition-colors"
              >
                Upload Logo
              </button>
              <span className="ml-2 text-xs text-txt-muted">PNG, JPG, or WebP (max 512 KB)</span>
            </div>
          )}
          <input
            ref={fileInputRef}
            type="file"
            accept="image/png,image/jpeg,image/webp"
            onChange={(e) => handleImageSelect(e, "logoDataUri", setLogoError)}
            className="hidden"
          />
          {logoError && <p className="text-xs text-state-danger">{logoError}</p>}
        </div>

        {/* Logo dimensions */}
        <div className="flex items-center gap-4">
          <div className="space-y-1">
            <label className="block text-xs font-medium text-txt-secondary">Width (px)</label>
            <input
              type="number"
              min={10}
              max={200}
              value={branding.logoWidth ?? 60}
              onChange={(e) => handleLogoDimensionChange("logoWidth", e.target.value)}
              className={numberInputClass}
            />
          </div>
          <div className="space-y-1">
            <label className="block text-xs font-medium text-txt-secondary">Height (px)</label>
            <input
              type="number"
              min={10}
              max={200}
              value={branding.logoHeight ?? 60}
              onChange={(e) => handleLogoDimensionChange("logoHeight", e.target.value)}
              className={numberInputClass}
            />
          </div>
          <span className="text-xs text-txt-muted self-end pb-2">10 - 200 px</span>
        </div>
      </div>

      {/* ---- Identity Section ---- */}
      <div className="space-y-3">
        <h3 className="text-xs font-semibold text-txt-muted uppercase tracking-wide">Identity</h3>

        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-txt-secondary">
            Issuer Display Name
          </label>
          <input
            type="text"
            value={branding.issuerDisplayName ?? ""}
            onChange={(e) => handleDisplayNameChange(e.target.value)}
            placeholder="e.g. Acme University"
            className={textInputClass}
          />
          <p className="text-xs text-txt-muted">
            Shown on credential templates. Falls back to your organization name if empty.
          </p>
        </div>
      </div>

      {/* ---- Extras Section ---- */}
      <div className="space-y-3">
        <h3 className="text-xs font-semibold text-txt-muted uppercase tracking-wide">Extras</h3>

        {/* Footer Text */}
        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-txt-secondary">Footer Text</label>
          <input
            type="text"
            value={branding.footerText ?? ""}
            onChange={(e) => handleFooterTextChange(e.target.value)}
            placeholder="Custom footer text for PDF certificates"
            maxLength={MAX_FOOTER_LENGTH}
            className={textInputClass}
          />
          <p className="text-xs text-txt-muted">
            Appears at the bottom of PDF certificates. Max {MAX_FOOTER_LENGTH} characters.
          </p>
        </div>

        {/* Seal Upload */}
        <div className="space-y-1.5">
          <label className="block text-xs font-medium text-txt-secondary">Seal / Badge</label>
          {branding.sealDataUri ? (
            <div className="flex items-center gap-3">
              <div className="h-12 w-12 rounded border border-border-light bg-surface-warm flex items-center justify-center overflow-hidden">
                <img
                  src={branding.sealDataUri}
                  alt="Seal preview"
                  className="max-h-full max-w-full object-contain"
                />
              </div>
              <button
                onClick={() => handleRemoveImage("sealDataUri")}
                className="text-xs font-medium text-state-danger hover:text-state-danger hover:underline"
              >
                Remove
              </button>
            </div>
          ) : (
            <div>
              <button
                onClick={() => sealInputRef.current?.click()}
                className="px-3 py-1.5 text-xs font-medium text-txt-primary bg-surface-card border border-border-default rounded hover:bg-surface-warm transition-colors"
              >
                Upload Seal
              </button>
              <span className="ml-2 text-xs text-txt-muted">PNG, JPG, or WebP (max 512 KB)</span>
            </div>
          )}
          <input
            ref={sealInputRef}
            type="file"
            accept="image/png,image/jpeg,image/webp"
            onChange={(e) => handleImageSelect(e, "sealDataUri", setSealError)}
            className="hidden"
          />
          {sealError && <p className="text-xs text-state-danger">{sealError}</p>}
        </div>
      </div>

      {/* ---- Live Preview ---- */}
      <div className="space-y-1.5">
        <h3 className="text-xs font-semibold text-txt-muted uppercase tracking-wide">Preview</h3>
        <div
          className="rounded border border-border-light p-4 max-w-sm"
          style={{ backgroundColor: effectiveBg }}
        >
          {/* Color bar */}
          <div className="h-2 rounded-full mb-3" style={{ backgroundColor: effectiveColor }} />
          <div className="flex items-center gap-3">
            {branding.logoDataUri ? (
              <div className="h-10 w-10 rounded border border-border-light flex items-center justify-center overflow-hidden flex-shrink-0">
                <img
                  src={branding.logoDataUri}
                  alt=""
                  className="max-h-full max-w-full object-contain"
                />
              </div>
            ) : (
              <div className="h-10 w-10 rounded border border-dashed border-border flex items-center justify-center flex-shrink-0">
                <span className="text-[10px] text-txt-muted">Logo</span>
              </div>
            )}
            <div>
              <p className="text-sm font-medium" style={{ color: effectiveText }}>
                {branding.issuerDisplayName || "Your Organization"}
              </p>
              <p className="text-xs" style={{ color: effectiveLabel }}>
                Verifiable Credential
              </p>
            </div>
          </div>
          {branding.sealDataUri && (
            <div className="mt-3 flex justify-center">
              <img src={branding.sealDataUri} alt="" className="h-8 w-8 object-contain" />
            </div>
          )}
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
