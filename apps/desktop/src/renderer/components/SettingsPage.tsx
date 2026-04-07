/**
 * SettingsPage — key management and application settings.
 *
 * Provides:
 *  - Full key management UI via KeyManagement component (4 tabs:
 *    Import File, Hardware Token, OS Cert Store, Generate Key)
 *  - Software update card with check/download/install flow
 *  - Network status indicator
 *  - Help & Support card with bug reporting
 *  - About card
 *
 * All key operations happen via IPC. Only metadata (ID, fingerprint,
 * algorithm, source) is displayed. Private keys NEVER reach the renderer.
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { Card } from "./ui/Card";
import { Button } from "./ui/Button";
import { KeyManagement } from "./KeyManagement";
import { BugReportDialog } from "./BugReportDialog";
import type {
  BrandingGetResponse,
  BrandingSetRequest,
  DeDiStatusResponse,
  IssuerBrandingPayload,
  UpdateStatusResponse,
} from "../../shared/ipc-types";

const DEDI_BASE_URL = "https://api.dedi.global";

// ---------------------------------------------------------------------------
// Branding constants — keep in sync with apps/desktop/src/main/branding.ts
// ---------------------------------------------------------------------------

const HEX_COLOR_RE = /^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$/;
const ACCEPTED_LOGO_MIME = ["image/png", "image/svg+xml"] as const;
const MAX_LOGO_RAW_BYTES = 1024 * 1024;
const MAX_LOGO_PIXEL_DIMENSION = 1024;
const DEFAULT_PRIMARY_COLOR = "#1a56db";
const DEFAULT_ACCENT_COLOR = "#0ea5e9";

/**
 * Read a `File` (PNG or SVG) into a base64 string. Returns `null` if the
 * read fails or the file is too large.
 */
function readFileAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Could not read file."));
    reader.onload = () => {
      const result = reader.result;
      if (typeof result !== "string") {
        reject(new Error("Unexpected file read result."));
        return;
      }
      // FileReader.readAsDataURL → "data:<mime>;base64,<payload>"
      const comma = result.indexOf(",");
      if (comma === -1) {
        reject(new Error("Invalid file data."));
        return;
      }
      resolve(result.slice(comma + 1));
    };
    reader.readAsDataURL(file);
  });
}

/**
 * Verify a PNG `File` is within `MAX_LOGO_PIXEL_DIMENSION` x
 * `MAX_LOGO_PIXEL_DIMENSION`. Resolves `true` if the dimensions are
 * acceptable. Resolves `false` if the image is too large or fails to load.
 */
function checkPngDimensions(file: File): Promise<{ ok: boolean; width?: number; height?: number; error?: string }> {
  return new Promise((resolve) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      const ok = img.width <= MAX_LOGO_PIXEL_DIMENSION && img.height <= MAX_LOGO_PIXEL_DIMENSION;
      resolve({
        ok,
        width: img.width,
        height: img.height,
        error: ok
          ? undefined
          : `Logo is ${img.width}×${img.height}; max allowed is ${MAX_LOGO_PIXEL_DIMENSION}×${MAX_LOGO_PIXEL_DIMENSION}.`,
      });
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      resolve({ ok: false, error: "Could not read image dimensions." });
    };
    img.src = url;
  });
}

// ---------------------------------------------------------------------------
// BrandingCard — issuer logo + brand colors
// ---------------------------------------------------------------------------

function BrandingCard() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [primaryColor, setPrimaryColor] = useState(DEFAULT_PRIMARY_COLOR);
  const [accentColor, setAccentColor] = useState(DEFAULT_ACCENT_COLOR);
  const [persistedBranding, setPersistedBranding] = useState<IssuerBrandingPayload | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [pendingLogoFile, setPendingLogoFile] = useState<File | null>(null);
  const [pendingLogoPreview, setPendingLogoPreview] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Object URL lifecycle: revoke previous URL when the file changes or
  // when the component unmounts.
  useEffect(() => {
    if (!pendingLogoFile) {
      setPendingLogoPreview(null);
      return;
    }
    const url = URL.createObjectURL(pendingLogoFile);
    setPendingLogoPreview(url);
    return () => URL.revokeObjectURL(url);
  }, [pendingLogoFile]);

  const loadBranding = useCallback(async () => {
    setLoading(true);
    try {
      const response: BrandingGetResponse = await window.opencred.brandingGet();
      if (response.configured && response.branding) {
        setPersistedBranding(response.branding);
        setPrimaryColor(response.branding.primaryColor ?? DEFAULT_PRIMARY_COLOR);
        setAccentColor(response.branding.accentColor ?? DEFAULT_ACCENT_COLOR);
      } else {
        setPersistedBranding(undefined);
      }
    } catch {
      // Branding API not available — silently fall back to defaults.
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadBranding();
  }, [loadBranding]);

  function clearMessages() {
    setError(null);
    setSuccess(null);
  }

  async function handleFileSelected(file: File) {
    clearMessages();

    const mime = file.type.toLowerCase();
    if (!ACCEPTED_LOGO_MIME.includes(mime as (typeof ACCEPTED_LOGO_MIME)[number])) {
      setError(`Logo must be PNG or SVG. Selected: ${file.type || "unknown"}.`);
      return;
    }
    if (file.size > MAX_LOGO_RAW_BYTES) {
      setError(`Logo is ${(file.size / 1024).toFixed(0)} KB; max allowed is ${MAX_LOGO_RAW_BYTES / 1024} KB.`);
      return;
    }

    if (mime === "image/png") {
      const dim = await checkPngDimensions(file);
      if (!dim.ok) {
        setError(dim.error ?? "Logo dimensions are too large.");
        return;
      }
    }

    setPendingLogoFile(file);
  }

  async function handleSave() {
    clearMessages();

    if (!HEX_COLOR_RE.test(primaryColor)) {
      setError("Primary color must be a hex value, e.g. #1a56db.");
      return;
    }
    if (!HEX_COLOR_RE.test(accentColor)) {
      setError("Accent color must be a hex value, e.g. #0ea5e9.");
      return;
    }

    setSaving(true);

    try {
      const request: BrandingSetRequest = {
        primaryColor,
        accentColor,
      };

      if (pendingLogoFile) {
        const base64 = await readFileAsBase64(pendingLogoFile);
        request.logoFile = {
          mimeType: pendingLogoFile.type,
          base64,
          name: pendingLogoFile.name,
        };
      }

      const result = await window.opencred.brandingSet(request);
      if (!result.success) {
        setError(result.error ?? "Failed to save branding.");
        setSaving(false);
        return;
      }

      setPersistedBranding(result.branding);
      setPendingLogoFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = "";
      }
      setSuccess("Branding saved. New credentials will use these values.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save branding.");
    } finally {
      setSaving(false);
    }
  }

  async function handleRemoveLogo() {
    clearMessages();
    setSaving(true);
    try {
      const result = await window.opencred.brandingSet({ removeLogo: true });
      if (!result.success) {
        setError(result.error ?? "Failed to remove logo.");
      } else {
        setPersistedBranding(result.branding);
        setSuccess("Logo removed.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove logo.");
    } finally {
      setSaving(false);
    }
  }

  async function handleResetAll() {
    clearMessages();
    setSaving(true);
    try {
      const result = await window.opencred.brandingClear();
      if (!result.success) {
        setError(result.error ?? "Failed to reset branding.");
      } else {
        setPersistedBranding(undefined);
        setPrimaryColor(DEFAULT_PRIMARY_COLOR);
        setAccentColor(DEFAULT_ACCENT_COLOR);
        setPendingLogoFile(null);
        if (fileInputRef.current) fileInputRef.current.value = "";
        setSuccess("Branding reset to OpenCred defaults.");
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reset branding.");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <Card className="space-y-2">
        <h2 className="text-sm font-medium text-gray-700">Branding</h2>
        <p className="text-xs text-gray-400">Loading...</p>
      </Card>
    );
  }

  const previewLogo = pendingLogoPreview ?? persistedBranding?.logoDataUri;

  return (
    <Card className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-700">Branding</h2>
        {persistedBranding && (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
            <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
            Active
          </span>
        )}
      </div>
      <p className="text-xs text-gray-500 -mt-1">
        Add your institutional logo and brand colors. These appear on the visual representation of every credential you issue (the signed credential JSON is unchanged).
      </p>

      {/* Logo upload */}
      <div className="space-y-2">
        <label className="block text-xs font-medium text-gray-600">Institutional logo</label>
        <div className="flex items-center gap-3">
          <div className="flex h-16 w-16 flex-shrink-0 items-center justify-center rounded-md border border-dashed border-gray-300 bg-white">
            {previewLogo ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={previewLogo} alt="Logo preview" className="max-h-14 max-w-14 object-contain" />
            ) : (
              <span className="text-[10px] text-gray-400">No logo</span>
            )}
          </div>
          <div className="flex flex-col gap-1">
            <input
              ref={fileInputRef}
              type="file"
              accept="image/png,image/svg+xml"
              className="block text-xs text-gray-500 file:mr-3 file:rounded file:border-0 file:bg-gray-100 file:px-3 file:py-1 file:text-xs file:font-medium file:text-gray-700 hover:file:bg-gray-200"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void handleFileSelected(file);
              }}
              disabled={saving}
            />
            <p className="text-[10px] text-gray-400">PNG or SVG, max 1 MB, max 1024×1024.</p>
          </div>
        </div>

        {persistedBranding?.logoDataUri && !pendingLogoFile && (
          <button
            type="button"
            className="text-xs font-medium text-red-600 hover:underline"
            onClick={() => void handleRemoveLogo()}
            disabled={saving}
          >
            Remove logo
          </button>
        )}
      </div>

      {/* Color pickers */}
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1">
          <label className="block text-xs font-medium text-gray-600">Primary color</label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={HEX_COLOR_RE.test(primaryColor) ? primaryColor : DEFAULT_PRIMARY_COLOR}
              onChange={(e) => setPrimaryColor(e.target.value)}
              disabled={saving}
              className="h-9 w-12 cursor-pointer rounded border border-gray-300"
              aria-label="Primary brand color"
            />
            <input
              type="text"
              value={primaryColor}
              onChange={(e) => setPrimaryColor(e.target.value)}
              disabled={saving}
              placeholder={DEFAULT_PRIMARY_COLOR}
              className="flex-1 rounded border border-gray-300 px-2 py-1.5 font-mono text-xs text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand-blue"
              aria-label="Primary color hex"
            />
          </div>
        </div>
        <div className="space-y-1">
          <label className="block text-xs font-medium text-gray-600">Accent color</label>
          <div className="flex items-center gap-2">
            <input
              type="color"
              value={HEX_COLOR_RE.test(accentColor) ? accentColor : DEFAULT_ACCENT_COLOR}
              onChange={(e) => setAccentColor(e.target.value)}
              disabled={saving}
              className="h-9 w-12 cursor-pointer rounded border border-gray-300"
              aria-label="Accent brand color"
            />
            <input
              type="text"
              value={accentColor}
              onChange={(e) => setAccentColor(e.target.value)}
              disabled={saving}
              placeholder={DEFAULT_ACCENT_COLOR}
              className="flex-1 rounded border border-gray-300 px-2 py-1.5 font-mono text-xs text-gray-900 focus:outline-none focus:ring-2 focus:ring-brand-blue"
              aria-label="Accent color hex"
            />
          </div>
        </div>
      </div>

      {/* Feedback */}
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-xs text-red-700">{error}</div>
      )}
      {success && (
        <div className="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-xs text-green-700">{success}</div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-2 pt-1">
        <Button onClick={() => void handleSave()} disabled={saving} size="sm">
          {saving ? "Saving..." : "Save branding"}
        </Button>
        {persistedBranding && (
          <button
            type="button"
            onClick={() => void handleResetAll()}
            disabled={saving}
            className="px-3 py-1.5 text-xs font-medium text-gray-600 border border-gray-200 rounded hover:bg-gray-50 transition-colors disabled:opacity-50"
          >
            Reset to defaults
          </button>
        )}
      </div>
    </Card>
  );
}

// ---------------------------------------------------------------------------
// DeDiCard — configure / manage DeDi integration from Settings
// ---------------------------------------------------------------------------

type DeDiCardState = "idle" | "form" | "saving" | "publishing";

function StatusRow({
  label,
  active,
  description,
  action,
  onAction,
  disabled,
}: {
  label: string;
  active: boolean;
  description: string;
  action?: string;
  onAction?: () => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-center justify-between px-3 py-2">
      <div className="flex items-center gap-2">
        <span
          className={`h-2 w-2 rounded-full flex-shrink-0 ${active ? "bg-green-500" : "bg-gray-300"}`}
        />
        <span className="text-xs font-medium text-gray-700">{label}</span>
        <span className="text-xs text-gray-400">{description}</span>
      </div>
      {action && onAction && (
        <button
          onClick={onAction}
          disabled={disabled}
          className="text-xs font-medium text-brand-blue hover:underline disabled:opacity-50"
        >
          {disabled ? "..." : action}
        </button>
      )}
      {!action && (
        <span className={`text-xs font-medium ${active ? "text-green-600" : "text-gray-400"}`}>
          {active ? "Live" : "Inactive"}
        </span>
      )}
    </div>
  );
}

function DeDiCard() {
  const [status, setStatus] = useState<DeDiStatusResponse | null>(null);
  const [state, setState] = useState<DeDiCardState>("idle");
  const [namespace, setNamespace] = useState("");
  // Transient form state only — sent to main process via IPC for encrypted
  // storage (safeStorage) and cleared immediately after submission.
  // Same pattern as DeDiSetup.tsx.
  const [apiKey, setApiKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [actionResult, setActionResult] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  const loadStatus = useCallback(async () => {
    try {
      const s = await window.opencred.dediGetStatus();
      setStatus(s);
      if (s.configured && s.namespace) setNamespace(s.namespace);
    } catch {
      setStatus({ configured: false, registriesReady: false, publishedSchemas: [] });
    }
  }, []);

  useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  async function handleSave() {
    if (!namespace.trim()) {
      setError("Please enter a namespace.");
      return;
    }
    if (!apiKey) {
      setError("Please enter your API key.");
      return;
    }

    setError(null);
    setActionResult(null);
    setState("saving");

    try {
      const result = await window.opencred.dediSetConfig({
        baseUrl: DEDI_BASE_URL,
        namespace: namespace.trim(),
        credentials: { type: "api-key", apiKey },
      });

      if (!result.success) {
        setError(result.error ?? "Failed to configure DeDi.");
        setState("form");
        return;
      }

      setApiKey("");
      setState("idle");
      await loadStatus();
      setActionResult({ type: "success", message: "DeDi configured successfully." });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to configure DeDi.");
      setState("form");
    }
  }

  async function handleDisconnect() {
    setError(null);
    setActionResult(null);
    try {
      await window.opencred.dediDisconnect();
      setNamespace("");
      setApiKey("");
      setState("idle");
      await loadStatus();
      setActionResult({ type: "success", message: "Disconnected from DeDi." });
    } catch (err) {
      setActionResult({
        type: "error",
        message: err instanceof Error ? err.message : "Failed to disconnect.",
      });
    }
  }

  async function handlePublishDID() {
    setError(null);
    setActionResult(null);
    setState("publishing");

    try {
      const { keys } = await window.opencred.listKeys();
      if (keys.length === 0) {
        setActionResult({
          type: "error",
          message: "No signing keys available. Import or generate a key first.",
        });
        setState("idle");
        return;
      }

      if (!status?.namespace) {
        setActionResult({ type: "error", message: "No namespace configured." });
        setState("idle");
        return;
      }

      const activeKey = keys[0];
      const exportResult = await window.opencred.exportDidDocument({
        keyId: activeKey.id,
        domain: status.namespace,
      });

      if (!exportResult.success || !exportResult.didDocument || !exportResult.did) {
        setActionResult({
          type: "error",
          message: exportResult.error ?? "Failed to export DID document.",
        });
        setState("idle");
        return;
      }

      const pubResult = await window.opencred.dediPublishDID({
        did: exportResult.did,
        document: JSON.parse(exportResult.didDocument),
      });

      setActionResult(
        pubResult.success
          ? { type: "success", message: "DID published successfully." }
          : { type: "error", message: pubResult.error ?? "Failed to publish DID." },
      );
    } catch (err) {
      setActionResult({
        type: "error",
        message: err instanceof Error ? err.message : "Failed to publish DID.",
      });
    }

    setState("idle");
  }

  async function handleCreateRegistries() {
    setActionResult(null);
    try {
      const result = await window.opencred.dediEnsureRegistries();
      if (result.success) {
        setActionResult({ type: "success", message: "Registries created." });
        await loadStatus();
      } else {
        setActionResult({ type: "error", message: result.error ?? "Failed to create registries." });
      }
    } catch (err) {
      setActionResult({
        type: "error",
        message: err instanceof Error ? err.message : "Failed to create registries.",
      });
    }
  }

  if (!status) return null;

  const isConfigured = status.configured;

  return (
    <Card className="space-y-3">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-medium text-gray-700">DeDi Integration</h2>
        {isConfigured ? (
          <span className="inline-flex items-center gap-1.5 rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
            <span className="h-1.5 w-1.5 rounded-full bg-green-500" />
            Connected
          </span>
        ) : (
          <span className="text-xs text-gray-400">Not configured</span>
        )}
      </div>

      {/* Action result feedback */}
      {actionResult && (
        <div
          className={`rounded-md px-3 py-2 text-xs ${
            actionResult.type === "success"
              ? "bg-green-50 text-green-700 border border-green-200"
              : "bg-red-50 text-red-700 border border-red-200"
          }`}
        >
          {actionResult.message}
        </div>
      )}

      {/* Not configured — idle */}
      {!isConfigured && state === "idle" && (
        <>
          <p className="text-xs text-gray-500">
            Connect to DeDi to publish your DID, schemas, and revocation lists.
          </p>
          <Button
            onClick={() => {
              setState("form");
              setActionResult(null);
            }}
          >
            Configure
          </Button>
        </>
      )}

      {/* Configured — idle */}
      {isConfigured && state === "idle" && (
        <>
          <div className="text-xs text-gray-500 mb-1">
            Namespace: <span className="font-medium text-gray-700">{status.namespace}</span>
          </div>

          {/* Status indicators */}
          <div className="rounded-md border border-gray-200 divide-y divide-gray-100">
            <StatusRow
              label="Registries"
              active={status.registriesReady}
              description="Schema, Public Key, Revocation"
              action={status.registriesReady ? undefined : "Create"}
              onAction={
                status.registriesReady
                  ? undefined
                  : () => {
                      void handleCreateRegistries();
                    }
              }
            />
            <StatusRow
              label="Public Key"
              active={false}
              description="Publish your DID document"
              action="Publish"
              onAction={() => void handlePublishDID()}
            />
            <StatusRow
              label="Schemas"
              active={status.publishedSchemas.length > 0}
              description={
                status.publishedSchemas.length > 0
                  ? `${status.publishedSchemas.length} published`
                  : "Published on first issuance"
              }
            />
          </div>

          <div className="flex gap-2 pt-1">
            <Button
              onClick={() => {
                setState("form");
                setApiKey("");
                setActionResult(null);
              }}
              size="sm"
            >
              Reconfigure
            </Button>
            <button
              onClick={() => void handleDisconnect()}
              className="px-3 py-1.5 text-xs font-medium text-red-600 border border-red-200 rounded hover:bg-red-50 transition-colors"
            >
              Disconnect
            </button>
          </div>
        </>
      )}

      {/* Inline configure / reconfigure form */}
      {(state === "form" || state === "saving") && (
        <div className="space-y-3 pt-1">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Namespace</label>
            <input
              type="text"
              value={namespace}
              onChange={(e) => {
                setNamespace(e.target.value);
                setError(null);
              }}
              placeholder="your-domain.example"
              disabled={state === "saving"}
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue disabled:opacity-50"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">API Key</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => {
                setApiKey(e.target.value);
                setError(null);
              }}
              placeholder="Enter your DeDi API key"
              disabled={state === "saving"}
              className="w-full rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue disabled:opacity-50"
            />
          </div>

          {error && <p className="text-xs text-red-600">{error}</p>}

          <div className="flex gap-2">
            <Button onClick={() => void handleSave()} disabled={state === "saving"}>
              {state === "saving" ? "Saving..." : "Save"}
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                setState("idle");
                setError(null);
                setActionResult(null);
              }}
              disabled={state === "saving"}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {/* Busy states */}
      {state === "publishing" && (
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 border-2 border-brand-blue border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-gray-500">Publishing DID...</span>
        </div>
      )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// UpdateCard — in-app update UI
// ---------------------------------------------------------------------------

function UpdateCard() {
  const [status, setStatus] = useState<UpdateStatusResponse>({
    checking: false,
    available: false,
    downloading: false,
    downloaded: false,
  });
  const [isDev, setIsDev] = useState(false);

  useEffect(() => {
    // Get initial status
    window.opencred
      .updateGetStatus()
      .then(setStatus)
      .catch(() => {
        setIsDev(true);
      });

    // Subscribe to live updates
    const unsub = window.opencred.onUpdateStatus(setStatus);
    return unsub;
  }, []);

  function handleCheck() {
    void window.opencred.updateCheck();
  }

  function handleDownload() {
    void window.opencred.updateDownload();
  }

  function handleInstall() {
    void window.opencred.updateInstall();
  }

  // Dev mode or offline — graceful fallback
  if (isDev) {
    return (
      <Card className="space-y-2">
        <h2 className="text-sm font-medium text-gray-700">Software Updates</h2>
        <p className="text-xs text-gray-500">Auto-update is not available in development mode.</p>
      </Card>
    );
  }

  // Format download speed
  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  return (
    <Card className="space-y-3">
      <h2 className="text-sm font-medium text-gray-700">Software Updates</h2>

      {/* Error state */}
      {status.error && (
        <div className="flex items-center justify-between">
          <p className="text-xs text-red-600">{status.error}</p>
          <button
            onClick={handleCheck}
            className="text-xs font-medium text-brand-blue hover:underline"
          >
            Retry
          </button>
        </div>
      )}

      {/* Downloaded — ready to install */}
      {status.downloaded && (
        <div className="space-y-2">
          <p className="text-xs text-green-700">
            Version {status.version} downloaded. Restart to apply.
          </p>
          {status.releaseNotes && (
            <p className="text-xs text-gray-500 line-clamp-3">{status.releaseNotes}</p>
          )}
          <button
            onClick={handleInstall}
            className="px-3 py-1.5 text-xs font-medium text-white bg-green-600 rounded hover:bg-green-700 transition-colors"
          >
            Restart Now
          </button>
        </div>
      )}

      {/* Downloading — progress bar */}
      {status.downloading && !status.downloaded && (
        <div className="space-y-2">
          <div className="flex items-center justify-between text-xs text-gray-600">
            <span>Downloading {status.version}...</span>
            {status.progress && (
              <span>
                {formatBytes(status.progress.transferred)} / {formatBytes(status.progress.total)} (
                {formatBytes(status.progress.bytesPerSecond)}/s)
              </span>
            )}
          </div>
          <div className="w-full h-1.5 bg-gray-200 rounded-full overflow-hidden">
            <div
              className="h-full bg-brand-blue rounded-full transition-all duration-300"
              style={{ width: `${status.progress?.percent ?? 0}%` }}
            />
          </div>
        </div>
      )}

      {/* Available — offer download */}
      {status.available && !status.downloading && !status.downloaded && !status.error && (
        <div className="space-y-2">
          <p className="text-xs text-gray-700">Version {status.version} is available.</p>
          {status.releaseNotes && (
            <p className="text-xs text-gray-500 line-clamp-3">{status.releaseNotes}</p>
          )}
          <button
            onClick={handleDownload}
            className="px-3 py-1.5 text-xs font-medium text-white bg-brand-blue rounded hover:bg-brand-blue/90 transition-colors"
          >
            Download Update
          </button>
        </div>
      )}

      {/* Checking */}
      {status.checking && (
        <div className="flex items-center gap-2">
          <div className="h-3 w-3 border-2 border-brand-blue border-t-transparent rounded-full animate-spin" />
          <span className="text-xs text-gray-500">Checking for updates...</span>
        </div>
      )}

      {/* Up to date */}
      {!status.checking &&
        !status.available &&
        !status.downloading &&
        !status.downloaded &&
        !status.error && (
          <div className="flex items-center justify-between">
            <p className="text-xs text-gray-500">Running latest version.</p>
            <button
              onClick={handleCheck}
              className="text-xs font-medium text-brand-blue hover:underline"
            >
              Check for Updates
            </button>
          </div>
        )}
    </Card>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/** Number of days before a key is considered overdue for rotation. */
const ROTATION_THRESHOLD_DAYS = 90;
/** Number of days the rotation reminder is snoozed after dismissal. */
const ROTATION_SNOOZE_DAYS = 30;

interface SettingsPageProps {
  onRotationDismissed?: () => void;
}

export function SettingsPage({ onRotationDismissed }: SettingsPageProps) {
  const [isOffline, setIsOffline] = useState(false);
  const [bugReportOpen, setBugReportOpen] = useState(false);
  const [rotationInfo, setRotationInfo] = useState<{ overdue: boolean; ageDays: number }>({
    overdue: false,
    ageDays: 0,
  });
  const [orgName, setOrgName] = useState("");
  const [orgNameSaved, setOrgNameSaved] = useState(false);
  const [orgNameSaving, setOrgNameSaving] = useState(false);

  const checkOffline = useCallback(async () => {
    try {
      const offline = await window.opencred.getOfflineStatus();
      setIsOffline(offline);
    } catch {
      setIsOffline(true);
    }
  }, []);

  const checkRotation = useCallback(async () => {
    try {
      const response = await window.opencred.listKeys();
      if (response.keys.length === 0) return;

      const dismissedUntil = (await window.opencred.getConfig("keyRotationDismissedUntil")) as
        | string
        | undefined;
      if (dismissedUntil && new Date(dismissedUntil) > new Date()) return;

      const now = Date.now();
      const thresholdMs = ROTATION_THRESHOLD_DAYS * 24 * 60 * 60 * 1000;
      let oldestAge = 0;
      for (const key of response.keys) {
        const age = now - new Date(key.importedAt).getTime();
        if (age > oldestAge) oldestAge = age;
      }
      if (oldestAge > thresholdMs) {
        setRotationInfo({ overdue: true, ageDays: Math.floor(oldestAge / (24 * 60 * 60 * 1000)) });
      }
    } catch {
      // Non-fatal
    }
  }, []);

  async function handleDismissRotation() {
    const snoozeUntil = new Date();
    snoozeUntil.setDate(snoozeUntil.getDate() + ROTATION_SNOOZE_DAYS);
    try {
      await window.opencred.setConfig("keyRotationDismissedUntil", snoozeUntil.toISOString());
      setRotationInfo({ overdue: false, ageDays: 0 });
      onRotationDismissed?.();
    } catch {
      // Non-fatal: banner stays visible if preference fails to persist
    }
  }

  useEffect(() => {
    void checkOffline();
    void checkRotation();
    void (async () => {
      try {
        const saved = (await window.opencred.getConfig("organizationName")) as string | undefined;
        if (saved) setOrgName(saved);
      } catch {
        /* non-fatal */
      }
    })();
  }, [checkOffline, checkRotation]);

  async function handleSaveOrgName() {
    const trimmed = orgName.trim();
    setOrgNameSaving(true);
    try {
      await window.opencred.setConfig("organizationName", trimmed || undefined);
      setOrgNameSaved(true);
      setTimeout(() => setOrgNameSaved(false), 2000);
    } catch {
      /* non-fatal */
    } finally {
      setOrgNameSaving(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Organization name */}
      <Card className="space-y-3">
        <h2 className="text-sm font-medium text-gray-700">Your Organization</h2>
        <p className="text-xs text-gray-500 -mt-1">This name appears on credentials you issue.</p>
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={orgName}
            onChange={(e) => {
              setOrgName(e.target.value);
              setOrgNameSaved(false);
            }}
            placeholder="e.g. Ministry of Agriculture, Govt of India"
            className="flex-1 rounded border border-gray-300 px-3 py-2 text-sm text-gray-900 placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-brand-blue focus:border-brand-blue"
          />
          <Button onClick={() => void handleSaveOrgName()} disabled={orgNameSaving} size="sm">
            {orgNameSaving ? "Saving..." : "Save"}
          </Button>
          {orgNameSaved && (
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
        </div>
      </Card>

      {/* Key rotation warning */}
      {rotationInfo.overdue && (
        <div className="flex items-center justify-between rounded-lg border border-amber-300 bg-amber-50 px-4 py-3">
          <div className="flex items-center gap-3">
            <span className="flex h-6 w-6 items-center justify-center rounded-full bg-amber-200">
              <svg
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="#92400e"
                strokeWidth={2}
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z"
                />
              </svg>
            </span>
            <p className="text-sm text-amber-800">
              Your signing key is <strong>{rotationInfo.ageDays} days</strong> old. Consider
              rotating for security best practices.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => void handleDismissRotation()}
              className="text-xs font-medium text-amber-700 hover:text-amber-900 px-2 py-1"
            >
              Dismiss
            </button>
            <Button
              onClick={() => {
                const el = document.getElementById("key-management-section");
                if (el) el.scrollIntoView({ behavior: "smooth" });
              }}
            >
              Rotate Key
            </Button>
          </div>
        </div>
      )}

      {/* 1. Key management — all 4 sources (most important) */}
      <div id="key-management-section">
        <KeyManagement />
      </div>

      {/* 2. Issuer branding (logo + colors) */}
      <BrandingCard />

      {/* 3. Software updates */}
      <UpdateCard />

      {/* 4. DeDi integration */}
      <DeDiCard />

      {/* 4. Network status */}
      <Card className="space-y-2">
        <h2 className="text-sm font-medium text-gray-700">Network Status</h2>
        <p className="text-xs text-gray-400 -mt-1">
          Check your connectivity for online features like revocation and DeDi sync.
        </p>
        <div className="flex items-center gap-2">
          <span
            className={`h-2.5 w-2.5 rounded-full ${isOffline ? "bg-amber-500" : "bg-green-500"}`}
          />
          <span className={`text-sm ${isOffline ? "text-amber-700" : "text-green-700"}`}>
            {isOffline ? "Offline" : "Online"}
          </span>
        </div>
        <p className="text-xs text-gray-500">
          {isOffline
            ? "You are offline. Credential issuance and signature verification still work. Revocation checks require a network connection."
            : "Connected. All features are available."}
        </p>
      </Card>

      {/* 5. Help & Support */}
      <Card className="space-y-2">
        <h2 className="text-sm font-medium text-gray-700">Help & Support</h2>
        <p className="text-xs text-gray-500">
          Encountered an issue? Generate a bug report with system info and recent logs.
        </p>
        <button
          onClick={() => setBugReportOpen(true)}
          className="px-3 py-1.5 text-xs font-medium text-txt-primary bg-surface-card border border-border-default rounded hover:bg-gray-100 transition-colors"
        >
          Report Bug
        </button>
      </Card>

      {/* 6. About */}
      <Card className="space-y-1">
        <h2 className="text-sm font-medium text-gray-700">About</h2>
        <p className="text-xs text-gray-400">Version and security info for this installation.</p>
        <p className="text-xs text-gray-500">OpenCred Desktop v0.1.0</p>
        <p className="text-xs text-gray-400">
          All signing happens locally. Private keys never leave this machine.
        </p>
      </Card>

      {/* Bug report dialog */}
      <BugReportDialog open={bugReportOpen} onClose={() => setBugReportOpen(false)} />
    </div>
  );
}
