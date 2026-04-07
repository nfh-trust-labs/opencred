/**
 * SVG credential template types.
 */

/**
 * Issuer-controlled branding applied to the rendered credential.
 *
 * Branding is presentation-layer only — it never appears in the signed
 * Verifiable Credential payload. Verifiers receive the same VC JSON
 * regardless of branding configuration.
 *
 * Logos are always embedded as `data:` URIs (no remote fetches at view
 * time). When branding is undefined or partially set, the renderer falls
 * back to the OpenCred defaults (no logo, default brand colors).
 */
export interface IssuerBranding {
  /** Logo as a `data:image/png;base64,...` or `data:image/svg+xml;base64,...` URI. */
  logoDataUri?: string;
  /** Hex primary color (`#RRGGBB`, e.g. `#1a56db`). */
  primaryColor?: string;
  /** Hex accent color (`#RRGGBB`). */
  accentColor?: string;
}

/** A credential template definition. */
export interface CredentialTemplate {
  /** Unique template ID (usually matches a schema ID). */
  id: string;
  /** Human-readable template name. */
  name: string;
  /** The SVG template content with {{placeholder}} tokens. */
  svg: string;
  /** Optional default branding baked into a custom template. */
  branding?: IssuerBranding;
}

/** Customization options applied by the issuer. */
export interface TemplateCustomization {
  /** Primary color for the credential (CSS color string). */
  primaryColor?: string;
  /** Accent color for the credential (CSS color string). */
  accentColor?: string;
  /** Issuer's logo as a data URI (e.g., "data:image/png;base64,..."). */
  logoDataUri?: string;
  /** Display name for the issuer (overrides DID in template). */
  issuerDisplayName?: string;
  /**
   * Issuer branding (logo + brand colors). When provided, individual
   * `primaryColor`, `accentColor`, and `logoDataUri` fields above act as
   * overrides — branding is the issuer-managed default and the explicit
   * fields take precedence when set.
   */
  branding?: IssuerBranding;
}

/** Values to substitute into the template. */
export interface RenderValues {
  /** Issuer name / DID. */
  issuerName: string;
  /** Credential title (derived from type). */
  credentialTitle: string;
  /** ISO date string for validFrom. */
  validFrom: string;
  /** ISO date string for validUntil (optional). */
  validUntil?: string;
  /** Subject fields — accessed as subject.fieldName. */
  subject: Record<string, string>;
  /** QR code as a data URI (optional). */
  qrCode?: string;
}

/** Options for rendering a template. */
export interface RenderOptions {
  /** Template customization (colors, logo, etc.). */
  customization?: TemplateCustomization;
  /** Values to render into the template. */
  values: RenderValues;
}
