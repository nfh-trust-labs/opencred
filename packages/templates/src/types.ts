/**
 * SVG credential template types.
 */

/** A credential template definition. */
export interface CredentialTemplate {
  /** Unique template ID (usually matches a schema ID). */
  id: string;
  /** Human-readable template name. */
  name: string;
  /** The SVG template content with {{placeholder}} tokens. */
  svg: string;
}

/** Customization options applied by the issuer. */
export interface TemplateCustomization {
  /** Primary color for the credential (CSS color string). */
  primaryColor?: string;
  /** Issuer's logo as a data URI (e.g., "data:image/png;base64,..."). */
  logoDataUri?: string;
  /** Display name for the issuer (overrides DID in template). */
  issuerDisplayName?: string;
  /** Background color for the credential card (CSS hex). */
  backgroundColor?: string;
  /** Secondary color for subheadings and section headers (CSS hex). */
  secondaryColor?: string;
  /** Main text color (CSS hex). */
  textColor?: string;
  /** Label text color (CSS hex). */
  labelColor?: string;
  /** Logo width in pixels (10-200). */
  logoWidth?: number;
  /** Logo height in pixels (10-200). */
  logoHeight?: number;
  /** Custom footer text. */
  footerText?: string;
  /** Seal/badge image as a data URI. */
  sealDataUri?: string;
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
