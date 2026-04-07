export type {
  CredentialTemplate,
  IssuerBranding,
  TemplateCustomization,
  RenderValues,
  RenderOptions,
} from "./types.js";

export { registerTemplate, getTemplate, listTemplateIds } from "./registry.js";

export {
  renderSvg,
  DEFAULT_PRIMARY_COLOR,
  DEFAULT_ACCENT_COLOR,
} from "./renderer.js";

export {
  ALLOWED_LOGO_MIME_TYPES,
  MAX_LOGO_DATA_URI_BYTES,
  isValidHexColor,
  normalizeHexColor,
  resolveBranding,
  sanitizeSvgLogo,
  svgToDataUri,
  validateLogoDataUri,
} from "./branding.js";

export type {
  LogoValidationResult,
  ResolvedBranding,
  SvgSanitizationResult,
} from "./branding.js";
