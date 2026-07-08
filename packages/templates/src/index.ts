export type {
  CredentialTemplate,
  TemplateCustomization,
  RenderValues,
  RenderOptions,
} from "./types.js";

export { registerTemplate, getTemplate, listTemplateIds } from "./registry.js";

export { renderSvg } from "./renderer.js";
