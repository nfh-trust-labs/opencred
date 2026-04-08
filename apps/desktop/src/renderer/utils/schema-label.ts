/**
 * Derive a human-readable display label from a schema ID.
 *
 * v1 schema library IDs follow the pattern `[category/]<name>/<version>`.
 * Examples:
 *   - "electricity/v1"                           → "Electricity v1"
 *   - "immunization/v1"                          → "Immunization v1"
 *   - "employment-offer-letter/v1"               → "Employment Offer Letter v1"
 *   - "open-badges/v3"                           → "Open Badges v3"
 *   - "dif/verified-person/v1"                   → "Verified Person v1"
 *   - "traceability/commercial-invoice/v1"       → "Commercial Invoice v1"
 *
 * The category prefix (first path segment when there are 3+ parts) is not
 * shown in the label — verifiers can access the full ID via the raw string
 * if needed. This keeps labels short enough for a dropdown.
 *
 * Falls back to the raw ID if the shape doesn't match (defensive for
 * custom or legacy schemas).
 */
export function formatSchemaLabel(id: string): string {
  if (!id) return id;
  const parts = id.split("/");
  if (parts.length < 2) return id;

  const version = parts[parts.length - 1];
  const name = parts[parts.length - 2];
  if (!name || !version) return id;

  // Title-case each dash-separated word: "commercial-invoice" → "Commercial Invoice"
  const titleCased = name
    .split("-")
    .map((w) => (w ? w.charAt(0).toUpperCase() + w.slice(1) : w))
    .join(" ");

  return `${titleCased} ${version}`;
}
