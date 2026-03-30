/**
 * Shared formatting utilities for the renderer.
 */

/**
 * Format an ISO date string as a short locale date (e.g. "Mar 30, 2026").
 * Returns the raw string on parse failure.
 */
export function formatKeyDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}
