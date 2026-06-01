/**
 * Spinner — the single loading indicator for the app.
 *
 * Replaces the divergent ad-hoc "Loading..." text that several pages used.
 */

interface SpinnerProps {
  label?: string;
  className?: string;
}

export function Spinner({ label = "Loading…", className = "" }: SpinnerProps) {
  return (
    <div
      className={`flex items-center justify-center gap-2 py-8 text-txt-muted ${className}`}
      role="status"
      aria-live="polite"
    >
      <span
        className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-border border-t-brand-blue"
        aria-hidden="true"
      />
      <span className="text-body-sm">{label}</span>
    </div>
  );
}
