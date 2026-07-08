/**
 * Badge — small status indicator with color coding.
 *
 * Editorial Refined style: 4px radius, subtle colored borders.
 */

type Variant = "success" | "error" | "warning" | "info" | "neutral";

interface BadgeProps {
  variant?: Variant;
  children: string;
  className?: string;
}

const VARIANT_CLASSES: Record<Variant, string> = {
  success: "bg-state-success-bg text-state-success border-state-success-border/60",
  error: "bg-state-danger-bg text-red-800 border-state-danger-border/60",
  warning: "bg-state-warning-bg text-state-warning border-state-warning-border/60",
  info: "bg-brand-blue-light text-brand-blue border-blue-200/60",
  neutral: "bg-surface-bg text-txt-muted border-border",
};

export function Badge({ variant = "neutral", children, className = "" }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-oc border px-2 py-0.5 font-mono text-body-2xs uppercase tracking-wider ${VARIANT_CLASSES[variant]} ${className}`}
    >
      {children}
    </span>
  );
}
