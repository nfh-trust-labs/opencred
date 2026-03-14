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
  success: "bg-green-50 text-green-800 border-green-200/60",
  error: "bg-red-50 text-red-800 border-red-200/60",
  warning: "bg-amber-50 text-amber-800 border-amber-200/60",
  info: "bg-brand-blue-light text-brand-blue border-blue-200/60",
  neutral: "bg-surface-bg text-txt-muted border-border",
};

export function Badge({ variant = "neutral", children, className = "" }: BadgeProps) {
  return (
    <span
      className={`inline-flex items-center rounded-oc border px-2 py-0.5 font-mono text-[0.6rem] uppercase tracking-wider ${VARIANT_CLASSES[variant]} ${className}`}
    >
      {children}
    </span>
  );
}
