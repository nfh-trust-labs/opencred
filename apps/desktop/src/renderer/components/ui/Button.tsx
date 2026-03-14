/**
 * Button — reusable styled button with variant support.
 *
 * Variants:
 *  - primary: brand blue background (default action)
 *  - secondary: transparent with border (cancel / back)
 *  - danger: transparent with red border (destructive action)
 *
 * Styled to match the Editorial Refined design scheme.
 */

import type { ButtonHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "danger";
type Size = "default" | "sm";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

const VARIANT_CLASSES: Record<Variant, string> = {
  primary:
    "bg-brand-blue text-white hover:bg-[#004AD9] focus:ring-brand-blue disabled:opacity-40",
  secondary:
    "bg-transparent text-txt-primary border border-border hover:bg-surface-warm focus:ring-brand-blue disabled:opacity-40 disabled:text-txt-muted",
  danger:
    "bg-transparent text-red-700 border border-red-300 hover:bg-red-50 focus:ring-red-500 disabled:opacity-40",
};

const SIZE_CLASSES: Record<Size, string> = {
  default: "px-6 py-2.5 text-[0.82rem]",
  sm: "px-3.5 py-1.5 text-[0.72rem]",
};

export function Button({
  variant = "primary",
  size = "default",
  className = "",
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      className={`rounded-oc font-semibold font-body transition-colors duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:cursor-not-allowed oc-hover-glow ${VARIANT_CLASSES[variant]} ${SIZE_CLASSES[size]} ${className}`}
      {...rest}
    >
      {children}
    </button>
  );
}
