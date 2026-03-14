/**
 * Card — editorial-style content container.
 *
 * Default variant has a blue left-border accent (3px solid brand blue).
 * Use variant="neutral" for containers without the accent (e.g. tables).
 */

import type { ReactNode } from "react";

type Variant = "default" | "neutral";

interface CardProps {
  children: ReactNode;
  className?: string;
  variant?: Variant;
}

export function Card({ children, className = "", variant = "default" }: CardProps) {
  const base = variant === "neutral" ? "oc-card-neutral" : "oc-card";
  return (
    <div className={`${base} ${className}`}>
      {children}
    </div>
  );
}
