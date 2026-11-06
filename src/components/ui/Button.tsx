import type { ButtonHTMLAttributes, ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

import { cx } from "../../lib/cx";

type Variant = "default" | "primary" | "danger" | "ghost";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: "sm" | "md";
  icon?: LucideIcon;
  children?: ReactNode;
}

export function Button({
  variant = "default",
  size = "md",
  icon: Icon,
  className,
  children,
  type,
  ...rest
}: ButtonProps) {
  return (
    <button
      type={type ?? "button"}
      className={cx("btn", "btn--" + variant, size === "sm" && "btn--sm", className)}
      {...rest}
    >
      {Icon ? <Icon size={14} aria-hidden="true" /> : null}
      {children ? <span>{children}</span> : null}
    </button>
  );
}

export interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon: LucideIcon;
  label: string;
}

export function IconButton({ icon: Icon, label, className, type, ...rest }: IconButtonProps) {
  return (
    <button
      type={type ?? "button"}
      className={cx("btn btn--ghost btn--icon", className)}
      aria-label={label}
      title={label}
      {...rest}
    >
      <Icon size={14} aria-hidden="true" />
    </button>
  );
}
