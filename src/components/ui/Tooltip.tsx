import type { ReactNode } from "react";

import { cx } from "../../lib/cx";

/** Hover/focus tooltip. The bubble is decorative; controls keep their own aria-label. */
export function Tooltip({
  label,
  children,
  side = "right",
}: {
  label: string;
  children: ReactNode;
  side?: "right" | "bottom";
}) {
  return (
    <span className={cx("tooltip", side === "bottom" && "tooltip--bottom")}>
      {children}
      <span className="tooltip__bubble" role="tooltip" aria-hidden="true">
        {label}
      </span>
    </span>
  );
}
