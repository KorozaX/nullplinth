import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { AlertTriangle, Loader2 } from "lucide-react";

import { Button } from "./Button";
import { cx } from "../../lib/cx";

export function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  compact,
}: {
  icon?: LucideIcon;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
  compact?: boolean;
}) {
  return (
    <div className={cx("empty", compact && "empty--compact")} role="status">
      {Icon ? <Icon className="empty__icon" size={22} aria-hidden="true" /> : null}
      <p className="empty__title">{title}</p>
      {description !== undefined ? <p className="empty__body">{description}</p> : null}
      {action !== undefined ? <div className="empty__action">{action}</div> : null}
    </div>
  );
}

export function ErrorState({
  title = "Could not load",
  message,
  onRetry,
  retryLabel = "Retry",
}: {
  title?: string;
  message?: string | null;
  onRetry?: () => void;
  retryLabel?: string;
}) {
  return (
    <div className="error-state" role="alert">
      <AlertTriangle className="error-state__icon" size={18} aria-hidden="true" />
      <div>
        <p className="error-state__title">{title}</p>
        {message ? <p className="error-state__body">{message}</p> : null}
      </div>
      {onRetry ? (
        <Button size="sm" variant="ghost" onClick={onRetry}>
          {retryLabel}
        </Button>
      ) : null}
    </div>
  );
}

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="loading" role="status" aria-live="polite">
      <Loader2 className="loading__icon" size={16} aria-hidden="true" />
      <span>{label + "\u2026"}</span>
    </div>
  );
}

export function Notice({
  tone = "info",
  children,
}: {
  tone?: "info" | "ok" | "error";
  children: ReactNode;
}) {
  return (
    <div className={cx("notice", "notice--" + tone)} role={tone === "error" ? "alert" : "status"}>
      {children}
    </div>
  );
}
