import { X } from "lucide-react";

export interface ToastProps {
  tone: "ok" | "error";
  message: string;
  onDismiss: () => void;
}

/** Single transient notification, mounted by the import workflow. */
export function Toast({ tone, message, onDismiss }: ToastProps) {
  return (
    <div className="toast-stack">
      <div className={"toast toast--" + tone} role={tone === "error" ? "alert" : "status"}>
        <span>{message}</span>
        <button
          type="button"
          className="btn btn--ghost btn--icon btn--sm toast__close"
          aria-label="Dismiss notification"
          onClick={onDismiss}
        >
          <X size={12} aria-hidden="true" />
        </button>
      </div>
    </div>
  );
}
