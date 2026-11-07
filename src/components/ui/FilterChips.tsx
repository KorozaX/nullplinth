import { X } from "lucide-react";

/** Removable chip representing one active query condition. */
export function FilterChip({
  label,
  value,
  onRemove,
}: {
  label: string;
  value: string;
  onRemove: () => void;
}) {
  return (
    <span className="filter-chip">
      <span>{label}</span>
      <span className="filter-chip__value">{value}</span>
      <button
        type="button"
        className="filter-chip__remove"
        aria-label={"Remove filter " + label + " " + value}
        onClick={onRemove}
      >
        <X size={11} aria-hidden="true" />
      </button>
    </span>
  );
}
