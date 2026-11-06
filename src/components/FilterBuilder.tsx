import { useMemo, useState } from "react";
import { Plus, X } from "lucide-react";

import type { FilterOp, FilterRow } from "../types/contracts";
import type { FieldDef } from "../lib/filterFields";
import { defaultFilterRow, findField, OPERATORS, operatorsFor, validateFilterRow } from "../lib/filterFields";
import { Button, IconButton } from "./ui/Button";
import { Select, TextInput } from "./ui/Field";
import { cx } from "../lib/cx";

export interface FilterBuilderProps {
  fields: readonly FieldDef[];
  value: FilterRow[];
  onChange: (next: FilterRow[]) => void;
  disabled?: boolean;
  label?: string;
}

export function FilterBuilder({ fields, value, onChange, disabled, label = "Filters" }: FilterBuilderProps) {
  const [touched, setTouched] = useState<number[]>([]);
  const errors = useMemo(() => value.map((row) => validateFilterRow(row, fields)), [value, fields]);

  function markTouched(index: number) {
    setTouched((current) => (current.includes(index) ? current : [...current, index]));
  }

  function shouldReveal(index: number): boolean {
    const error = errors[index];
    if (error === null) return false;
    const row = value[index];
    if (!row) return false;
    const op = OPERATORS.find((candidate) => candidate.op === row.op);
    const needsValue = op ? op.needsValue : true;
    return touched.includes(index) || (needsValue && row.value.trim().length > 0);
  }

  function updateRow(index: number, patch: Partial<FilterRow>) {
    onChange(value.map((row, position) => (position === index ? { ...row, ...patch } : row)));
    markTouched(index);
  }

  function updateField(index: number, fieldName: string) {
    const previous = findField(fields, value[index] ? value[index].field : "");
    const nextField = findField(fields, fieldName);
    const ops = operatorsFor(nextField);
    const currentOp = value[index] ? value[index].op : "eq";
    const op = ops.some((candidate) => candidate.op === currentOp) ? currentOp : ops[0] ? ops[0].op : "eq";
    const keepValue = previous && nextField && previous.kind === nextField.kind && previous.options === nextField.options;
    onChange(
      value.map((row, position) =>
        position === index ? { field: fieldName, op, value: keepValue && row.value ? row.value : "" } : row,
      ),
    );
    markTouched(index);
  }

  function addRow() {
    onChange([...value, defaultFilterRow(fields)]);
  }

  function removeRow(index: number) {
    onChange(value.filter((_row, position) => position !== index));
    setTouched((current) =>
      current
        .filter((position) => position !== index)
        .map((position) => (position > index ? position - 1 : position)),
    );
  }

  const revealedInvalid = value.filter((_row, index) => shouldReveal(index)).length;

  return (
    <div className="filters" role="group" aria-label={label}>
      {value.length === 0 ? (
        <p className="filters__note">No filters. Every event in the selected range is shown.</p>
      ) : (
        <div className="filters__list">
          {value.map((row, index) => {
            const field = findField(fields, row.field);
            const ops = operatorsFor(field);
            const op = ops.find((candidate) => candidate.op === row.op);
            const needsValue = op ? op.needsValue : true;
            const error = errors[index];
            const showError = shouldReveal(index);
            const valueLabel = "Filter " + String(index + 1) + " value";
            return (
              <div className="filter-row" key={index}>
                <Select
                  className="select--compact"
                  aria-label={"Filter " + String(index + 1) + " field"}
                  value={row.field}
                  disabled={disabled}
                  onChange={(event) => updateField(index, event.target.value)}
                >
                  {fields.map((candidate) => (
                    <option key={candidate.field} value={candidate.field}>
                      {candidate.label}
                    </option>
                  ))}
                </Select>
                <Select
                  className="select--compact"
                  aria-label={"Filter " + String(index + 1) + " operator"}
                  value={row.op}
                  disabled={disabled}
                  onChange={(event) => updateRow(index, { op: event.target.value as FilterOp })}
                >
                  {ops.map((candidate) => (
                    <option key={candidate.op} value={candidate.op}>
                      {candidate.label}
                    </option>
                  ))}
                </Select>
                {needsValue ? (
                  field && field.kind === "enum" && field.options ? (
                    <Select
                      className="select--compact"
                      aria-label={valueLabel}
                      value={row.value}
                      disabled={disabled}
                      onChange={(event) => updateRow(index, { value: event.target.value })}
                    >
                      <option value="">Choose a value</option>
                      {field.options.map((option) => (
                        <option key={option} value={option}>
                          {option}
                        </option>
                      ))}
                    </Select>
                  ) : (
                    <TextInput
                      className={cx("input--compact", field?.kind === "ip" && "input--mono")}
                      aria-label={valueLabel}
                      placeholder={field?.placeholder ?? "Value"}
                      value={row.value}
                      disabled={disabled}
                      onChange={(event) => updateRow(index, { value: event.target.value })}
                    />
                  )
                ) : (
                  <span className="filter-row__fixed">No value needed</span>
                )}
                <IconButton
                  icon={X}
                  label={"Remove filter " + String(index + 1)}
                  className="btn--sm"
                  disabled={disabled}
                  onClick={() => removeRow(index)}
                />
                {showError && error ? (
                  <p className="filter-row__error" role="alert">
                    {error}
                  </p>
                ) : null}
              </div>
            );
          })}
        </div>
      )}
      <div className="filters__foot">
        <Button size="sm" variant="ghost" icon={Plus} onClick={addRow} disabled={disabled}>
          Add filter
        </Button>
        {value.length > 0 ? (
          <span className={cx("filters__note", revealedInvalid > 0 && "filters__note--warn")}>
            {revealedInvalid > 0
              ? String(revealedInvalid) + " filter needs a fix before it is applied"
              : String(value.length) + (value.length === 1 ? " filter" : " filters") + " applied with AND"}
          </span>
        ) : null}
      </div>
    </div>
  );
}
