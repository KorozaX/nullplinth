import type { ReactNode } from "react";

import { Button } from "./Button";
import { cx } from "../../lib/cx";
import { formatNumber } from "../../lib/format";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => ReactNode;
  sortable?: boolean;
  mono?: boolean;
  align?: "left" | "right";
  className?: string;
  width?: string;
}

export interface SortState {
  key: string;
  direction: "asc" | "desc";
}

export interface DataTableProps<T> {
  columns: ReadonlyArray<Column<T>>;
  rows: readonly T[];
  rowKey: (row: T) => string | number;
  onRowClick?: (row: T) => void;
  selectedKey?: string | number | null;
  sort?: SortState | null;
  onSortChange?: (next: SortState) => void;
  emptyMessage?: string;
  dense?: boolean;
  label?: string;
}

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  onRowClick,
  selectedKey,
  sort,
  onSortChange,
  emptyMessage = "No rows",
  dense,
  label,
}: DataTableProps<T>) {
  const hasRows = rows.length > 0;
  return (
    <div className={cx("table-wrap", dense && "table-wrap--dense")}>
      <table className="table" aria-label={label}>
        <thead>
          <tr>
            {columns.map((column) => {
              const sorted = sort !== undefined && sort !== null && sort.key === column.key;
              const ariaSort = column.sortable
                ? sorted
                  ? sort?.direction === "asc"
                    ? "ascending"
                    : "descending"
                  : "none"
                : undefined;
              return (
                <th
                  key={column.key}
                  scope="col"
                  style={column.width ? { width: column.width } : undefined}
                  aria-sort={ariaSort}
                >
                  {column.sortable && onSortChange ? (
                    <button
                      type="button"
                      className="th__btn"
                      onClick={() =>
                        onSortChange({
                          key: column.key,
                          direction: sorted && sort?.direction === "desc" ? "asc" : "desc",
                        })
                      }
                    >
                      {column.header}
                      <span className="th__arrow" aria-hidden="true">
                        {sorted ? (sort?.direction === "asc" ? "\u25B2" : "\u25BC") : ""}
                      </span>
                    </button>
                  ) : (
                    column.header
                  )}
                </th>
              );
            })}
          </tr>
        </thead>
        <tbody>
          {hasRows ? (
            rows.map((row) => {
              const key = rowKey(row);
              const selected = selectedKey !== undefined && selectedKey !== null && selectedKey === key;
              return (
                <tr
                  key={key}
                  className={cx(onRowClick && "table__row--clickable", selected && "is-selected")}
                  tabIndex={onRowClick ? 0 : undefined}
                  aria-selected={onRowClick ? selected : undefined}
                  onClick={onRowClick ? () => onRowClick(row) : undefined}
                  onKeyDown={
                    onRowClick
                      ? (event) => {
                          if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            onRowClick(row);
                          }
                        }
                      : undefined
                  }
                >
                  {columns.map((column) => (
                    <td
                      key={column.key}
                      className={cx(column.mono && "mono", column.align === "right" && "ta-right", column.className)}
                    >
                      {column.render(row)}
                    </td>
                  ))}
                </tr>
              );
            })
          ) : (
            <tr>
              <td className="table__empty" colSpan={columns.length}>
                {emptyMessage}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

export interface PaginationProps {
  page: number;
  pageSize: number;
  total: number;
  pageSizes?: readonly number[];
  onPageChange: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
  disabled?: boolean;
}

export function Pagination({
  page,
  pageSize,
  total,
  pageSizes,
  onPageChange,
  onPageSizeChange,
  disabled,
}: PaginationProps) {
  const pageCount = Math.max(1, Math.ceil(total / Math.max(1, pageSize)));
  return (
    <div className="pager">
      <span className="pager__summary">
        {formatNumber(total) + " " + (total === 1 ? "result" : "results") + " \u00B7 page " + String(page) + " of " + String(pageCount)}
      </span>
      <div className="pager__controls">
        {onPageSizeChange && pageSizes ? (
          <label className="pager__size">
            Rows
            <select
              value={pageSize}
              disabled={disabled}
              onChange={(event) => onPageSizeChange(Number(event.target.value))}
            >
              {pageSizes.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
        ) : null}
        <Button size="sm" variant="ghost" disabled={disabled || page <= 1} onClick={() => onPageChange(page - 1)} aria-label="Previous page">
          Prev
        </Button>
        <Button
          size="sm"
          variant="ghost"
          disabled={disabled || page >= pageCount}
          onClick={() => onPageChange(page + 1)}
          aria-label="Next page"
        >
          Next
        </Button>
      </div>
    </div>
  );
}
