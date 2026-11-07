import { useCallback, useEffect, useMemo, useState } from "react";
import { Download, Inbox, RefreshCw, Search, SlidersHorizontal, X } from "lucide-react";

import { api } from "../services/api";
import type { EventDetail, EventQuery, EventRow, FilterRow } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { useWorkspace } from "../context/WorkspaceContext";
import { errorMessage, useLoad } from "../lib/async";
import { pickSavePath } from "../lib/dialog";
import {
  formatDuration,
  formatEndpoint,
  formatFieldLabel,
  formatNumber,
  formatTimestamp,
  formatValue,
} from "../lib/format";
import { EVENT_FIELDS, OPERATORS, validateFilterRow } from "../lib/filterFields";
import { RANGE_PRESETS, parseDateTimeInput, presetWindow } from "../lib/timeRange";
import type { RangePreset } from "../lib/timeRange";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { Field, Select, TextInput } from "../components/ui/Field";
import { ProtocolChip, SeverityBadge } from "../components/ui/Badge";
import { DataTable, Pagination } from "../components/ui/Table";
import type { Column, SortState } from "../components/ui/Table";
import { Drawer } from "../components/ui/Drawer";
import { FilterChip } from "../components/ui/FilterChips";
import { FilterBuilder } from "../components/FilterBuilder";
import { EventDetailPanel } from "../components/EventDetailPanel";

const PAGE_SIZES = [25, 50, 100, 250] as const;

export interface EventExplorerScreenProps {
  /** Text pushed in from the global search box. */
  initialText?: string;
}

export function EventExplorerScreen({ initialText = "" }: EventExplorerScreenProps) {
  const { mode, isAnalyst } = useMode();
  const { version } = useWorkspace();
  const datasets = useLoad(() => api.listDatasets(), [version]);

  const [filters, setFilters] = useState<FilterRow[]>([]);
  const [datasetFilter, setDatasetFilter] = useState<number | "all">("all");
  const [rangePreset, setRangePreset] = useState<RangePreset>("all");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [text, setText] = useState(initialText);
  const [showBuilder, setShowBuilder] = useState(false);
  const [sort, setSort] = useState("ts");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);

  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<EventDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [exporting, setExporting] = useState<"csv" | "json" | null>(null);

  useEffect(() => {
    setText(initialText);
    setPage(1);
  }, [initialText]);

  const range = useMemo(() => {
    if (rangePreset === "custom") {
      return { fromTs: parseDateTimeInput(customFrom), toTs: parseDateTimeInput(customTo) };
    }
    return presetWindow(rangePreset);
  }, [rangePreset, customFrom, customTo]);

  const filterErrors = useMemo(() => filters.map((row) => validateFilterRow(row, EVENT_FIELDS)), [filters]);
  const appliedFilters = useMemo(
    () => filters.filter((_row, index) => filterErrors[index] === null),
    [filters, filterErrors],
  );

  const query = useMemo<EventQuery>(
    () => ({
      datasetIds: datasetFilter === "all" ? [] : [datasetFilter],
      sourceTypes: [],
      fromTs: range.fromTs,
      toTs: range.toTs,
      filters: appliedFilters,
      text: text.trim().length > 0 ? text.trim() : null,
      sort,
      sortDir,
      page,
      pageSize,
    }),
    [datasetFilter, range, appliedFilters, text, sort, sortDir, page, pageSize],
  );

  const results = useLoad(() => api.searchEvents(query), [JSON.stringify(query), version]);

  const datasetLabel =
    datasetFilter === "all"
      ? "All datasets"
      : (datasets.data ?? []).find((dataset) => dataset.id === datasetFilter)?.name ?? "Dataset";
  const rangeLabel = RANGE_PRESETS.find((preset) => preset.id === rangePreset)?.label ?? "All time";
  const invalidFilterCount = filterErrors.filter((error) => error !== null).length;
  const activeChips: Array<{ key: string; label: string; value: string; remove: () => void }> = [];

  if (datasetFilter !== "all") {
    activeChips.push({
      key: "dataset",
      label: "Dataset",
      value: datasetLabel,
      remove: () => {
        setDatasetFilter("all");
        setPage(1);
      },
    });
  }
  if (rangePreset !== "all") {
    activeChips.push({
      key: "range",
      label: "Range",
      value: rangeLabel,
      remove: () => {
        setRangePreset("all");
        setPage(1);
      },
    });
  }
  filters.forEach((row, index) => {
    if (filterErrors[index] !== null) return;
    const operator = OPERATORS.find((candidate) => candidate.op === row.op);
    const value = operator && !operator.needsValue ? operator.label : operator ? operator.label + " " + row.value : row.value;
    activeChips.push({
      key: "filter-" + String(index),
      label: formatFieldLabel(row.field),
      value,
      remove: () => {
        setFilters(filters.filter((_candidate, position) => position !== index));
        setPage(1);
      },
    });
  });

  function changeFilters(next: FilterRow[]) {
    setFilters(next);
    setPage(1);
  }

  function changeDataset(value: string) {
    setDatasetFilter(value === "all" ? "all" : Number(value));
    setPage(1);
  }

  function changeRange(value: string) {
    setRangePreset(value as RangePreset);
    setPage(1);
  }

  function changeText(value: string) {
    setText(value);
    setPage(1);
  }

  function handleSort(next: SortState) {
    setSort(next.key);
    setSortDir(next.direction);
    setPage(1);
  }

  function resetSearch() {
    setFilters([]);
    setText("");
    setDatasetFilter("all");
    setRangePreset("all");
    setCustomFrom("");
    setCustomTo("");
    setPage(1);
  }

  const closeDetail = useCallback(() => {
    setSelectedId(null);
    setDetail(null);
    setDetailError(null);
  }, []);

  const openEventDetail = useCallback(async (eventId: number) => {
    setSelectedId(eventId);
    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    try {
      const loaded = await api.getEvent(eventId);
      setDetail(loaded);
    } catch (cause) {
      setDetailError(errorMessage(cause));
    } finally {
      setDetailLoading(false);
    }
  }, []);

  async function handleExport(format: "csv" | "json") {
    const target = await pickSavePath("events." + format, [
      { name: format === "csv" ? "CSV" : "JSON", extensions: [format] },
    ]);
    if (!target) return;
    setExporting(format);
    setActionError(null);
    setNotice(null);
    try {
      const written = await api.exportEvents({ path: target, format, query });
      setNotice("Exported " + written + ".");
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setExporting(null);
    }
  }

  const columns: ReadonlyArray<Column<EventRow>> = isAnalyst
    ? [
        {
          key: "ts",
          header: "Time",
          sortable: true,
          mono: true,
          width: "156px",
          render: (event: EventRow) => formatTimestamp(event.ts, mode),
        },
        {
          key: "severity",
          header: "Severity",
          width: "96px",
          render: (event: EventRow) => <SeverityBadge severity={event.severity} />,
        },
        { key: "sourceType", header: "Source type", render: (event: EventRow) => formatValue(event.sourceType) },
        { key: "category", header: "Event category", render: (event: EventRow) => formatValue(event.category) },
        { key: "eventType", header: "Event type", render: (event: EventRow) => formatValue(event.eventType) },
        {
          key: "srcIp",
          header: "Source IP",
          mono: true,
          render: (event: EventRow) => formatEndpoint(event.srcIp, event.srcPort),
        },
        {
          key: "dstIp",
          header: "Destination IP",
          mono: true,
          render: (event: EventRow) => formatEndpoint(event.dstIp, event.dstPort),
        },
        {
          key: "transport",
          header: "Transport",
          render: (event: EventRow) => <ProtocolChip protocol={event.transport} />,
        },
        { key: "appProto", header: "App protocol", render: (event: EventRow) => <ProtocolChip protocol={event.appProto} /> },
        { key: "action", header: "Action", render: (event: EventRow) => formatValue(event.action) },
        { key: "username", header: "User", render: (event: EventRow) => formatValue(event.username) },
      ]
    : [
        {
          key: "ts",
          header: "Time",
          sortable: true,
          mono: true,
          width: "156px",
          render: (event: EventRow) => formatTimestamp(event.ts, mode),
        },
        {
          key: "severity",
          header: "Severity",
          width: "96px",
          render: (event: EventRow) => <SeverityBadge severity={event.severity} />,
        },
        {
          key: "srcIp",
          header: "From",
          mono: true,
          render: (event: EventRow) => formatEndpoint(event.srcIp, event.srcPort),
        },
        {
          key: "dstIp",
          header: "To",
          mono: true,
          render: (event: EventRow) => formatEndpoint(event.dstIp, event.dstPort),
        },
        {
          key: "message",
          header: "What happened",
          render: (event: EventRow) => (
            <span className="cell-chips">
              {event.appProto ? <ProtocolChip protocol={event.appProto} /> : null}
              <span className="truncate">{formatValue(event.message)}</span>
            </span>
          ),
        },
      ];

  const resultData = results.data;
  const resultEvents = resultData ? resultData.events : [];
  const pageCount = resultData ? Math.max(1, Math.ceil(resultData.total / Math.max(1, resultData.pageSize))) : 1;

  return (
    <div className="page">
      <div className="page__head">
        <div className="page__titles">
          <h2 className="page__title">Event Explorer</h2>
          <p className="page__lede">
            Build conditions instead of writing a query: combine any number of filters with AND, choose a time range,
            then open a row for the normalized fields next to the untouched original record.
          </p>
        </div>
        <div className="page__actions">
          <Button icon={RefreshCw} variant="ghost" onClick={results.reload} aria-label="Refresh results" />
        </div>
      </div>

      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      <Panel flush>
        <div className="event-search">
          <div className="event-search__row">
            <div className="event-search__input">
              <Search size={15} aria-hidden="true" />
              <input
                value={text}
                placeholder="Search messages, hosts, users"
                aria-label="Search events"
                onChange={(event) => changeText(event.target.value)}
              />
              {text.length > 0 ? (
                <button
                  type="button"
                  className="icon-btn"
                  aria-label="Clear search text"
                  onClick={() => changeText("")}
                >
                  <X size={13} aria-hidden="true" />
                </button>
              ) : null}
            </div>
            <Button
              icon={SlidersHorizontal}
              variant={showBuilder ? "secondary" : "ghost"}
              onClick={() => setShowBuilder((current) => !current)}
            >
              {showBuilder ? "Hide filters" : "Filters"}
              {appliedFilters.length > 0 ? " (" + String(appliedFilters.length) + ")" : ""}
            </Button>
            <Button variant="ghost" onClick={resetSearch}>
              Reset
            </Button>
          </div>

          <div className="event-search__controls">
            <Field label="Dataset">
              <Select value={String(datasetFilter)} onChange={(event) => changeDataset(event.target.value)}>
                <option value="all">All datasets</option>
                {(datasets.data ?? []).map((dataset) => (
                  <option key={dataset.id} value={String(dataset.id)}>
                    {dataset.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Time range">
              <Select value={rangePreset} onChange={(event) => changeRange(event.target.value)}>
                {RANGE_PRESETS.map((preset) => (
                  <option key={preset.id} value={preset.id}>
                    {preset.label}
                  </option>
                ))}
              </Select>
            </Field>
            {rangePreset === "custom" ? (
              <>
                <Field label="From">
                  <TextInput
                    type="datetime-local"
                    value={customFrom}
                    onChange={(event) => {
                      setCustomFrom(event.target.value);
                      setPage(1);
                    }}
                  />
                </Field>
                <Field label="To">
                  <TextInput
                    type="datetime-local"
                    value={customTo}
                    onChange={(event) => {
                      setCustomTo(event.target.value);
                      setPage(1);
                    }}
                  />
                </Field>
              </>
            ) : null}
            <div className="grow" />
            <Button
              size="sm"
              icon={Download}
              variant="ghost"
              onClick={() => handleExport("csv")}
              disabled={exporting !== null || resultData === null}
            >
              {exporting === "csv" ? "Exporting" : "CSV"}
            </Button>
            <Button
              size="sm"
              icon={Download}
              variant="ghost"
              onClick={() => handleExport("json")}
              disabled={exporting !== null || resultData === null}
            >
              {exporting === "json" ? "Exporting" : "JSON"}
            </Button>
          </div>

          <div className="active-filters">
            <span className="active-filters__label">Active</span>
            {activeChips.length === 0 ? (
              <span className="dim">No filters — every event in the selected range is shown.</span>
            ) : (
              <>
                {activeChips.map((chip) => (
                  <FilterChip key={chip.key} label={chip.label} value={chip.value} onRemove={chip.remove} />
                ))}
                <Button size="sm" variant="ghost" onClick={resetSearch}>
                  Clear all
                </Button>
              </>
            )}
            {invalidFilterCount > 0 ? (
              <span className="filters__note--warn">
                {String(invalidFilterCount)} filter{invalidFilterCount === 1 ? "" : "s"} waiting for a valid value
              </span>
            ) : null}
          </div>
        </div>

        {showBuilder ? (
          <div className="filter-builder">
            <FilterBuilder fields={EVENT_FIELDS} value={filters} onChange={changeFilters} label="Event filters" />
          </div>
        ) : null}
      </Panel>

      <Panel
        title="Results"
        meta={
          resultData
            ? formatNumber(resultData.total) +
              " events · " +
              formatDuration(resultData.durationMs) +
              (invalidFilterCount > 0 ? " · invalid filters ignored" : "")
            : undefined
        }
        flush
      >
        {results.loading ? (
          <LoadingState label="Searching events" />
        ) : results.error ? (
          <ErrorState message={results.error} onRetry={results.reload} />
        ) : resultEvents.length === 0 ? (
          <EmptyState
            icon={Inbox}
            title="No events match this search"
            description={
              datasets.data && datasets.data.length === 0
                ? "No datasets have been imported yet. Import a log file from the Overview or Data Sources screen."
                : "Widen the time range, remove a filter, or clear the free-text box."
            }
            action={
              <Button icon={Search} variant="ghost" onClick={resetSearch}>
                Clear search
              </Button>
            }
          />
        ) : (
          <>
            <div className="event-meta" style={{ padding: "var(--s-3) var(--s-6)" }}>
              <span>
                page {resultData ? resultData.page : page} of {pageCount}
              </span>
              <span className="dot" aria-hidden="true" />
              <span>
                {String(appliedFilters.length)} filter{appliedFilters.length === 1 ? "" : "s"} applied
              </span>
              {text.trim().length > 0 ? (
                <>
                  <span className="dot" aria-hidden="true" />
                  <span>text: {text.trim()}</span>
                </>
              ) : null}
              <span className="dot" aria-hidden="true" />
              <span>{isAnalyst ? "analyst density" : "beginner density"}</span>
            </div>
            <DataTable
              label="Events"
              columns={columns}
              rows={resultEvents}
              rowKey={(event: EventRow) => event.id}
              onRowClick={(event: EventRow) => void openEventDetail(event.id)}
              selectedKey={selectedId}
              sort={{ key: sort, direction: sortDir }}
              onSortChange={handleSort}
              dense={!isAnalyst}
            />
            <Pagination
              page={resultData ? resultData.page : page}
              pageSize={resultData ? resultData.pageSize : pageSize}
              total={resultData ? resultData.total : 0}
              pageSizes={PAGE_SIZES}
              onPageChange={setPage}
              onPageSizeChange={(size) => {
                setPageSize(size);
                setPage(1);
              }}
            />
          </>
        )}
      </Panel>

      <Drawer
        open={selectedId !== null}
        title={selectedId !== null ? "Event " + String(selectedId) : "Event"}
        subtitle={detail ? formatTimestamp(detail.event.ts, mode) : undefined}
        onClose={closeDetail}
        testId="event-detail"
      >
        <EventDetailPanel detail={detail} loading={detailLoading} error={detailError} mode={mode} />
      </Drawer>
    </div>
  );
}
