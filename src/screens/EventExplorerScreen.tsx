import { useCallback, useMemo, useState } from "react";
import { Download, Inbox, RefreshCw, Search, SlidersHorizontal } from "lucide-react";

import { api } from "../services/api";
import type { EventDetail, EventQuery, EventRow, FilterRow } from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { useWorkspace } from "../context/WorkspaceContext";
import { errorMessage, useLoad } from "../lib/async";
import { pickSavePath } from "../lib/dialog";
import { formatDuration, formatEndpoint, formatNumber, formatTimestamp, formatValue } from "../lib/format";
import { EVENT_FIELDS, validateFilterRow } from "../lib/filterFields";
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
import { FilterBuilder } from "../components/FilterBuilder";
import { EventDetailPanel } from "../components/EventDetailPanel";

const PAGE_SIZES = [25, 50, 100, 250] as const;

export function EventExplorerScreen() {
  const { mode, isAnalyst } = useMode();
  const { version } = useWorkspace();
  const datasets = useLoad(() => api.listDatasets(), [version]);

  const [filters, setFilters] = useState<FilterRow[]>([]);
  const [datasetFilter, setDatasetFilter] = useState<number | "all">("all");
  const [rangePreset, setRangePreset] = useState<RangePreset>("all");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [text, setText] = useState("");
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

  function changePageSize(value: number) {
    setPageSize(value);
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
          render: (event: EventRow) => formatTimestamp(event.ts, mode),
          width: "150px",
        },
        {
          key: "severity",
          header: "Severity",
          render: (event: EventRow) => <SeverityBadge severity={event.severity} />,
          width: "86px",
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
          render: (event: EventRow) => formatTimestamp(event.ts, mode),
          width: "150px",
        },
        {
          key: "severity",
          header: "Severity",
          render: (event: EventRow) => <SeverityBadge severity={event.severity} />,
          width: "86px",
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
  const invalidFilterCount = filterErrors.filter((error) => error !== null).length;

  return (
    <div className="page">
      <div className="page__bar">
        <p className="page__lede">
          Build filters step by step instead of writing a query. Combine any number of conditions with AND, choose a
          time range, then open a row to see the normalized fields next to the untouched original record.
        </p>
        <div className="toolbar">
          <Button icon={RefreshCw} variant="ghost" onClick={results.reload} aria-label="Refresh results" />
        </div>
      </div>

      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      <Panel
        title="Guided search"
        meta={invalidFilterCount > 0 ? String(invalidFilterCount) + " filter needs a fix" : undefined}
        actions={
          <Button size="sm" variant="ghost" icon={SlidersHorizontal} onClick={resetSearch}>
            Reset
          </Button>
        }
      >
        <div className="filter-bar">
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
          <Field label="Free text" className="filter-bar__grow">
            <TextInput
              value={text}
              placeholder="Search messages, hosts, users"
              onChange={(event) => changeText(event.target.value)}
            />
          </Field>
        </div>

        <FilterBuilder fields={EVENT_FIELDS} value={filters} onChange={changeFilters} label="Event filters" />
      </Panel>

      <Panel
        title="Results"
        meta={
          resultData
            ? formatNumber(resultData.total) +
              " events in " +
              formatDuration(resultData.durationMs) +
              (invalidFilterCount > 0 ? " (invalid filters ignored)" : "")
            : undefined
        }
        actions={
          <div className="toolbar">
            <Button
              size="sm"
              icon={Download}
              onClick={() => handleExport("csv")}
              disabled={exporting !== null || resultData === null}
            >
              {exporting === "csv" ? "Exporting" : "CSV"}
            </Button>
            <Button
              size="sm"
              icon={Download}
              onClick={() => handleExport("json")}
              disabled={exporting !== null || resultData === null}
            >
              {exporting === "json" ? "Exporting" : "JSON"}
            </Button>
          </div>
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
            <DataTable
              label="Events"
              columns={columns}
              rows={resultEvents}
              rowKey={(event: EventRow) => event.id}
              onRowClick={(event: EventRow) => void openEventDetail(event.id)}
              selectedKey={selectedId}
              sort={{ key: sort, direction: sortDir }}
              onSortChange={handleSort}
              dense
            />
            <Pagination
              page={resultData ? resultData.page : page}
              pageSize={resultData ? resultData.pageSize : pageSize}
              total={resultData ? resultData.total : 0}
              pageSizes={PAGE_SIZES}
              onPageChange={setPage}
              onPageSizeChange={changePageSize}
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
