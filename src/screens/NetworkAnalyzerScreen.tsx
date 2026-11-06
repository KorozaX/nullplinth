import { useCallback, useEffect, useMemo, useState } from "react";
import { Inbox, Layers, RefreshCw, Upload } from "lucide-react";

import { api } from "../services/api";
import type {
  Capture,
  FilterRow,
  FlowRow,
  PacketDetail,
  PacketPage,
  PacketQuery,
  PacketRow,
} from "../types/contracts";
import { useMode } from "../context/ModeContext";
import { errorMessage, useLoad } from "../lib/async";
import { pickFile } from "../lib/dialog";
import { formatBytes, formatDuration, formatEndpoint, formatNumber, formatTimestamp } from "../lib/format";
import { PACKET_FIELDS, validateFilterRow } from "../lib/filterFields";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { Field, Select } from "../components/ui/Field";
import { DataTable, Pagination } from "../components/ui/Table";
import type { Column } from "../components/ui/Table";
import { FilterBuilder } from "../components/FilterBuilder";
import { LayerTree } from "../components/LayerTree";
import { HexView } from "../components/HexView";

const PAGE_SIZES = [50, 100, 250, 500] as const;

export function NetworkAnalyzerScreen() {
  const { mode, isAnalyst } = useMode();
  const captures = useLoad(() => api.listCaptures(), []);

  const [captureId, setCaptureId] = useState<number | null>(null);
  const [filters, setFilters] = useState<FilterRow[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(100);

  const [activeFlowId, setActiveFlowId] = useState<number | null>(null);
  const [flowPackets, setFlowPackets] = useState<PacketRow[] | null>(null);

  const [selectedPacketId, setSelectedPacketId] = useState<number | null>(null);
  const [packetDetail, setPacketDetail] = useState<PacketDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [importBusy, setImportBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  useEffect(() => {
    const list = captures.data;
    if (!list || list.length === 0) return;
    if (captureId === null || !list.some((capture) => capture.id === captureId)) {
      setCaptureId(list[0].id);
    }
  }, [captures.data, captureId]);

  const flows = useLoad(
    () => (captureId === null ? Promise.resolve<FlowRow[]>([]) : api.listFlows(captureId)),
    [captureId],
  );

  const filterErrors = useMemo(() => filters.map((row) => validateFilterRow(row, PACKET_FIELDS)), [filters]);
  const appliedFilters = useMemo(
    () => filters.filter((_row, index) => filterErrors[index] === null),
    [filters, filterErrors],
  );

  const query = useMemo<PacketQuery>(
    () => ({
      captureId,
      filters: appliedFilters,
      fromTs: null,
      toTs: null,
      sort: "packetNo",
      sortDir: "asc",
      page,
      pageSize,
    }),
    [captureId, appliedFilters, page, pageSize],
  );

  const packets = useLoad<PacketPage>(
    () =>
      captureId === null
        ? Promise.resolve<PacketPage>({ total: 0, packets: [], page, pageSize, durationMs: 0 })
        : api.searchPackets(query),
    [JSON.stringify(query)],
  );

  function changeCapture(value: string) {
    setCaptureId(Number(value));
    setPage(1);
    setActiveFlowId(null);
    setFlowPackets(null);
    setSelectedPacketId(null);
    setPacketDetail(null);
  }

  function changeFilters(next: FilterRow[]) {
    setFilters(next);
    setPage(1);
  }

  const openPacket = useCallback(async (packetId: number) => {
    setSelectedPacketId(packetId);
    setPacketDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    try {
      const loaded = await api.getPacket(packetId);
      setPacketDetail(loaded);
    } catch (cause) {
      setDetailError(errorMessage(cause));
    } finally {
      setDetailLoading(false);
    }
  }, []);

  async function selectFlow(flow: FlowRow) {
    setActiveFlowId(flow.id);
    setFlowPackets(null);
    setSelectedPacketId(null);
    setPacketDetail(null);
    setDetailError(null);
    try {
      const rows = await api.getFlowPackets(flow.id);
      setFlowPackets(rows);
    } catch (cause) {
      setActionError(errorMessage(cause));
    }
  }

  function clearFlow() {
    setActiveFlowId(null);
    setFlowPackets(null);
  }

  async function handleImport() {
    const path = await pickFile("Import packet capture", [
      { name: "Packet captures", extensions: ["pcap", "pcapng", "cap"] },
    ]);
    if (!path) return;
    setImportBusy(true);
    setNotice(null);
    setActionError(null);
    try {
      const capture = await api.importPcap(path);
      setNotice(
        "Imported " + formatNumber(capture.packetCount) + " packets from " + capture.name + ".",
      );
      captures.reload();
      setCaptureId(capture.id);
      setPage(1);
      setActiveFlowId(null);
      setFlowPackets(null);
    } catch (cause) {
      setActionError(errorMessage(cause));
    } finally {
      setImportBusy(false);
    }
  }

  const columns: ReadonlyArray<Column<PacketRow>> = isAnalyst
    ? [
        {
          key: "packetNo",
          header: "No.",
          mono: true,
          align: "right",
          width: "70px",
          render: (packet: PacketRow) => formatNumber(packet.packetNo),
        },
        {
          key: "ts",
          header: "Time",
          mono: true,
          width: "150px",
          render: (packet: PacketRow) => formatTimestamp(packet.ts, mode),
        },
        {
          key: "srcIp",
          header: "Source",
          mono: true,
          render: (packet: PacketRow) => formatEndpoint(packet.srcIp, packet.srcPort),
        },
        {
          key: "dstIp",
          header: "Destination",
          mono: true,
          render: (packet: PacketRow) => formatEndpoint(packet.dstIp, packet.dstPort),
        },
        { key: "protocol", header: "Protocol", render: (packet: PacketRow) => packet.protocol ?? "\u2014" },
        { key: "transport", header: "Transport", render: (packet: PacketRow) => packet.transport ?? "\u2014" },
        { key: "tcpFlags", header: "Flags", mono: true, render: (packet: PacketRow) => packet.tcpFlags ?? "\u2014" },
        {
          key: "caplen",
          header: "Len",
          mono: true,
          align: "right",
          render: (packet: PacketRow) => String(packet.caplen),
        },
        { key: "summary", header: "Info", render: (packet: PacketRow) => packet.summary ?? "\u2014" },
      ]
    : [
        {
          key: "packetNo",
          header: "No.",
          mono: true,
          align: "right",
          width: "70px",
          render: (packet: PacketRow) => formatNumber(packet.packetNo),
        },
        {
          key: "ts",
          header: "Time",
          mono: true,
          width: "150px",
          render: (packet: PacketRow) => formatTimestamp(packet.ts, mode),
        },
        {
          key: "srcIp",
          header: "From",
          mono: true,
          render: (packet: PacketRow) => formatEndpoint(packet.srcIp, packet.srcPort),
        },
        {
          key: "dstIp",
          header: "To",
          mono: true,
          render: (packet: PacketRow) => formatEndpoint(packet.dstIp, packet.dstPort),
        },
        { key: "protocol", header: "Protocol", render: (packet: PacketRow) => packet.protocol ?? "\u2014" },
        { key: "summary", header: "Info", render: (packet: PacketRow) => packet.summary ?? "\u2014" },
      ];

  if (captures.loading && !captures.data) return <LoadingState label="Loading captures" />;
  if (captures.error) return <ErrorState message={captures.error} onRetry={captures.reload} />;

  const captureList: readonly Capture[] = captures.data ?? [];
  const hasCaptures = captureList.length > 0;
  const visiblePackets: readonly PacketRow[] = flowPackets ?? (packets.data ? packets.data.packets : []);
  const activeFlow = (flows.data ?? []).find((flow) => flow.id === activeFlowId) ?? null;

  const captureBar = (
    <div className="network__bar">
      <Field label="Capture">
        <Select
          value={captureId === null ? "" : String(captureId)}
          onChange={(event) => changeCapture(event.target.value)}
          disabled={!hasCaptures}
        >
          {hasCaptures ? null : <option value="">No captures</option>}
          {captureList.map((capture) => (
            <option key={capture.id} value={String(capture.id)}>
              {capture.name} ({formatNumber(capture.packetCount)} packets)
            </option>
          ))}
        </Select>
      </Field>
      <div className="toolbar">
        <Button icon={Upload} variant="primary" onClick={handleImport} disabled={importBusy}>
          {importBusy ? "Importing" : "Import PCAP"}
        </Button>
        <Button icon={RefreshCw} variant="ghost" onClick={captures.reload} aria-label="Refresh captures" />
      </div>
    </div>
  );

  return (
    <div className="page">
      <div className="page__bar">
        <p className="page__lede">
          Decode captures offline: packets are parsed into protocol layers, grouped into conversations, and shown as a
          hex dump. Payloads are never decrypted.
        </p>
      </div>

      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      {!hasCaptures ? (
        <Panel flush>
          <EmptyState
            icon={Inbox}
            title="No captures imported"
            description="Import a .pcap or .pcapng file to decode Ethernet, IP, TCP, UDP, ICMP, DNS, HTTP and TLS records. Unsupported link types are reported instead of aborting the import."
            action={
              <Button icon={Upload} variant="primary" onClick={handleImport} disabled={importBusy}>
                {importBusy ? "Importing" : "Import PCAP"}
              </Button>
            }
          />
        </Panel>
      ) : (
        <div className="network">
          <Panel title="Capture" meta={formatNumber(captureList.length)}>{captureBar}</Panel>

          <div className="network__main">
            <Panel title="Conversations" meta={formatNumber(flows.data ? flows.data.length : 0)} flush>
              {flows.loading ? (
                <LoadingState label="Loading conversations" />
              ) : flows.error ? (
                <ErrorState message={flows.error} onRetry={flows.reload} />
              ) : (flows.data ?? []).length === 0 ? (
                <EmptyState compact icon={Layers} title="No conversations" description="No flow groups found in this capture." />
              ) : (
                <div className="record-list flow-list">
                  {activeFlow ? (
                    <div className="panel__body">
                      <Button size="sm" variant="ghost" onClick={clearFlow}>
                        Show all packets
                      </Button>
                    </div>
                  ) : null}
                  {(flows.data ?? []).map((flow) => (
                    <button
                      key={flow.id}
                      type="button"
                      className={"record" + (flow.id === activeFlowId ? " is-active" : "")}
                      onClick={() => void selectFlow(flow)}
                    >
                      <span className="record__title mono">
                        {formatEndpoint(flow.srcIp, flow.srcPort)}
                      </span>
                      <span className="record__title mono">
                        {"\u2192 " + formatEndpoint(flow.dstIp, flow.dstPort)}
                      </span>
                      <span className="record__meta">
                        <span>{flow.transport}</span>
                        <span>{formatNumber(flow.packetCount)} packets</span>
                        <span>{formatBytes(flow.bytesTotal)}</span>
                      </span>
                    </button>
                  ))}
                </div>
              )}
            </Panel>

            <Panel
              title={activeFlow ? "Conversation packets" : "Packets"}
              meta={
                activeFlow
                  ? formatNumber(flowPackets ? flowPackets.length : activeFlow.packetCount) + " packets"
                  : packets.data
                    ? formatNumber(packets.data.total) + " in " + formatDuration(packets.data.durationMs)
                    : undefined
              }
              actions={
                activeFlow ? (
                  <Button size="sm" variant="ghost" onClick={clearFlow}>
                    Clear conversation
                  </Button>
                ) : undefined
              }
              flush
            >
              <div className="panel__body">
                {activeFlow ? null : (
                  <FilterBuilder
                    fields={PACKET_FIELDS}
                    value={filters}
                    onChange={changeFilters}
                    label="Packet filters"
                  />
                )}
              </div>
              {packets.loading && !activeFlow ? (
                <LoadingState label="Searching packets" />
              ) : packets.error && !activeFlow ? (
                <ErrorState message={packets.error} onRetry={packets.reload} />
              ) : visiblePackets.length === 0 ? (
                <EmptyState
                  compact
                  icon={Inbox}
                  title={activeFlow ? "No packets in this conversation" : "No packets match the filters"}
                  description={activeFlow ? undefined : "Clear a filter or import a capture with packets."}
                />
              ) : (
                <>
                  <DataTable
                    label="Packets"
                    columns={columns}
                    rows={visiblePackets}
                    rowKey={(packet: PacketRow) => packet.id}
                    onRowClick={(packet: PacketRow) => void openPacket(packet.id)}
                    selectedKey={selectedPacketId}
                    dense
                  />
                  {activeFlow ? null : (
                    <Pagination
                      page={packets.data ? packets.data.page : page}
                      pageSize={packets.data ? packets.data.pageSize : pageSize}
                      total={packets.data ? packets.data.total : 0}
                      pageSizes={PAGE_SIZES}
                      onPageChange={setPage}
                      onPageSizeChange={(size) => {
                        setPageSize(size);
                        setPage(1);
                      }}
                    />
                  )}
                </>
              )}
            </Panel>
          </div>

          <div className="network__inspect">
            <Panel title="Decoded layers" meta={packetDetail ? "Packet " + String(packetDetail.packet.packetNo) : undefined}>
              {detailLoading ? (
                <LoadingState label="Decoding packet" />
              ) : detailError ? (
                <ErrorState message={detailError} />
              ) : packetDetail ? (
                <>
                  {packetDetail.unsupported ? <Notice tone="error">{packetDetail.unsupported}</Notice> : null}
                  <LayerTree layers={packetDetail.layers} />
                </>
              ) : (
                <EmptyState compact icon={Layers} title="No packet selected" description="Choose a packet in the list to inspect its decoded layers." />
              )}
            </Panel>
            <Panel title="Hex + ASCII">
              {packetDetail ? (
                <HexView hex={packetDetail.hex} ascii={packetDetail.ascii} />
              ) : (
                <EmptyState compact icon={Layers} title="No packet selected" description="Raw bytes appear here as 16 bytes per line." />
              )}
            </Panel>
          </div>
        </div>
      )}
    </div>
  );
}
