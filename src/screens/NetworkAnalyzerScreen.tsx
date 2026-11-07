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
import { useWorkspace } from "../context/WorkspaceContext";
import { useImport } from "../components/ImportWorkflow";
import { errorMessage, useLoad } from "../lib/async";
import { formatBytes, formatDuration, formatEndpoint, formatNumber, formatTimestamp } from "../lib/format";
import { PACKET_FIELDS, validateFilterRow } from "../lib/filterFields";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingState, Notice } from "../components/ui/Feedback";
import { Panel } from "../components/ui/Panel";
import { Field, Select } from "../components/ui/Field";
import { EncryptedChip, FrameKindChip, ProtocolChip } from "../components/ui/Badge";
import { DataTable, Pagination } from "../components/ui/Table";
import type { Column } from "../components/ui/Table";
import { FilterBuilder } from "../components/FilterBuilder";
import { LayerTree } from "../components/LayerTree";
import { HexView } from "../components/HexView";

const PAGE_SIZES = [50, 100, 250, 500] as const;

export function NetworkAnalyzerScreen() {
  const { mode, isAnalyst } = useMode();
  const { version } = useWorkspace();
  const { beginImport } = useImport();
  const captures = useLoad(() => api.listCaptures(), [version]);

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
    [captureId, version],
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
    [JSON.stringify(query), version],
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

  const columns: ReadonlyArray<Column<PacketRow>> = isAnalyst
    ? [
        {
          key: "packetNo",
          header: "No.",
          mono: true,
          align: "right",
          width: "68px",
          render: (packet: PacketRow) => formatNumber(packet.packetNo),
        },
        {
          key: "ts",
          header: "Time",
          mono: true,
          width: "156px",
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
        {
          key: "protocol",
          header: "Protocol",
          render: (packet: PacketRow) => <ProtocolChip protocol={packet.protocol} />,
        },
        {
          key: "frameKind",
          header: "Frame",
          render: (packet: PacketRow) => <FrameKindChip frameKind={packet.frameKind} />,
        },
        { key: "tcpFlags", header: "Flags", mono: true, render: (packet: PacketRow) => packet.tcpFlags ?? "\u2014" },
        {
          key: "caplen",
          header: "Len",
          mono: true,
          align: "right",
          render: (packet: PacketRow) => String(packet.caplen),
        },
        {
          key: "summary",
          header: "Info",
          render: (packet: PacketRow) => (
            <span className="cell-chips">
              {packet.encrypted ? <EncryptedChip encrypted /> : null}
              {packet.summary ?? "\u2014"}
            </span>
          ),
        },
      ]
    : [
        {
          key: "packetNo",
          header: "No.",
          mono: true,
          align: "right",
          width: "68px",
          render: (packet: PacketRow) => formatNumber(packet.packetNo),
        },
        {
          key: "ts",
          header: "Time",
          mono: true,
          width: "156px",
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
        {
          key: "protocol",
          header: "Protocol",
          render: (packet: PacketRow) => <ProtocolChip protocol={packet.protocol} />,
        },
        {
          key: "summary",
          header: "Info",
          render: (packet: PacketRow) => (
            <span className="cell-chips">
              {packet.frameKind ? <FrameKindChip frameKind={packet.frameKind} /> : null}
              {packet.encrypted ? <EncryptedChip encrypted /> : null}
              {packet.summary ?? "\u2014"}
            </span>
          ),
        },
      ];

  if (captures.loading && !captures.data) return <LoadingState label="Loading captures" />;
  if (captures.error) return <ErrorState message={captures.error} onRetry={captures.reload} />;

  const captureList: readonly Capture[] = captures.data ?? [];
  const hasCaptures = captureList.length > 0;
  const selectedCapture = captureList.find((capture) => capture.id === captureId) ?? null;
  const visiblePackets: readonly PacketRow[] = flowPackets ?? (packets.data ? packets.data.packets : []);
  const activeFlow = (flows.data ?? []).find((flow) => flow.id === activeFlowId) ?? null;

  return (
    <div className="page">
      <div className="page__head">
        <div className="page__titles">
          <h2 className="page__title">Network Analyzer</h2>
          <p className="page__lede">
            Decode captures offline: packets are parsed into protocol layers, grouped into conversations and shown as a
            hex dump. Wireless frames are labelled by kind; encrypted payloads are never decrypted.
          </p>
        </div>
        <div className="page__actions">
          <Button icon={Upload} variant="primary" onClick={() => void beginImport()}>
            Import capture
          </Button>
          <Button icon={RefreshCw} variant="ghost" onClick={captures.reload} aria-label="Refresh captures" />
        </div>
      </div>

      {actionError ? <Notice tone="error">{actionError}</Notice> : null}

      {!hasCaptures ? (
        <Panel flush>
          <EmptyState
            icon={Inbox}
            title="No captures imported"
            description="Import a .pcap or .pcapng file to decode Ethernet, 802.11, IP, TCP, UDP, ICMP, DNS, HTTP and TLS records. Unsupported link types are reported instead of aborting the import."
            action={
              <Button icon={Upload} variant="primary" onClick={() => void beginImport()}>
                Import capture
              </Button>
            }
          />
        </Panel>
      ) : (
        <>
          <Panel title="Capture" flush>
            <div className="capture-bar">
              <div className="capture-bar__left">
                <Field label="Active capture">
                  <Select
                    value={captureId === null ? "" : String(captureId)}
                    onChange={(event) => changeCapture(event.target.value)}
                  >
                    {captureList.map((capture) => (
                      <option key={capture.id} value={String(capture.id)}>
                        {capture.name} ({formatNumber(capture.packetCount)} packets)
                      </option>
                    ))}
                  </Select>
                </Field>
                {selectedCapture ? (
                  <div className="capture-bar__meta">
                    <span className="chip chip--eth">{selectedCapture.linkType ?? "unknown link"}</span>
                    <span className="chip chip--other">{formatNumber(selectedCapture.packetCount)} packets</span>
                    <span className="chip chip--other">{formatBytes(selectedCapture.fileSize)}</span>
                    <span className="dim mono">{formatTimestamp(selectedCapture.importedAt, mode)}</span>
                  </div>
                ) : null}
              </div>
            </div>
          </Panel>

          <div className="network-grid">
            <div className="network-main">
              <Panel
                title="Conversations"
                meta={formatNumber(flows.data ? flows.data.length : 0)}
                actions={
                  activeFlow ? (
                    <Button size="sm" variant="ghost" onClick={clearFlow}>
                      Show all traffic
                    </Button>
                  ) : undefined
                }
                flush
              >
                {flows.loading ? (
                  <LoadingState label="Loading conversations" />
                ) : flows.error ? (
                  <ErrorState message={flows.error} onRetry={flows.reload} />
                ) : (flows.data ?? []).length === 0 ? (
                  <EmptyState
                    compact
                    icon={Layers}
                    title="No conversations"
                    description="No flow groups were found in this capture."
                  />
                ) : (
                  <div className="conversation-list">
                    {(flows.data ?? []).map((flow) => (
                      <button
                        key={flow.id}
                        type="button"
                        className={"conversation-row" + (flow.id === activeFlowId ? " is-active" : "")}
                        onClick={() => void selectFlow(flow)}
                      >
                        <span className="conversation-row__pair">
                          <span className="conversation-row__end">{formatEndpoint(flow.srcIp, flow.srcPort)}</span>
                          <span className="conversation-row__end">
                            {"\u2192 " + formatEndpoint(flow.dstIp, flow.dstPort)}
                          </span>
                        </span>
                        <span className="conversation-row__meta">
                          <ProtocolChip protocol={flow.transport} label={flow.transport.toUpperCase()} />
                          {formatNumber(flow.packetCount)} pkts
                          <span className="dim">{formatBytes(flow.bytesTotal)}</span>
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
                <div style={{ padding: "var(--s-4) var(--s-6)" }}>
                  {activeFlow ? null : (
                    <FilterBuilder fields={PACKET_FIELDS} value={filters} onChange={changeFilters} label="Packet filters" />
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

            <div className="network-inspector">
              <Panel
                title="Decoded layers"
                meta={packetDetail ? "Packet " + String(packetDetail.packet.packetNo) : undefined}
              >
                {detailLoading ? (
                  <LoadingState label="Decoding packet" />
                ) : detailError ? (
                  <ErrorState message={detailError} />
                ) : packetDetail ? (
                  <div className="stack--tight">
                    <div className="cell-chips">
                      <ProtocolChip protocol={packetDetail.packet.protocol} />
                      <FrameKindChip frameKind={packetDetail.packet.frameKind} />
                      <EncryptedChip encrypted={packetDetail.packet.encrypted} />
                    </div>
                    {packetDetail.unsupported ? <Notice tone="error">{packetDetail.unsupported}</Notice> : null}
                    <LayerTree layers={packetDetail.layers} />
                  </div>
                ) : (
                  <EmptyState
                    compact
                    icon={Layers}
                    title="No packet selected"
                    description="Choose a packet to inspect its decoded protocol hierarchy."
                  />
                )}
              </Panel>

              <Panel title="Hex + ASCII">
                {packetDetail ? (
                  <HexView hex={packetDetail.hex} ascii={packetDetail.ascii} />
                ) : (
                  <EmptyState
                    compact
                    icon={Layers}
                    title="No packet selected"
                    description="Raw bytes appear here as 16 bytes per line, synced to the selected packet."
                  />
                )}
              </Panel>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
