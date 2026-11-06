// The only place that talks to the Rust backend. Every Tauri command lives here.
import { invoke } from "@tauri-apps/api/core";

import type {
  Alert,
  AlertDetail,
  Capture,
  CsvPreview,
  Dataset,
  DetectionRun,
  DetectionSettings,
  EventDetail,
  EventPage,
  EventQuery,
  ExportRequest,
  FlowRow,
  ImportOptions,
  ImportResult,
  Investigation,
  InvestigationDetail,
  NewInvestigation,
  Overview,
  PacketDetail,
  PacketPage,
  PacketQuery,
  PacketRow,
} from "../types/contracts";

export const api = {
  getOverview: () => invoke<Overview>("get_overview"),

  listDatasets: () => invoke<Dataset[]>("list_datasets"),
  deleteDataset: (datasetId: number) => invoke<void>("delete_dataset", { datasetId }),
  loadDemoData: () => invoke<number>("load_demo_data"),

  previewCsv: (path: string) => invoke<CsvPreview>("preview_csv", { path }),
  importFile: (options: ImportOptions) => invoke<ImportResult>("import_file", { options }),

  searchEvents: (query: EventQuery) => invoke<EventPage>("search_events", { query }),
  getEvent: (eventId: number) => invoke<EventDetail>("get_event", { eventId }),
  exportEvents: (request: ExportRequest) => invoke<string>("export_events", { request }),

  importPcap: (path: string) => invoke<Capture>("import_pcap", { path }),
  listCaptures: () => invoke<Capture[]>("list_captures"),
  deleteCapture: (captureId: number) => invoke<void>("delete_capture", { captureId }),
  searchPackets: (query: PacketQuery) => invoke<PacketPage>("search_packets", { query }),
  getPacket: (packetId: number) => invoke<PacketDetail>("get_packet", { packetId }),
  listFlows: (captureId: number | null) => invoke<FlowRow[]>("list_flows", { captureId }),
  getFlowPackets: (flowId: number) => invoke<PacketRow[]>("get_flow_packets", { flowId }),

  runDetection: () => invoke<DetectionRun>("run_detection"),
  listAlerts: (severity?: string | null, status?: string | null) =>
    invoke<Alert[]>("list_alerts", { severity: severity ?? null, status: status ?? null }),
  getAlert: (alertId: number) => invoke<AlertDetail>("get_alert", { alertId }),
  updateAlertStatus: (alertId: number, status?: string | null, note?: string | null) =>
    invoke<void>("update_alert_status", { alertId, status: status ?? null, note: note ?? null }),

  createInvestigation: (input: NewInvestigation) =>
    invoke<InvestigationDetail>("create_investigation", { input }),
  listInvestigations: () => invoke<Investigation[]>("list_investigations"),
  getInvestigation: (investigationId: number) =>
    invoke<InvestigationDetail>("get_investigation", { investigationId }),
  updateInvestigation: (
    investigationId: number,
    patch: { title?: string; description?: string; status?: string },
  ) =>
    invoke<InvestigationDetail>("update_investigation", {
      investigationId,
      title: patch.title ?? null,
      description: patch.description ?? null,
      status: patch.status ?? null,
    }),
  addInvestigationNote: (investigationId: number, body: string) =>
    invoke<InvestigationDetail>("add_investigation_note", { investigationId, body }),
  attachAlertToInvestigation: (investigationId: number, alertId: number) =>
    invoke<InvestigationDetail>("attach_alert_to_investigation", { investigationId, alertId }),
  exportInvestigation: (investigationId: number, path: string) =>
    invoke<string>("export_investigation", { investigationId, path }),

  getSettings: () => invoke<DetectionSettings>("get_settings"),
  saveSettings: (settings: DetectionSettings) => invoke<DetectionSettings>("save_settings", { settings }),
};

export type Api = typeof api;
