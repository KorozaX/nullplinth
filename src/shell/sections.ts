import {
  Activity,
  AlertTriangle,
  FolderSearch,
  LayoutDashboard,
  Network,
  Settings,
  ShieldQuestion,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

export type SectionId = "overview" | "events" | "network" | "alerts" | "investigations" | "sources" | "settings";

export interface SectionDef {
  id: SectionId;
  label: string;
  description: string;
  icon: LucideIcon;
}

export const SECTIONS: readonly SectionDef[] = [
  {
    id: "overview",
    label: "Overview",
    description: "Workbench summary across every imported dataset and capture",
    icon: LayoutDashboard,
  },
  {
    id: "events",
    label: "Event Explorer",
    description: "Search and inspect normalized log events with the guided filter builder",
    icon: FolderSearch,
  },
  {
    id: "network",
    label: "Network Analyzer",
    description: "Inspect packet captures, decoded layers and conversations",
    icon: Network,
  },
  {
    id: "alerts",
    label: "Alerts",
    description: "Detection results, plain-language explanations and evidence",
    icon: AlertTriangle,
  },
  {
    id: "investigations",
    label: "Investigations",
    description: "Case files with notes and attached alerts",
    icon: ShieldQuestion,
  },
  {
    id: "sources",
    label: "Data Sources",
    description: "Imported datasets and packet captures stored on this machine",
    icon: Activity,
  },
  {
    id: "settings",
    label: "Settings",
    description: "Detection thresholds and application information",
    icon: Settings,
  },
];

export function sectionById(id: SectionId): SectionDef {
  return SECTIONS.find((section) => section.id === id) ?? SECTIONS[0];
}
