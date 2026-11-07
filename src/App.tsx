import { useCallback, useState } from "react";
import type { ReactNode } from "react";

import { api } from "./services/api";
import { useLoad } from "./lib/async";
import { formatNumber } from "./lib/format";
import { ModeProvider } from "./context/ModeContext";
import { WorkspaceProvider, useWorkspace } from "./context/WorkspaceContext";
import { ImportProvider } from "./components/ImportWorkflow";
import { WorkspaceGate } from "./components/WorkspaceWelcome";
import { AppShell } from "./shell/AppShell";
import type { SectionId } from "./shell/sections";
import { OverviewScreen } from "./screens/OverviewScreen";
import { EventExplorerScreen } from "./screens/EventExplorerScreen";
import { NetworkAnalyzerScreen } from "./screens/NetworkAnalyzerScreen";
import { AlertsScreen } from "./screens/AlertsScreen";
import { InvestigationsScreen } from "./screens/InvestigationsScreen";
import { DataSourcesScreen } from "./screens/DataSourcesScreen";
import { SettingsScreen } from "./screens/SettingsScreen";

interface SectionProps {
  section: SectionId;
  onNavigate: (next: SectionId) => void;
  onOpenInvestigation: (investigationId: number) => void;
  onSearch: (text: string) => void;
  investigationFocus: number | null;
  eventSearch: string;
}

function renderSection(props: SectionProps): ReactNode {
  switch (props.section) {
    case "events":
      return <EventExplorerScreen initialText={props.eventSearch} />;
    case "network":
      return <NetworkAnalyzerScreen />;
    case "alerts":
      return <AlertsScreen onOpenInvestigation={props.onOpenInvestigation} />;
    case "investigations":
      return <InvestigationsScreen focusId={props.investigationFocus} />;
    case "sources":
      return <DataSourcesScreen />;
    case "settings":
      return <SettingsScreen />;
    case "overview":
    default:
      return <OverviewScreen onNavigate={props.onNavigate} onSearch={props.onSearch} />;
  }
}

function AppContent() {
  const { version } = useWorkspace();
  const workspace = useLoad(() => api.workspaceState(), [version]);
  const [section, setSection] = useState<SectionId>("overview");
  const [investigationFocus, setInvestigationFocus] = useState<number | null>(null);
  const [eventSearch, setEventSearch] = useState("");

  const openInvestigation = useCallback((investigationId: number) => {
    setInvestigationFocus(investigationId);
    setSection("investigations");
  }, []);

  const searchEvents = useCallback((text: string) => {
    setEventSearch(text);
    setSection("events");
  }, []);

  const summary = workspace.data
    ? formatNumber(workspace.data.events) +
      " events" +
      " · " +
      formatNumber(workspace.data.datasets) +
      " datasets" +
      " · " +
      formatNumber(workspace.data.captures) +
      " captures"
    : undefined;

  return (
    <WorkspaceGate>
      <AppShell section={section} onSelect={setSection} workspaceSummary={summary} onSearch={searchEvents}>
        {renderSection({
          section,
          onNavigate: setSection,
          onOpenInvestigation: openInvestigation,
          onSearch: searchEvents,
          investigationFocus,
          eventSearch,
        })}
      </AppShell>
    </WorkspaceGate>
  );
}

export function App() {
  return (
    <WorkspaceProvider>
      <ModeProvider>
        <ImportProvider>
          <AppContent />
        </ImportProvider>
      </ModeProvider>
    </WorkspaceProvider>
  );
}
